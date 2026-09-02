'''
The Google reconcile queue: the durable record that a purchase token owes work, which is what lets a
notification be acked the moment it arrives.
'''

import dataclasses
import json
import threading

import pendulum

import backend
import base
import db

from providers import google_play

from tests.helpers import TestingContext


def _queue(ctx) -> list[tuple]:
    with ctx.connection() as conn:
        return db.query(
            conn,
            'SELECT payment_token, eligible_at, attempts, last_error FROM google_reconcile_queue ORDER BY eligible_at',
        ).fetchall()


def test_enqueueing_a_token_collapses(pg_database):
    # The unit of work is the token, not the notification. Ten RTDNs for one subscription are one piece of
    # work, because the resource is fetched at reconcile time: whatever the tenth would have told us is
    # already in the snapshot the first fetch returns. So the token is the primary key and enqueueing is
    # idempotent -- a burst costs one fetch, not ten.
    with TestingContext(pg_database) as ctx:
        at = base.datetime_from_unix_ms(1767225600000)
        with ctx.connection() as conn:
            for offset in range(10):
                with db.transaction(conn) as tx:
                    backend.google_enqueue_reconcile(tx, 'tok', at + offset * base.HOUR)

        rows = _queue(ctx)
        assert len(rows) == 1
        # And it holds the EARLIEST of them: a fresh notification pulls work forward, never pushes it back.
        assert rows[0][1] == at


def test_a_new_notification_pulls_a_backed_off_token_forward_without_forgiving_it(pg_database):
    # A token waiting out a backoff should be retried promptly when new information arrives -- but the
    # arrival says nothing about whether the reason it was failing has gone away. So the due time moves
    # earlier and the failure count does not reset; otherwise a permanently stuck token that keeps
    # receiving notifications would retry at full speed forever.
    with TestingContext(pg_database) as ctx:
        now = base.datetime_from_unix_ms(1767225600000)
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok', now)
            with db.transaction(conn) as tx:
                claimed = backend.google_claim_due_reconciles(tx, now=now, lease_until=now + 1 * base.HOUR, limit=10)
            with db.transaction(conn) as tx:
                backend.google_reconcile_failed(tx, claimed[0], retry_at=now + 10 * base.HOUR, error='boom')

            assert _queue(ctx)[0][2] == 1 and _queue(ctx)[0][3] == 'boom'

            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok', now + 1 * base.HOUR)

        token, eligible_at, attempts, last_error = _queue(ctx)[0]
        assert eligible_at == now + 1 * base.HOUR, 'the new notification pulled it forward'
        assert attempts == 1, 'but did not forgive the failure'
        assert last_error == 'boom'


def test_claiming_leases_rather_than_locking_across_the_fetch(pg_database):
    # Reconciling makes a network call, so the claim cannot hold row locks across it the way the credit
    # drain does. It pushes eligible_at out to a lease instead and commits, leaving the work to happen outside
    # any transaction. A second runner therefore sees nothing due, and a worker that dies mid-fetch simply
    # lets the lease lapse -- no in-progress state to reap, and no way to lose the work.
    with TestingContext(pg_database) as ctx:
        now = base.datetime_from_unix_ms(1767225600000)
        lease_until = now + pendulum.duration(minutes=15)
        with ctx.connection() as conn:
            for token in ('tok-a', 'tok-b'):
                with db.transaction(conn) as tx:
                    backend.google_enqueue_reconcile(tx, token, now)

            with db.transaction(conn) as tx:
                claimed = backend.google_claim_due_reconciles(tx, now=now, lease_until=lease_until, limit=10)
            assert sorted(c.payment_token for c in claimed) == ['tok-a', 'tok-b']
            assert all(c.attempts == 0 for c in claimed)

            # A second pass while the lease is live finds nothing.
            with db.transaction(conn) as tx:
                assert backend.google_claim_due_reconciles(tx, now=now, lease_until=lease_until, limit=10) == []

            # Once it lapses, the work comes back on its own.
            with db.transaction(conn) as tx:
                again = backend.google_claim_due_reconciles(
                    tx, now=lease_until, lease_until=lease_until + pendulum.duration(minutes=15), limit=10
                )
            assert sorted(c.payment_token for c in again) == ['tok-a', 'tok-b']


def test_a_finished_token_leaves_the_queue(pg_database):
    # The row is an obligation, not a record: the notification history keeps what arrived, and this table
    # only ever answers "what still owes work". So success deletes rather than marking done.
    with TestingContext(pg_database) as ctx:
        now = base.datetime_from_unix_ms(1767225600000)
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok', now)
            with db.transaction(conn) as tx:
                claimed = backend.google_claim_due_reconciles(tx, now=now, lease_until=now + 1 * base.HOUR, limit=10)
            with db.transaction(conn) as tx:
                assert backend.google_reconcile_done(tx, claimed[0]) is True
        assert _queue(ctx) == []


def test_the_claim_takes_the_most_overdue_first_and_respects_its_limit(pg_database):
    # WHICH tokens a limited claim selects: the most overdue, so a backlog drains oldest-first rather than
    # starving whatever fell behind, and bounded so one pass cannot pull an unbounded batch into memory.
    #
    # Asserted as a SET, deliberately. The `ORDER BY eligible_at` lives in the subquery that feeds the
    # UPDATE's `WHERE payment_token IN (...)`, and an UPDATE's RETURNING order is not constrained by it --
    # so the sequence this comes back in is incidental, and an earlier version of this test pinned it by
    # luck. It broke when a partial index changed the plan, which is exactly finding 3.4's shape: a test
    # that passes because of physical row order tells you nothing about the property you meant.
    #
    # Nothing depends on the order anyway: the drain processes each claim independently.
    with TestingContext(pg_database) as ctx:
        now = base.datetime_from_unix_ms(1767225600000)
        with ctx.connection() as conn:
            for index in range(5):
                with db.transaction(conn) as tx:
                    backend.google_enqueue_reconcile(tx, f'tok-{index}', now - (5 - index) * base.HOUR)

            with db.transaction(conn) as tx:
                claimed = backend.google_claim_due_reconciles(tx, now=now, lease_until=now + 1 * base.HOUR, limit=2)
        assert sorted(c.payment_token for c in claimed) == ['tok-0', 'tok-1'], 'the two most overdue, not any two'


def test_a_notification_arriving_mid_fetch_is_not_erased_by_the_fetch_that_missed_it(pg_database):
    # A reconcile fetches a snapshot, then writes what it saw. A notification arriving in between describes
    # a state that fetch cannot have seen -- so finishing it must not clear the queue entry, or the change
    # sits unapplied until some later event happens to touch the token.
    #
    # Note why the revision counter is needed and comparing eligible_at would not do: enqueue only ever LOWERS
    # eligible_at, and a token being worked on is already due, so the newer notification leaves the value
    # untouched. Nothing about the timestamps distinguishes the two worlds.
    with TestingContext(pg_database) as ctx:
        now = base.datetime_from_unix_ms(1767225600000)
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok', now)
            with db.transaction(conn) as tx:
                claimed = backend.google_claim_due_reconciles(
                    tx, now=now, lease_until=now + pendulum.duration(minutes=15), limit=10
                )
            assert len(claimed) == 1

            # ... the worker is off fetching, and Google tells us something else changed ...
            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok', now)

            # ... and the worker comes back and tries to close out the obligation it picked up.
            with db.transaction(conn) as tx:
                assert backend.google_reconcile_done(tx, claimed[0]) is False, 'a newer obligation stands'

        rows = _queue(ctx)
        assert len(rows) == 1, 'still owing work'

        # And the newer obligation is claimable rather than stranded behind the old lease.
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                again = backend.google_claim_due_reconciles(
                    tx, now=now + pendulum.duration(minutes=16), lease_until=now + 1 * base.HOUR, limit=10
                )
        assert [c.payment_token for c in again] == ['tok']
        assert again[0].revision != claimed[0].revision


def test_a_notification_arriving_mid_fetch_does_not_hand_the_token_to_a_second_worker(pg_database):
    # eligible_at and leased_until answer different questions -- "when should this be looked at" versus "is
    # somebody looking at it right now" -- and conflating them was a race. Enqueue pulls eligible_at back to now
    # by design, so while they shared a column a notification arriving mid-fetch made the token look due
    # again and a second runner could pick it up alongside the first. The loser of that race is whichever
    # snapshot commits last, which is not necessarily the newer one.
    with TestingContext(pg_database) as ctx:
        now = base.datetime_from_unix_ms(1767225600000)
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok', now)
            with db.transaction(conn) as tx:
                first = backend.google_claim_due_reconciles(
                    tx, now=now, lease_until=now + pendulum.duration(minutes=15), limit=10
                )
            assert len(first) == 1

            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok', now)

            with db.transaction(conn) as tx:
                second = backend.google_claim_due_reconciles(
                    tx, now=now, lease_until=now + pendulum.duration(minutes=15), limit=10
                )
            assert second == [], 'the lease still holds, however due the token looks'


def test_a_failure_records_itself_but_does_not_stomp_a_newer_obligation(pg_database):
    # The failure happened, so it is always recorded. The BACK-OFF is not: a notification that arrived while
    # the fetch was in flight is newer than the failure and keeps the urgency it asked for. Otherwise every
    # fresh notification for a failing token would inherit a backoff from an attempt that predates it,
    # contradicting enqueue's rule that new information only ever pulls work earlier.
    with TestingContext(pg_database) as ctx:
        now = base.datetime_from_unix_ms(1767225600000)
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok', now)
            with db.transaction(conn) as tx:
                claimed = backend.google_claim_due_reconciles(
                    tx, now=now, lease_until=now + pendulum.duration(minutes=15), limit=10
                )
            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok', now)
            with db.transaction(conn) as tx:
                backend.google_reconcile_failed(tx, claimed[0], retry_at=now + 10 * base.HOUR, error='boom')

        token, eligible_at, attempts, last_error = _queue(ctx)[0]
        assert attempts == 1 and last_error == 'boom', 'the failure is recorded either way'
        assert eligible_at == now, 'but the newer notification keeps its urgency'


def _snapshot(order_id: str, expiry: str, account_id: bytes) -> base.JSONObject:
    from tests.test_google import _google_snapshot

    return _google_snapshot(
        state='SUBSCRIPTION_STATE_ACTIVE', expiry=expiry, order_id=order_id, obfuscated_account_id=account_id
    )


def test_the_drain_reconciles_what_it_claims_and_clears_it(monkeypatch, pg_database):
    # The whole loop: claim, fetch outside any transaction, converge, clear. The fetch being outside is the
    # reason the lease exists -- holding row locks across a Play API call would pin a transaction open for
    # the length of an external request.
    import nacl.signing
    from providers import google_play

    monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')
    monkeypatch.setattr('providers.google_play.api.subscription_v1_acknowledge', lambda *a, **k: None)
    with TestingContext(pg_database) as ctx:
        account_id = bytes(nacl.signing.SigningKey(bytes([0x42] * 32)).verify_key)
        at = base.datetime_from_unix_ms(1767225600000)

        err = base.ErrorSink()
        details = google_play.api.parse_get_subscription_v2_response(
            _snapshot('GPA.6161-6161-6161-61611', '2026-02-01T00:00:00.000Z', account_id), err
        )
        assert not err.has() and details is not None
        monkeypatch.setattr('providers.google_play.api.fetch_subscription_v2_details', lambda *a, **k: details)

        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok-drained', at)

        assert google_play.drain_due_reconciles(at=at) == 1
        assert _queue(ctx) == [], 'the obligation is discharged'

        with ctx.connection() as conn:
            rows = db.query(conn, 'SELECT payment_token FROM google_play_payment_details').fetchall()
        assert [row[0] for row in rows] == ['tok-drained']


def test_a_failing_token_backs_off_and_stops_crowding_out_fresh_work(monkeypatch, pg_database):
    # The reason the backoff earns its column. The claim is ORDER BY eligible_at LIMIT n, so a token that
    # stays eligible at its original instant sorts ahead of every later arrival and consumes a slot on every
    # pass. Pushing a failure into the future is what moves it BEHIND new work.
    from providers import google_play

    monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')

    def boom(package_name, purchase_token, err):
        err.msg_list.append('injected fetch failure')
        return None

    monkeypatch.setattr('providers.google_play.api.fetch_subscription_v2_details', boom)
    with TestingContext(pg_database) as ctx:
        at = base.datetime_from_unix_ms(1767225600000)
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok-stuck', at)

        assert google_play.drain_due_reconciles(at=at) == 1

        token, eligible_at, attempts, last_error = _queue(ctx)[0]
        assert attempts == 1
        assert 'injected fetch failure' in last_error
        assert eligible_at == at + google_play.notifications.reconcile_retry_delay(0), 'backed off'

        # A notification arriving now is eligible immediately, and the stuck token is not.
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok-fresh', at + pendulum.duration(seconds=1))
            with db.transaction(conn) as tx:
                claimed = backend.google_claim_due_reconciles(
                    tx, now=at + pendulum.duration(seconds=1), lease_until=at + pendulum.duration(minutes=5), limit=32
                )
        assert [c.payment_token for c in claimed] == ['tok-fresh'], 'the stuck token waits its turn'


def test_one_failing_token_does_not_cost_the_rest_of_the_batch(monkeypatch, pg_database):
    # Unrelated subscriptions that happen to be due at the same moment. CLAUDE.md's rule for provider
    # notifications applies unchanged: each gets its own transaction, and a failure is logged and skipped.
    import nacl.signing
    from providers import google_play

    monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')
    monkeypatch.setattr('providers.google_play.api.subscription_v1_acknowledge', lambda *a, **k: None)
    with TestingContext(pg_database) as ctx:
        account_id = bytes(nacl.signing.SigningKey(bytes([0x42] * 32)).verify_key)
        at = base.datetime_from_unix_ms(1767225600000)

        err = base.ErrorSink()
        good = google_play.api.parse_get_subscription_v2_response(
            _snapshot('GPA.6262-6262-6262-62621', '2026-02-01T00:00:00.000Z', account_id), err
        )
        assert not err.has() and good is not None

        def fetch(package_name, purchase_token, err):
            if purchase_token == 'tok-bad':
                raise RuntimeError('Google fell over for this one')
            return good

        monkeypatch.setattr('providers.google_play.api.fetch_subscription_v2_details', fetch)

        with ctx.connection() as conn:
            for token in ('tok-bad', 'tok-ok'):
                with db.transaction(conn) as tx:
                    backend.google_enqueue_reconcile(tx, token, at)

        assert google_play.drain_due_reconciles(at=at) == 2

        remaining = _queue(ctx)
        assert [row[0] for row in remaining] == ['tok-bad'], 'the good one cleared, the bad one is retained'
        assert 'Google fell over' in remaining[0][3]
        with ctx.connection() as conn:
            rows = db.query(conn, 'SELECT payment_token FROM google_play_payment_details').fetchall()
        assert [row[0] for row in rows] == ['tok-ok']


@dataclasses.dataclass
class _FakeStreamedMessage:
    """Duck-types the pubsub Message the subscriber callback receives.

    The callback is the half of the streaming rewrite that can be tested here: it touches only `data`,
    `message_id`, `publish_time`, `ack()` and `nack()`, none of which need a gRPC stream. What remains
    untestable locally is the loop around it, which owns the client.
    """

    data: bytes
    message_id: str
    # The real `Message.publish_time` is a stdlib datetime; pendulum's DateTime subclasses it, so this
    # satisfies the duck type the callback needs (`.timestamp()`) without a stdlib instant in the repo.
    publish_time: pendulum.DateTime = dataclasses.field(default_factory=lambda: pendulum.datetime(2026, 1, 1))
    acked: bool = False
    nacked: bool = False

    def ack(self) -> None:
        self.acked = True

    def nack(self) -> None:
        self.nacked = True


def _rtdn_bytes(token: str, event_ms: int = 1767225600000) -> bytes:
    return json.dumps(
        {
            'version': '1.0',
            'packageName': 'network.loki.messenger',
            'eventTimeMillis': str(event_ms),
            'subscriptionNotification': {
                'version': '1.0',
                'notificationType': 4,
                'purchaseToken': token,
                'subscriptionId': 'session_pro',
            },
        }
    ).encode()


def test_a_streamed_notification_is_recorded_queued_and_acked(monkeypatch, pg_database):
    # The happy path of the subscriber callback, end to end against a real database: the message is
    # recorded, its token is queued for a reconcile, and only then is it acked.
    with TestingContext(pg_database) as ctx:
        monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')
        message = _FakeStreamedMessage(data=_rtdn_bytes('tok-streamed'), message_id='msg-1')

        google_play.notifications._handle_streamed_message(message)

        assert message.acked and not message.nacked
        with ctx.connection() as conn:
            assert [r[0] for r in db.query(conn, 'SELECT payment_token FROM google_reconcile_queue')] == [
                'tok-streamed'
            ]
            handled = db.query_scalar(
                conn, 'SELECT handled FROM google_notification_history WHERE message_id = %s', 'msg-1'
            )
        assert handled is True


def test_an_undecodable_streamed_notification_is_nacked_not_acked(monkeypatch, pg_database):
    # A payload we cannot read is left for redelivery rather than dropped: it is either a format we do not
    # understand yet or a bug, and both are better answered after a deploy than by silence. Acking would
    # make it unrecoverable -- Google never redelivers an acked message.
    with TestingContext(pg_database) as ctx:
        monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')
        message = _FakeStreamedMessage(data=b'{not json at all', message_id='msg-bad')

        google_play.notifications._handle_streamed_message(message)

        assert message.nacked and not message.acked
        with ctx.connection() as conn:
            assert not db.query(conn, 'SELECT payment_token FROM google_reconcile_queue').fetchall()


def test_a_redelivered_streamed_notification_is_acked_without_repeating_the_work(monkeypatch, pg_database):
    # Pub/Sub is at-least-once, and the commit-then-ack window cannot be closed -- a callback abandoned
    # between the two leaves a handled message unacked, which Google then redelivers. That must be a no-op
    # ending in an ack, which is what makes the whole delivery model harmless.
    with TestingContext(pg_database) as ctx:
        monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')
        first = _FakeStreamedMessage(data=_rtdn_bytes('tok-twice'), message_id='msg-dup')
        google_play.notifications._handle_streamed_message(first)
        assert first.acked

        with ctx.connection() as conn:
            revision_before = db.query_scalar(
                conn, 'SELECT revision FROM google_reconcile_queue WHERE payment_token = %s', 'tok-twice'
            )

        second = _FakeStreamedMessage(data=_rtdn_bytes('tok-twice'), message_id='msg-dup')
        google_play.notifications._handle_streamed_message(second)

        assert second.acked and not second.nacked
        with ctx.connection() as conn:
            rows = db.query(conn, 'SELECT payment_token FROM google_reconcile_queue').fetchall()
            revision_after = db.query_scalar(
                conn, 'SELECT revision FROM google_reconcile_queue WHERE payment_token = %s', 'tok-twice'
            )
        assert len(rows) == 1, 'one token, one obligation'
        assert revision_after == revision_before, 'and the redelivery did not re-enqueue it'


def test_a_streamed_notification_that_fails_to_handle_is_nacked(monkeypatch, pg_database):
    # The decode path has its own nack (tested above); this is the OTHER one -- a message that decodes fine
    # and then fails to handle. Both have to nack, and it is worth stating separately because the first
    # test's early return does not exercise this branch at all: an unconditional `ack()` here passes every
    # other test in this file.
    #
    # An acked message is never redelivered, so getting this wrong loses the notification permanently.
    with TestingContext(pg_database) as ctx:
        monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')
        monkeypatch.setattr(
            'providers.google_play.notifications.handle_parsed_notification', lambda tx, parse, err: False
        )
        message = _FakeStreamedMessage(data=_rtdn_bytes('tok-unhandled'), message_id='msg-unhandled')

        google_play.notifications._handle_streamed_message(message)

        assert message.nacked and not message.acked
        with ctx.connection() as conn:
            handled = db.query_scalar(
                conn, 'SELECT handled FROM google_notification_history WHERE message_id = %s', 'msg-unhandled'
            )
        assert handled is False, 'recorded, but not marked done -- so a redelivery retries it'


def test_the_history_row_records_googles_instant_and_the_prune_applies_our_window(monkeypatch, pg_database):
    # `event_at` is Google's `eventTimeMillis` verbatim; the retention window is applied by the prune
    # rather than added before the INSERT. The difference is invisible until the window moves -- a stored
    # deadline leaves every existing row on the value it was written with -- so it needs pinning here.
    with TestingContext(pg_database) as ctx:
        monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')
        event_ms = 1767225600000
        event_at = base.datetime_from_unix_ms(event_ms)

        google_play.notifications._handle_streamed_message(
            _FakeStreamedMessage(data=_rtdn_bytes('tok-pruned', event_ms=event_ms), message_id='msg-handled')
        )

        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_add_notification_id(tx, 'msg-unhandled', event_at, '{}')

            stored = db.query_scalar(
                conn, 'SELECT event_at FROM google_notification_history WHERE message_id = %s', 'msg-handled'
            )
            assert stored == event_at, 'the notification instant, not that instant plus our window'

            deadline = event_at + base.GOOGLE_NOTIFICATION_RETAIN_FOR
            assert backend.delete_expired_google_notifications(conn, now=deadline - base.HOUR) == 0
            assert backend.delete_expired_google_notifications(conn, now=deadline) == 1

            remaining = [r[0] for r in db.query(conn, 'SELECT message_id FROM google_notification_history')]
        assert remaining == ['msg-unhandled'], 'an unhandled row is the replay backlog, and ages out at no window'


def test_a_token_that_never_reconciles_is_parked_rather_than_retried_forever(pg_database):
    # Without a cap a permanently-broken token retries at the six-hour ceiling indefinitely: four Play API
    # fetches a day, forever, for a purchase that will never register. That is one row's worth of waste in
    # isolation, but the failures are rarely isolated -- an unrecognised base plan is an ordinary Play Console
    # action and breaks EVERY new purchase -- and the claim orders by `eligible_at`, so broken work is
    # claimed ahead of fresh work.
    #
    # Parking stops the retries and nothing else: the row, its `attempts` and its `last_error` all stay.
    with TestingContext(pg_database) as ctx:
        now = base.datetime_from_unix_ms(1767225600000)
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok-doomed', now)

            # Fail it up to one attempt short of the cap; it must still be claimable.
            for attempt in range(google_play.notifications.RECONCILE_MAX_ATTEMPTS - 1):
                with db.transaction(conn) as tx:
                    claimed = backend.google_claim_due_reconciles(tx, now=now, lease_until=now, limit=10)
                assert len(claimed) == 1, f'still queued at attempt {attempt}'
                with db.transaction(conn) as tx:
                    backend.google_reconcile_failed(tx, claimed[0], retry_at=now, error='boom', park=False)

            # The last one parks it.
            with db.transaction(conn) as tx:
                claimed = backend.google_claim_due_reconciles(tx, now=now, lease_until=now, limit=10)
            assert len(claimed) == 1
            with db.transaction(conn) as tx:
                backend.google_reconcile_failed(tx, claimed[0], retry_at=now, error='the last straw', park=True)

            # Now it is invisible to the drain, however overdue it is.
            with db.transaction(conn) as tx:
                assert (
                    backend.google_claim_due_reconciles(tx, now=now + 365 * base.DAY, lease_until=now, limit=10) == []
                )

            # But not forgotten: the token is the one fact about a subscription we cannot re-derive.
            parked = backend.google_parked_reconciles(conn)
            assert [row[0] for row in parked] == ['tok-doomed']
            assert parked[0][1] == google_play.notifications.RECONCILE_MAX_ATTEMPTS
            assert parked[0][2] == 'the last straw'

            # And un-parking puts it straight back, which is what makes "deploy the fix and re-run" work.
            with db.transaction(conn) as tx:
                assert backend.google_unpark_reconcile(tx, 'tok-doomed', eligible_at=now) is True
            with db.transaction(conn) as tx:
                assert len(backend.google_claim_due_reconciles(tx, now=now, lease_until=now, limit=10)) == 1
            assert backend.google_parked_reconciles(conn) == []


def test_parking_yields_to_a_notification_that_arrived_during_the_fetch(pg_database):
    # Parking is subject to the same newer-obligation rule as the backoff. A notification arriving mid-fetch
    # describes a state that attempt cannot have seen, so it gets its chance rather than being parked on the
    # strength of a failure that predates it -- otherwise the arrival of new information could be what
    # finally condemns a token.
    with TestingContext(pg_database) as ctx:
        now = base.datetime_from_unix_ms(1767225600000)
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok', now)
            with db.transaction(conn) as tx:
                claimed = backend.google_claim_due_reconciles(tx, now=now, lease_until=now, limit=10)

            # A notification lands while the fetch is in flight, bumping the revision.
            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok', now)

            with db.transaction(conn) as tx:
                backend.google_reconcile_failed(tx, claimed[0], retry_at=now + 6 * base.HOUR, error='boom', park=True)

            assert backend.google_parked_reconciles(conn) == [], 'the newer obligation was not parked'
            with db.transaction(conn) as tx:
                assert len(backend.google_claim_due_reconciles(tx, now=now, lease_until=now, limit=10)) == 1


def test_init_api_prepares_the_drain_without_a_subscriber(monkeypatch):
    # The drain's prerequisite, isolated: a process can reach Google without running the Pub/Sub subscriber.
    # That is the whole point of the split — the maintenance mule owes the reconcile backstop precisely
    # BECAUSE it is not the process running the subscriber, so it cannot get its API state as a side effect
    # of starting one.
    monkeypatch.setattr('providers.google_play.api.package_name', '')
    monkeypatch.setattr('providers.google_play.api.subscription_product_id', '')
    monkeypatch.setattr('providers.google_play.api.credentials', None)
    monkeypatch.setattr('providers.google_play.api.publisher_service', None)
    threads_before = threading.active_count()

    # No credentials path: the identifiers still land, which is what `api` reads for every call. Building the
    # authed client needs a real service-account file, so that half is not exercised here.
    google_play.init_api(
        package_name='network.loki.messenger', subscription_product_id='pro', app_credentials_path=None
    )
    assert google_play.api.package_name == 'network.loki.messenger'
    assert google_play.api.subscription_product_id == 'pro'

    # No subscriber, and nothing that needs stopping: no thread, and none of the grpc machinery the
    # subscriber pulls in.
    assert threading.active_count() == threads_before

    # Idempotent, because the drain calls it on every pass rather than tracking whether it has run.
    google_play.init_api(
        package_name='network.loki.messenger', subscription_product_id='pro', app_credentials_path=None
    )
    assert google_play.api.package_name == 'network.loki.messenger'
