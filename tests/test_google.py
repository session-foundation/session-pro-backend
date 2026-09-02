'''
The Google Play provider: notification handling in isolation, and the recorded RTDN sequences
replayed end to end.
'''

import json
import nacl.signing
import nacl.bindings
import nacl.public
import os
import pendulum
import pytest
import time
import typing
import dataclasses
from providers import google_play
from providers.google_play.types import GoogleDuration
import backend
import base
import server
import db

from tests.helpers import (
    derived_status,
    TestingContext,
    round_datetime_to_next_store_day,
    _redeem_and_prove,
    _prove_at,
    _grant_voucher,
)


def test_google_subscription_notification_only_records_that_a_token_owes_a_look(monkeypatch, pg_database):
    # This replaces three characterisations of a control flow that no longer exists. The subscription case
    # used to fetch the resource and dispatch on notification type inside the handler, which gave it three
    # distinct failure shapes -- a failed fetch and a failed parse both returned early WITHOUT cancelling the
    # transaction, while a failure deeper in DID cancel -- and the asymmetry was worth pinning because it
    # decided whether the message was acked.
    #
    # There is nothing left to fetch or parse here. The case is one write: record that this token owes a
    # reconcile. So the contract collapses to something a test can state in one line, and the failures those
    # tests guarded now happen in the drain, where tests/test_google_queue.py covers them.
    with TestingContext(pg_database) as ctx:
        monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')
        parse = google_play.ParsedNotification(
            payload_type=google_play.ParsedNotificationPayloadType.Subscription,
            purchase_token='tok-recorded',
            package_name='network.loki.messenger',
            event_time_ms=1767225600000,
            sub_type=google_play.types.SubscriptionNotificationType.PURCHASED,
        )
        err = base.ErrorSink()
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                assert google_play.handle_parsed_notification(tx, parse, err) is True
                assert tx.cancel is False
        assert not err.has(), err.msg_list

        with ctx.connection() as conn:
            queued = db.query(conn, 'SELECT payment_token, eligible_at FROM google_reconcile_queue').fetchall()
        assert [row[0] for row in queued] == ['tok-recorded']
        assert queued[0][1] == base.datetime_from_unix_ms(1767225600000), 'dated from the store event'

        # Nothing was fetched, so nothing about the subscription is known yet -- that is the drain's job.
        assert not _payment_rows(ctx)


def test_google_a_failed_enqueue_is_not_acked_away(monkeypatch, pg_database):
    # The other half of the contract above, and the one that matters most. Recording that a token owes a
    # look is now the ONLY step that has to succeed before the message is acked, because it is the only
    # thing that cannot be recovered from anywhere else: no Play endpoint enumerates subscribers and no
    # client route submits a purchase token, so a first sighting acked away is a paying subscriber who
    # never gets Pro, with nothing anywhere to say so.
    #
    # So a failing enqueue must cancel the transaction and report the message as unhandled, which is what
    # keeps it unacked and redelivered.
    with TestingContext(pg_database) as ctx:
        monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')

        def _boom(*args, **kwargs):
            raise RuntimeError('the queue write failed')

        monkeypatch.setattr('backend.google_enqueue_reconcile', _boom)
        parse = google_play.ParsedNotification(
            payload_type=google_play.ParsedNotificationPayloadType.Subscription,
            purchase_token='tok-lost-if-acked',
            package_name='network.loki.messenger',
            event_time_ms=1767225600000,
            sub_type=google_play.types.SubscriptionNotificationType.PURCHASED,
        )
        err = base.ErrorSink()
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                assert google_play.handle_parsed_notification(tx, parse, err) is False, 'unhandled, so unacked'
                assert tx.cancel is True, 'and rolled back rather than half-applied'
        assert err.has(), 'and reported, rather than failing silently'

        with ctx.connection() as conn:
            queued = db.query(conn, 'SELECT payment_token FROM google_reconcile_queue').fetchall()
        assert not queued


def test_google_process_notification_message(monkeypatch, pg_database):
    # The per-message transaction block: what it does with a message that is absent, already handled, or
    # unhandled-and-failing. Pins the control flow the callback depends on -- handled=True means ack, and a
    # failure must leave the history row unhandled so a redelivery retries it.
    #
    # It used to also pin a `user_error` row per outcome, surfaced to the account as the wire's
    # `error_report`. Both are deleted: the bit was not actionable by a user, and a handling failure rolled
    # it back anyway. A stuck purchase is now visible as `attempts`/`last_error` on its reconcile-queue row.
    now_s = 1_600_000_000.0
    event_at = base.datetime_from_unix_ms(int(now_s * 1000))

    def make_msg(message_id: str, token: str):
        return google_play.notifications.SortedMessage(
            event_unix_ts_ms=int(now_s * 1000),
            message_id=message_id,
            parse=google_play.ParsedNotification(
                payload_type=google_play.ParsedNotificationPayloadType.Subscription,
                purchase_token=token,
                package_name='network.loki.messenger',
                event_time_ms=int(now_s * 1000),
            ),
        )

    def is_handled(conn, message_id: str):
        return db.query_scalar(
            conn, 'SELECT handled FROM google_notification_history WHERE message_id = %s', message_id
        )

    with TestingContext(pg_database) as ctx:
        monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')

        # (A) No history row at all -> treated as handled, so the message is acked rather than retried
        #     forever. Someone cleared it out-of-band and that is taken as authoritative.
        with ctx.connection() as conn:
            assert (
                google_play.notifications._process_notification_message(
                    conn, make_msg('m-absent', 'tok-a'), base.ErrorSink(), now_s
                )
                is True
            )

        # (B) Present and ALREADY handled -> handled again without re-running the handler. This is the path a
        #     redelivery of a committed-but-unacked message takes, and it is what makes at-least-once
        #     delivery a non-event.
        monkeypatch.setattr(
            'providers.google_play.notifications.handle_parsed_notification',
            lambda tx, parse, err: pytest.fail('handler must not run for an already-handled message'),
        )
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_add_notification_id(tx, 'm-done', event_at, '')
                backend.google_set_notification_handled(tx, message_id='m-done', delete=False)
            assert (
                google_play.notifications._process_notification_message(
                    conn, make_msg('m-done', 'tok-b'), base.ErrorSink(), now_s
                )
                is True
            )

        # (C) Present, unhandled, handler SUCCEEDS -> marked handled in the same transaction.
        monkeypatch.setattr(
            'providers.google_play.notifications.handle_parsed_notification', lambda tx, parse, err: True
        )
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_add_notification_id(tx, 'm-ok', event_at, '')
            assert (
                google_play.notifications._process_notification_message(
                    conn, make_msg('m-ok', 'tok-c'), base.ErrorSink(), now_s
                )
                is True
            )
            assert is_handled(conn, 'm-ok') is True

        # (D) Present, unhandled, handler FAILS -> reported unhandled and the row stays unhandled, which is
        #     what makes the callback nack it and Google redeliver.
        monkeypatch.setattr(
            'providers.google_play.notifications.handle_parsed_notification', lambda tx, parse, err: False
        )
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_add_notification_id(tx, 'm-fail', event_at, '')
            assert (
                google_play.notifications._process_notification_message(
                    conn, make_msg('m-fail', 'tok-d'), base.ErrorSink(), now_s
                )
                is False
            )
            assert is_handled(conn, 'm-fail') is False


def test_google_ack_sweep(monkeypatch, pg_database):
    # The mule's needs_ack sweep is the SOLE Google purchase-acker (notification handling only records the
    # obligation). Cover its three outcomes: a clean ack clears the flag; an ack that FAILS but that Google
    # already considers acknowledged (we acked then crashed before clearing) clears via the authoritative
    # acknowledgement_state; a genuinely failing ack leaves the flag set to retry next sweep.
    dsn = pg_database()
    pool = backend.bootstrap_db(database_url=dsn)
    assert pool

    class _AckedDetails:
        acknowledgement_state = google_play.types.SubscriptionsV2AcknowledgementState.ACKNOWLEDGED

    def seed(conn, token, needs_ack):
        tx = base.PaymentProviderTransaction()
        tx.provider = base.PaymentProvider.GooglePlayStore
        tx.google_payment_token = token
        tx.google_order_id = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        err = base.ErrorSink()
        backend.add_unredeemed_payment(
            conn,
            payment_tx=tx,
            plan=base.ProPlan.OneMonth,
            purchased_at=base.EPOCH,
            expiry_at=base.EPOCH,
            platform_refund_expiry_at=base.EPOCH,
            platform_obfuscated_account_id=os.urandom(32),
            err=err,
            needs_ack=needs_ack,
        )
        assert not err.msg_list, err.msg_list

    def flag(conn, token):
        return db.query_scalar(
            conn, 'SELECT needs_ack FROM google_play_payment_details WHERE payment_token = %s', token
        )

    tok_ok = os.urandom(32).hex()
    tok_crashed = os.urandom(32).hex()
    tok_fail = os.urandom(32).hex()
    tok_already = os.urandom(32).hex()

    with db.connection() as conn:
        # Each case seeds its token TRUE just before running the sweep, so the sweep (which processes all
        # currently-TRUE tokens) only sees this case's token — no cross-case interference, no re-seeding.

        # (1) Ack succeeds -> flag cleared. A FALSE row (already acknowledged at registration) is never
        #     even selected by the sweep.
        seed(conn, tok_already, needs_ack=False)
        seed(conn, tok_ok, needs_ack=True)
        monkeypatch.setattr('providers.google_play.api.subscription_v1_acknowledge', lambda purchase_token, err: None)
        google_play.notifications._sweep_pending_acks()
        assert flag(conn, tok_ok) is False
        assert flag(conn, tok_already) is False

        # (2) Ack FAILS but Google reports it already ACKNOWLEDGED (acked-then-crashed) -> cleared via the
        #     authoritative acknowledgement_state fetch.
        seed(conn, tok_crashed, needs_ack=True)
        monkeypatch.setattr(
            'providers.google_play.api.subscription_v1_acknowledge',
            lambda purchase_token, err: err.msg_list.append('ack boom'),
        )
        monkeypatch.setattr(
            'providers.google_play.api.fetch_subscription_v2_details', lambda pkg, token, err: _AckedDetails()
        )
        google_play.notifications._sweep_pending_acks()
        assert flag(conn, tok_crashed) is False

        # (3) Ack FAILS and Google does NOT confirm acknowledged (fetch returns nothing) -> flag stays set
        #     for the next sweep. (ack stub from case 2 still in effect.)
        seed(conn, tok_fail, needs_ack=True)
        monkeypatch.setattr('providers.google_play.api.fetch_subscription_v2_details', lambda pkg, token, err: None)
        google_play.notifications._sweep_pending_acks()
        assert flag(conn, tok_fail) is True
    pool.close()


def test_google_platform_handle_notification(monkeypatch, pg_database):
    with TestingContext(pg_database) as ctx:
        google_play.init(
            cloud_project_id='loki-5a81e',
            package_name='network.loki.messenger',
            cloud_subscription_name='session-pro-sub',
            subscription_product_id='session_pro',
            app_credentials_path=None,
        )

    err = base.ErrorSink()
    # The grace Play applies in these recorded scenarios. It is NOT stored anywhere -- Play folds grace into
    # the resource's `expiryTime` -- so this is here only for the tests' own time travel.
    store_grace = GoogleDuration("P2D", err)
    assert not err.has()

    monkeypatch.setattr("providers.google_play.api.subscription_v1_acknowledge", lambda *args, **kwargs: None)

    @dataclasses.dataclass
    class TestScenario:
        rtdn_event: base.JSONObject
        current_state: base.JSONObject

    @dataclasses.dataclass
    class TestUserCtx:
        master_key: nacl.signing.SigningKey
        rotating_key: nacl.signing.SigningKey
        payments: int
        google_obfuscated_account_id: bytes

        def __init__(self):
            self.payments = 0
            seed = bytes([0x01] * 32)
            self.master_key = nacl.signing.SigningKey(seed)
            self.rotating_key = nacl.signing.SigningKey.generate()
            self.google_obfuscated_account_id = bytes(self.master_key.verify_key)

    @dataclasses.dataclass
    class TestTx:
        purchase_token: str
        order_id: str
        event_ms: int
        expiry_at: int

    def purchase_token_of(scenario: TestScenario) -> str:
        block = scenario.rtdn_event.get("subscriptionNotification") or scenario.rtdn_event.get("voidedNotification")
        assert isinstance(block, dict)
        token = block["purchaseToken"]
        assert isinstance(token, str)
        return token

    def test_notification(scenario: TestScenario, ctx: TestingContext) -> TestTx:
        err_parse = base.ErrorSink()
        current_state = google_play.api.parse_get_subscription_v2_response(scenario.current_state, err_parse)
        assert not err_parse.has()
        assert current_state is not None

        # Token-keyed, like the standalone driver: the drain reconciles everything due, so a stub that
        # ignored the token would answer for one subscription with another's resource.
        _SNAPSHOTS[purchase_token_of(scenario)] = current_state

        def _fetch(package_name, token, err):
            known = _SNAPSHOTS.get(token)
            if known is None:
                err.msg_list.append(f'test fixture has no snapshot for {token}')
            return known

        monkeypatch.setattr("providers.google_play.api.fetch_subscription_v2_details", _fetch)

        event_time_ms_str = scenario.rtdn_event['eventTimeMillis']
        assert isinstance(event_time_ms_str, str)
        event_ms = int(event_time_ms_str)

        purchase_token = None
        if "subscriptionNotification" in scenario.rtdn_event:
            assert isinstance(scenario.rtdn_event["subscriptionNotification"], dict)
            purchase_token = scenario.rtdn_event["subscriptionNotification"]["purchaseToken"]
        elif "voidedNotification" in scenario.rtdn_event:
            assert isinstance(scenario.rtdn_event["voidedNotification"], dict)
            purchase_token = scenario.rtdn_event["voidedNotification"]["purchaseToken"]

        assert isinstance(purchase_token, str)

        err_rtdn = base.ErrorSink()
        parse = google_play.parse_notification(scenario.rtdn_event, err_rtdn)
        handled = False
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                handled = google_play.handle_parsed_notification(tx, parse, err_rtdn)
        assert not err_rtdn.has() and handled and len(parse.purchase_token) > 0

        # The notification now only records that the token owes a look, so drive the drain too. This
        # sequence asserts what each notification LEAVES BEHIND, which is still the right question; only the
        # mechanism between arrival and outcome has changed. The fetch is stubbed to this scenario's
        # snapshot, so the drain sees exactly what the old inline handler saw.
        google_play.drain_due_reconciles(at=base.datetime_from_unix_ms(event_ms))

        order_id = current_state.line_items[0].latest_successful_order_id
        expiry_time_unix_ms = current_state.line_items[0].expiry_time.unix_milliseconds
        assert order_id is not None and len(order_id) > 0
        assert purchase_token is not None and len(purchase_token) > 0
        return TestTx(
            purchase_token=purchase_token, order_id=order_id, event_ms=event_ms, expiry_at=expiry_time_unix_ms
        )

    """
    Testing Interaction Utility Functions
    """

    def get_pro_status(user_ctx: TestUserCtx, ctx: TestingContext, unix_ts_ms: int) -> base.JSONObject:
        ts = unix_ts_ms // 1000  # wire nonce is integer seconds (wire spec §1.1)
        hash_to_sign = backend.make_get_pro_status_message(
            master_pkey=user_ctx.master_key.verify_key, request_at=base.datetime_from_unix_seconds(ts)
        )
        request_body = {
            'master_pkey': bytes(user_ctx.master_key.verify_key).hex(),
            'master_sig': bytes(user_ctx.master_key.sign(hash_to_sign).signature).hex(),
            'ts': ts,
        }
        server.time_now = lambda: unix_ts_ms / 1000.0
        response = ctx.flask_client.post('/get_pro_status', json=request_body)
        server.time_now = lambda: time.time()
        response_json = response.json
        assert response_json is not None
        return response_json

    def get_payment_details(
        user_ctx: TestUserCtx, ctx: TestingContext, unix_ts_ms: int, limit: int, before: str = ''
    ) -> base.JSONObject:
        ts = unix_ts_ms // 1000  # wire nonce is integer seconds (wire spec §1.1)
        hash_to_sign = backend.make_get_payment_details_message(
            master_pkey=user_ctx.master_key.verify_key,
            request_at=base.datetime_from_unix_seconds(ts),
            limit=limit,
            before=before,
        )
        request_body = {
            'master_pkey': bytes(user_ctx.master_key.verify_key).hex(),
            'master_sig': bytes(user_ctx.master_key.sign(hash_to_sign).signature).hex(),
            'ts': ts,
            'limit': limit,
            'before': before,
        }
        server.time_now = lambda: unix_ts_ms / 1000.0
        response = ctx.flask_client.post('/get_payment_details', json=request_body)
        server.time_now = lambda: time.time()
        response_json = response.json
        assert response_json is not None
        return response_json

    def add_payment(tx: TestTx, user_ctx: TestUserCtx, ctx: TestingContext) -> int:
        # Redeem the mule-registered payment for this user: reconcile binds it by the master-key
        # account-id (the reflow replaces the old /add_pro_payment round-trip).
        with ctx.connection() as conn:
            backend.reconcile_pending_payments(
                conn, user_ctx.master_key.verify_key, redeemed_at=base.datetime_from_unix_ms(tx.event_ms)
            )
        return tx.event_ms

    def run_prune_at_end_of_day(event_ms: int):
        boundary_ms = base.unix_ms_from_datetime(
            round_datetime_to_next_store_day(
                at=base.datetime_from_unix_ms(event_ms), compressed=ctx.compressed_store_day
            )
        )
        end_of_day = base.datetime_from_unix_ms(event_ms + boundary_ms)
        with ctx.connection() as conn:
            backend.delete_expired_apple_notification_uuids(conn, now=end_of_day)
            backend.delete_expired_google_notifications(conn, now=end_of_day)

    """
    Testing Assert Utility Functions
    """

    def assert_clean_state(ctx: TestingContext):
        with ctx.connection() as conn:
            assert not backend.get_unredeemed_payments_list(conn)
            assert not backend.get_payments_list(conn)
            assert not backend.get_revocations_list(conn)

    def assert_has_unredeemed_payment(
        tx: TestTx, plan: base.ProPlan, platform_refund_expiry_at: int, ctx: TestingContext
    ):
        with ctx.connection() as conn:
            unredeemed_payments = backend.get_unredeemed_payments_list(conn)
            found = False
            for unredeemed_payment in unredeemed_payments:
                if unredeemed_payment.google_order_id == tx.order_id:
                    found = True
                    assert isinstance(unredeemed_payment, backend.PaymentRow)
                    assert unredeemed_payment.master_pkey is None
                    assert unredeemed_payment.plan == plan
                    assert unredeemed_payment.payment_provider == base.PaymentProvider.GooglePlayStore
                    assert unredeemed_payment.redeemed_at is None
                    assert unredeemed_payment.expiry_at == base.datetime_from_unix_ms(tx.expiry_at)
                    assert unredeemed_payment.grace_period == pendulum.duration()
                    assert unredeemed_payment.platform_refund_expiry_at == base.datetime_from_unix_ms(
                        platform_refund_expiry_at
                    )
                    assert unredeemed_payment.revoked_at is None
                    assert unredeemed_payment.apple == backend.AppleTransaction()
                    assert unredeemed_payment.google_payment_token == tx.purchase_token
                    assert unredeemed_payment.google_order_id == tx.order_id
            assert found

    def assert_has_payment(
        tx: TestTx,
        plan: base.ProPlan,
        # The instant the test itself claimed the payment at, when it drove the redeem. `None` where the
        # MULE auto-redeemed it instead: that stamps our clock at the moment the notification was handled,
        # which a test cannot predict, so all it can check is that the stamp is set and not before the
        # purchase it belongs to.
        redeemed_ts_ms: int | None,
        platform_refund_expiry_at: int,
        user_ctx: TestUserCtx,
        ctx: TestingContext,
    ):
        with ctx.connection() as conn:
            payments = backend.get_payments_list(conn)
            assert len(payments) == user_ctx.payments
            payment = payments[-1]
            assert isinstance(payment, backend.PaymentRow)
            assert payment.master_pkey == bytes(user_ctx.master_key.verify_key)
            assert derived_status(payment) == base.PaymentStatus.Redeemed
            assert payment.plan == plan
            assert payment.payment_provider == base.PaymentProvider.GooglePlayStore
            assert payment.redeemed_at is not None
            if redeemed_ts_ms is not None:
                assert payment.redeemed_at == base.datetime_from_unix_ms(redeemed_ts_ms)
            else:
                assert payment.redeemed_at >= payment.purchased_at
            assert payment.expiry_at == base.datetime_from_unix_ms(tx.expiry_at)
            assert payment.grace_period is None
            assert payment.platform_refund_expiry_at == base.datetime_from_unix_ms(platform_refund_expiry_at)
            assert payment.revoked_at is None
            assert payment.apple == backend.AppleTransaction()
            assert payment.google_payment_token == tx.purchase_token
            assert payment.google_order_id == tx.order_id

    def assert_has_user(tx: TestTx, user_ctx: TestUserCtx, ctx: TestingContext):
        with ctx.connection() as conn:
            user = backend.get_user(conn=conn, master_pkey=user_ctx.master_key.verify_key)
            assert isinstance(user, backend.UserRow)
            assert user.master_pkey == bytes(user_ctx.master_key.verify_key)
            # The user points at a live current generation with a populated 32-byte token. We do NOT
            # assert a generation count here: a generation is an epoch, reused across payments and
            # rolled only on revocation, so the count is scenario-dependent, not one-per-payment. The
            # current generation must be one of the user's, and (for these non-revoked scenarios) live.
            user_gen_ids = {row[0] for row in db.query(conn, "SELECT id FROM generations WHERE user_id = %s", user.id)}
            assert user.current_generation_id in user_gen_ids
            assert not backend.is_generation_revoked(
                conn, user.current_generation_id, base.datetime_from_unix_ms(tx.event_ms)
            )
            assert len(user.token) == backend.BLAKE2B_DIGEST_SIZE
            assert user.expiry_at == base.datetime_from_unix_ms(tx.expiry_at)

    def store_extension(paid_tx: TestTx, grace_tx: TestTx) -> pendulum.Duration:
        """How much the store added to the paid term when the renewal failed.

        Play applies grace by extending `expiryTime`, and the converge keeps the two apart: the row holds the
        paid term it already knew, and this difference in `grace_period`. So a grace step asserts the
        PURCHASE's expiry with the extension beside it, which is what lets a client say "your payment failed
        on the 3rd, you have Pro until the 6th" rather than showing a renewal date that moved."""
        return base.duration_from_ms(grace_tx.expiry_at - paid_tx.expiry_at)

    def assert_payment_details(
        tx: TestTx,
        pro_status: server.UserProStatus,
        payment_status: base.PaymentStatus,
        auto_renew: bool,
        grace_duration: pendulum.Duration,
        platform_refund_expiry_at: int,
        user_ctx: TestUserCtx,
        ctx: TestingContext,
        unix_ts_ms: int | None = None,
        revoke_unix_ts_ms: int | None = None,
    ):
        # The wire is integer seconds (upstream provider instants — here `revoked_ts` — are floats);
        # the harness/provider fixtures below are ms. `to_s` mirrors the server's floor-to-seconds so
        # a ms fixture compares against the emitted integer-seconds value.
        def to_s(ms):
            return base.unix_seconds_from_datetime(base.datetime_from_unix_ms(ms))

        status = get_pro_status(user_ctx=user_ctx, ctx=ctx, unix_ts_ms=unix_ts_ms if unix_ts_ms else tx.event_ms)
        err = base.ErrorSink()
        result = base.json_dict_require_obj(status, "result", err)
        res_auto_renewing = base.json_dict_require_bool(result, "auto_renewing", err)
        res_expiry_ts = base.json_dict_require_int(result, "expiry_ts", err)
        res_grace_period_duration = base.json_dict_require_int(result, "grace_period_duration", err)
        res_pro_status = base.json_dict_require_str_coerce_to_enum(result, "user_status", server.UserProStatus, err)
        res_latest = base.json_dict_require_obj(result, "latest_payment", err)
        assert not err.has(), status
        assert res_auto_renewing == auto_renew, json.dumps(result, indent=1)
        revoked = payment_status == base.PaymentStatus.Revoked
        if revoked:
            assert revoke_unix_ts_ms is not None
            # A revocation only ever pulls the end EARLIER, so a payment refunded after it had already
            # lapsed keeps its own expiry. This scenario hits that: in the compressed testing env its
            # expiry precedes the refund by a fifth of a "day".
            assert res_expiry_ts == to_s(min(tx.expiry_at, revoke_unix_ts_ms))
        else:
            # The account's expiry is reported as the store states it, with nothing added: no subtraction
            # to undo. What the account is SERVED past that instant is the separate duration below.
            assert res_expiry_ts == to_s(tx.expiry_at), json.dumps(result, indent=1)
            # And the pair reconciles: expiry + duration is when serving stops, which is the same instant
            # `user_status` flips. That is the store's grace -- for Google, the extension the converge keeps
            # separate from the paid term -- plus our own allowance.
            expected_served_past = base.seconds_from_duration(grace_duration + base.RENEWAL_LATENCY_ALLOWANCE)
            assert res_grace_period_duration == (expected_served_past if res_auto_renewing else 0), json.dumps(
                result, indent=1
            )
        assert res_pro_status == pro_status
        item = res_latest
        assert isinstance(item, dict)
        item_expiry_ts = base.json_dict_require_int(item, "expiry_ts", err)
        item_payment_id = base.json_dict_require_str(item, "payment_id", err)
        item_grace_duration = base.json_dict_require_int(item, "grace_period_duration", err)
        item_payment_provider = base.json_dict_require_str_coerce_to_enum(
            item, "payment_provider", base.PaymentProvider, err
        )
        item_platform_refund_expiry_ts = base.json_dict_require_int(item, "platform_refund_expiry_ts", err)
        item_revoked_ts = base.json_dict_require_float(item, "revoked_ts", err)
        item_status = base.json_dict_require_str_coerce_to_enum(item, "status", base.PaymentStatus, err)
        assert not err.has()
        assert item_expiry_ts == to_s(tx.expiry_at), res_latest
        # Google `payment_id` is the opaque `token|order_id` composite (backend-owned; §5.2).
        assert item_payment_id == f'{tx.purchase_token}|{tx.order_id}'
        assert item_grace_duration == base.seconds_from_duration(grace_duration)
        assert item_payment_provider == base.PaymentProvider.GooglePlayStore
        assert item_platform_refund_expiry_ts == to_s(platform_refund_expiry_at)
        assert (
            item_revoked_ts == 0.0
            if not revoked
            else base.unix_seconds_float_from_datetime(base.datetime_from_unix_ms(tx.event_ms))
        )
        assert item_status == payment_status

    """
    Testing Common Action Functions
    """

    def test_make_purchase(
        purchase: TestScenario, plan: base.ProPlan, ctx: TestingContext, check_payment_is_unredeemed: bool = False
    ):
        tx = test_notification(purchase, ctx)
        platform_refund_expiry_unix_tx_ms = tx.event_ms + base.MILLISECONDS_IN_DAY * 2
        if check_payment_is_unredeemed:
            assert_has_unredeemed_payment(
                tx=tx, plan=plan, platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms, ctx=ctx
            )
        return tx, platform_refund_expiry_unix_tx_ms

    def test_make_purchase_and_claim_payment(
        purchase: TestScenario, plan: base.ProPlan, user_ctx: TestUserCtx, ctx: TestingContext
    ):
        tx, platform_refund_expiry_unix_tx_ms = test_make_purchase(purchase=purchase, plan=plan, ctx=ctx)
        # Redeem subscription payment
        redeemed_ts_ms = add_payment(tx=tx, user_ctx=user_ctx, ctx=ctx)
        with ctx.connection() as conn:
            assert not backend.get_unredeemed_payments_list(conn)

        user_ctx.payments += 1
        assert_has_payment(
            tx=tx,
            plan=plan,
            redeemed_ts_ms=redeemed_ts_ms,
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        assert_has_user(tx=tx, user_ctx=user_ctx, ctx=ctx)
        assert_payment_details(
            tx=tx,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        return tx, platform_refund_expiry_unix_tx_ms

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User cancels
        3. User un-cancels
        4. User refunds
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1759723091078',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'lgmmicancjpmkconmddnaicb.AO-J1OyZa0o1Xez6T7kCcaIpqyIKzt5n1D_cTEFQhHJzVKw4INw2cMmckgE-ME0DgO1xJuFAYDuiYuM-Sy87HLQ8qvitpiMGrMnu1iL_-yvAYc4CoAx8u_Q',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-06T03:58:10.981Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3354-3745-5570-25336',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-06T04:03:10.613Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3354-3745-5570-25336',
                    }
                ],
            },
        )
        cancel = TestScenario(  # 2. User cancels
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1759723188437',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 3,
                    'purchaseToken': 'lgmmicancjpmkconmddnaicb.AO-J1OyZa0o1Xez6T7kCcaIpqyIKzt5n1D_cTEFQhHJzVKw4INw2cMmckgE-ME0DgO1xJuFAYDuiYuM-Sy87HLQ8qvitpiMGrMnu1iL_-yvAYc4CoAx8u_Q',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-06T03:58:10.981Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_CANCELED',
                'latestOrderId': 'GPA.3354-3745-5570-25336',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-06T03:59:48.074Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-06T04:03:10.613Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3354-3745-5570-25336',
                    }
                ],
            },
        )
        uncancel = TestScenario(  # 3. User uncancels
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1759723199349',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 7,
                    'purchaseToken': 'lgmmicancjpmkconmddnaicb.AO-J1OyZa0o1Xez6T7kCcaIpqyIKzt5n1D_cTEFQhHJzVKw4INw2cMmckgE-ME0DgO1xJuFAYDuiYuM-Sy87HLQ8qvitpiMGrMnu1iL_-yvAYc4CoAx8u_Q',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-06T03:58:10.981Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3354-3745-5570-25336',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-06T04:03:10.613Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3354-3745-5570-25336',
                    }
                ],
            },
        )
        refund = TestScenario(  # 4. User refunds
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1759723392088',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 12,
                    'purchaseToken': 'lgmmicancjpmkconmddnaicb.AO-J1OyZa0o1Xez6T7kCcaIpqyIKzt5n1D_cTEFQhHJzVKw4INw2cMmckgE-ME0DgO1xJuFAYDuiYuM-Sy87HLQ8qvitpiMGrMnu1iL_-yvAYc4CoAx8u_Q',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-06T03:58:10.981Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3354-3745-5570-25336',
                'canceledStateContext': {'systemInitiatedCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-06T04:03:11.808Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3354-3745-5570-25336',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        tx_subscribe, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """2. User cancels"""
        test_notification(cancel, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=False,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        """3. User un-cancels"""
        test_notification(uncancel, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        """4. User refunds"""
        refund_tx = test_notification(refund, ctx)
        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Revoked,
            auto_renew=False,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            revoke_unix_ts_ms=refund_tx.event_ms,
            # +1s (not +1ms): the wire nonce is integer seconds, so a sub-second margin
            # past expiry floors away — "just past expiry" is one whole second.
            unix_ts_ms=refund_tx.event_ms + 1000,
        )

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User enters grace period as subscription fails to renew
        3. User renews, exiting grace period
        4. User cancels (probably dont need this)
        5. Expires (probably dont need this)
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760056968727',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'jflmajbhbddmjjjihphljklh.AO-J1Ox0T3IQHCVuZkRq61fkTGJbMwFmw30uxSrI5N9uRofnf-X8HE8F78bhPKWzYd85OHzzkHC3WAkCRi6FeNyyRu6Trff9dQObNQycH6c2ymaU4mCWSLY',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:42:48.626Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3375-6103-0197-44778',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:47:48.269Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3375-6103-0197-44778',
                    }
                ],
            },
        )
        grace = TestScenario(  # 2. User enters grace period as subscription fails to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760057276700',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 6,
                    'purchaseToken': 'jflmajbhbddmjjjihphljklh.AO-J1Ox0T3IQHCVuZkRq61fkTGJbMwFmw30uxSrI5N9uRofnf-X8HE8F78bhPKWzYd85OHzzkHC3WAkCRi6FeNyyRu6Trff9dQObNQycH6c2ymaU4mCWSLY',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:42:48.626Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                'latestOrderId': 'GPA.3375-6103-0197-44778..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:52:48.269Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3375-6103-0197-44778',
                    }
                ],
            },
        )
        renew_after_grace = TestScenario(  # 3. User renews, exiting grace period
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760057286988',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 2,
                    'purchaseToken': 'jflmajbhbddmjjjihphljklh.AO-J1Ox0T3IQHCVuZkRq61fkTGJbMwFmw30uxSrI5N9uRofnf-X8HE8F78bhPKWzYd85OHzzkHC3WAkCRi6FeNyyRu6Trff9dQObNQycH6c2ymaU4mCWSLY',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:42:48.626Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3375-6103-0197-44778..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:52:48.269Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3375-6103-0197-44778..0',
                    }
                ],
            },
        )
        cancel = TestScenario(  # 4. User cancels (probably dont need this)
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760057334978',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 3,
                    'purchaseToken': 'jflmajbhbddmjjjihphljklh.AO-J1Ox0T3IQHCVuZkRq61fkTGJbMwFmw30uxSrI5N9uRofnf-X8HE8F78bhPKWzYd85OHzzkHC3WAkCRi6FeNyyRu6Trff9dQObNQycH6c2ymaU4mCWSLY',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:42:48.626Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_CANCELED',
                'latestOrderId': 'GPA.3375-6103-0197-44778..0',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-10T00:48:53.285Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:52:48.269Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3375-6103-0197-44778..0',
                    }
                ],
            },
        )
        expire = TestScenario(  # 5. Expires (probably dont need this)
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760057579735',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'jflmajbhbddmjjjihphljklh.AO-J1Ox0T3IQHCVuZkRq61fkTGJbMwFmw30uxSrI5N9uRofnf-X8HE8F78bhPKWzYd85OHzzkHC3WAkCRi6FeNyyRu6Trff9dQObNQycH6c2ymaU4mCWSLY',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:42:48.626Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3375-6103-0197-44778..0',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-10T00:48:53.285Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:52:48.269Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3375-6103-0197-44778..0',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        tx_subscribe, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """2. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            # tx_grace, not tx_subscribe: entering grace now converges the TERM as well as the grace period.
            # The old IN_GRACE branch wrote only the grace duration and left expiry_at wherever the purchase
            # had put it, so the resource's own view of the term never reached the payment row.
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=store_extension(tx_subscribe, tx_grace),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        # Expire payments at the EOD of the resubscribe expiry_ts (note the extend expiry_ts from the grace period tx)
        run_prune_at_end_of_day(event_ms=tx_grace.event_ms)

        # Now that payments up to the expiry time has been expired, this user's status should be expired (we need to also time-travel the clock past the grace period they were allocated)
        assert_payment_details(
            # tx_grace for the same reason as above: the grace notification converged the term, so the row
            # this is asserting on carries the resource's expiry rather than the purchase's.
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=store_extension(tx_subscribe, tx_grace),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + store_grace.milliseconds,
        )

        """3. User renews"""
        # NOTE: We don't check that the payment is unredeemed because this renewal will get
        # auto-redeemed due to "Google" sending the notification before the auto-redeem deadline
        # which is defined as the any time before the end of account hold.
        tx_renew, platform_refund_expiry_unix_tx_ms = test_make_purchase(
            purchase=renew_after_grace, plan=base.ProPlan.OneMonth, ctx=ctx, check_payment_is_unredeemed=False
        )
        user_ctx.payments += 1  # Auto-redeem, so 1 extra payment was done

        """4. User cancels"""
        tx_cancel = test_notification(cancel, ctx)
        assert_payment_details(
            tx=tx_renew,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=False,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_cancel.event_ms,
        )

        """5. Subscription expires"""
        # status isnt expired yet as the rounded expiry time hasnt happend and the sweeper hasn't run, so there should be no status change
        tx_expire = test_notification(expire, ctx)
        assert_payment_details(
            tx=tx_renew,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=False,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        run_prune_at_end_of_day(event_ms=tx_expire.event_ms)
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            tx=tx_renew,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=False,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_expire.event_ms,
        )

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User renews 1-month subscription
        3. User renews 1-month subscription
        4. User cancels 1-month subscription
        5. Subscription expires
        6. User resubscribes
        7. User fails to renew, entering grace period
        8. User fails to renew, entering account hold
        9. User fails to renew, cancelling and expiring
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760054059175',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'lnddpdboobddmpoiaonnneoe.AO-J1Ow9QQNKenAPxf9XeH3xwcbAnaVWSLGGcVA9Tsui1d8IqFsESiqvO0VcC5uv1IIHneWY95eQ5RyRBsW7Q1p7GFAs7OJPFHAvNo3T1q-yg08eL53UB88',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-09T23:54:19.001Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3309-4032-8192-54127',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-09T23:59:18.613Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3309-4032-8192-54127',
                    }
                ],
            },
        )
        renew_1 = TestScenario(  # 2. User renews 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760054493266',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 2,
                    'purchaseToken': 'lnddpdboobddmpoiaonnneoe.AO-J1Ow9QQNKenAPxf9XeH3xwcbAnaVWSLGGcVA9Tsui1d8IqFsESiqvO0VcC5uv1IIHneWY95eQ5RyRBsW7Q1p7GFAs7OJPFHAvNo3T1q-yg08eL53UB88',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-09T23:54:19.001Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3309-4032-8192-54127..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:04:18.613Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3309-4032-8192-54127..0',
                    }
                ],
            },
        )
        renew_2 = TestScenario(  # 3. User renews 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760054662501',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 2,
                    'purchaseToken': 'lnddpdboobddmpoiaonnneoe.AO-J1Ow9QQNKenAPxf9XeH3xwcbAnaVWSLGGcVA9Tsui1d8IqFsESiqvO0VcC5uv1IIHneWY95eQ5RyRBsW7Q1p7GFAs7OJPFHAvNo3T1q-yg08eL53UB88',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-09T23:54:19.001Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3309-4032-8192-54127..1',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:09:18.613Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3309-4032-8192-54127..1',
                    }
                ],
            },
        )
        cancel = TestScenario(  # 4. User cancels 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760054819931',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 3,
                    'purchaseToken': 'lnddpdboobddmpoiaonnneoe.AO-J1Ow9QQNKenAPxf9XeH3xwcbAnaVWSLGGcVA9Tsui1d8IqFsESiqvO0VcC5uv1IIHneWY95eQ5RyRBsW7Q1p7GFAs7OJPFHAvNo3T1q-yg08eL53UB88',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-09T23:54:19.001Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_CANCELED',
                'latestOrderId': 'GPA.3309-4032-8192-54127..1',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-10T00:06:59.489Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:09:18.613Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3309-4032-8192-54127..1',
                    }
                ],
            },
        )
        expire = TestScenario(  # 5. Subscription expires
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760054959804',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'lnddpdboobddmpoiaonnneoe.AO-J1Ow9QQNKenAPxf9XeH3xwcbAnaVWSLGGcVA9Tsui1d8IqFsESiqvO0VcC5uv1IIHneWY95eQ5RyRBsW7Q1p7GFAs7OJPFHAvNo3T1q-yg08eL53UB88',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-09T23:54:19.001Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3309-4032-8192-54127..1',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-10T00:06:59.489Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:09:18.613Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3309-4032-8192-54127..1',
                    }
                ],
            },
        )
        resubscribe = TestScenario(  # 6. User purchases (SUBSCRIPTION_PURCHASED)
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760055149918',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'jpdlliaaipkedokapkmchknd.AO-J1OyO0nXUZyOJqpgh7Rzie_FWawzMdrgHkLFH0JUxTZZSIxikffSv1oKcktXkiJnRCuevUxW4Al5AENkfTZZnDQFZqfqqJQf3CHHLjWk_fw7kjewoRDk',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:12:29.781Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3326-4415-9310-90534',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:17:29.313Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3326-4415-9310-90534',
                    }
                ],
            },
        )
        grace = TestScenario(  # 7. User fail to renew, entering grace period (SUBSCRIPTION_IN_GRACE_PERIOD)
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760055456738',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 6,
                    'purchaseToken': 'jpdlliaaipkedokapkmchknd.AO-J1OyO0nXUZyOJqpgh7Rzie_FWawzMdrgHkLFH0JUxTZZSIxikffSv1oKcktXkiJnRCuevUxW4Al5AENkfTZZnDQFZqfqqJQf3CHHLjWk_fw7kjewoRDk',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:12:29.781Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                'latestOrderId': 'GPA.3326-4415-9310-90534..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:22:29.313Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3326-4415-9310-90534',
                    }
                ],
            },
        )
        hold = TestScenario(  # 8. User fails to renew, entering account hold
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760055750572',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 5,
                    'purchaseToken': 'jpdlliaaipkedokapkmchknd.AO-J1OyO0nXUZyOJqpgh7Rzie_FWawzMdrgHkLFH0JUxTZZSIxikffSv1oKcktXkiJnRCuevUxW4Al5AENkfTZZnDQFZqfqqJQf3CHHLjWk_fw7kjewoRDk',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:12:29.781Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ON_HOLD',
                'latestOrderId': 'GPA.3326-4415-9310-90534..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:22:29.313Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3326-4415-9310-90534',
                    }
                ],
            },
        )
        fail_after_hold_a = TestScenario(  # 9. User fails to renew, cancelling and expiring
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760056350982',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 3,
                    'purchaseToken': 'jpdlliaaipkedokapkmchknd.AO-J1OyO0nXUZyOJqpgh7Rzie_FWawzMdrgHkLFH0JUxTZZSIxikffSv1oKcktXkiJnRCuevUxW4Al5AENkfTZZnDQFZqfqqJQf3CHHLjWk_fw7kjewoRDk',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:12:29.781Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3326-4415-9310-90534..0',
                'canceledStateContext': {'systemInitiatedCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:32:30.758Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3326-4415-9310-90534',
                    }
                ],
            },
        )
        fail_after_hold_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760056353213',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'jpdlliaaipkedokapkmchknd.AO-J1OyO0nXUZyOJqpgh7Rzie_FWawzMdrgHkLFH0JUxTZZSIxikffSv1oKcktXkiJnRCuevUxW4Al5AENkfTZZnDQFZqfqqJQf3CHHLjWk_fw7kjewoRDk',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T00:12:29.781Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3326-4415-9310-90534..0',
                'canceledStateContext': {'systemInitiatedCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T00:32:30.758Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3326-4415-9310-90534',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        test_make_purchase_and_claim_payment(purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx)

        """2. User renews"""
        # NOTE: Auto-redeem kicks in so claim is automatic
        test_make_purchase(purchase=renew_1, plan=base.ProPlan.OneMonth, ctx=ctx, check_payment_is_unredeemed=False)
        user_ctx.payments += 1

        """3. User renews"""
        # NOTE: Auto-redeem kicks in so claim is automatic
        tx_renew_2, platform_refund_expiry_unix_tx_ms = test_make_purchase(
            purchase=renew_2, plan=base.ProPlan.OneMonth, ctx=ctx, check_payment_is_unredeemed=False
        )
        user_ctx.payments += 1

        """4. User cancels"""
        # NOTE: Auto-redeem uses the unredeemed timestamp rounded up whereas if you claim it manually, it uses the server's time
        test_notification(cancel, ctx)
        assert_payment_details(
            tx=tx_renew_2,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=False,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        """5. Subscription expires"""
        tx_expire = test_notification(expire, ctx)
        # status isnt expired yet as the rounded expiry time hasn't happened and the sweeper hasn't run, so there should be no status change
        assert_payment_details(
            tx=tx_renew_2,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=False,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        # Expire payments
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        run_prune_at_end_of_day(event_ms=tx_expire.event_ms)
        assert_payment_details(
            tx=tx_renew_2,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=False,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_expire.event_ms,
        )

        """6. User purchased (SUBSCRIPTION_PURCHASED)"""
        tx_resubscribe, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=resubscribe, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """7. User fails to renew (enter grace period)"""
        # tx_grace, not tx_resubscribe: entering grace converges the TERM as well now, so the resource's
        # own view of the expiry is what reached the payment row.
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_resubscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=store_extension(tx_resubscribe, tx_grace),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        # Now that payments up to the expiry time has been expired, this user's status should be expired
        run_prune_at_end_of_day(event_ms=tx_grace.event_ms)
        assert_payment_details(
            tx=tx_resubscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=store_extension(tx_resubscribe, tx_grace),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + store_grace.milliseconds,
        )

        """8. User fails to renew (enter account hold)"""
        tx_hold = test_notification(hold, ctx)
        assert_payment_details(
            tx=tx_hold,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + store_grace.milliseconds,
        )

        """9. User fails to renew, cancelling and expiring"""
        test_notification(fail_after_hold_a, ctx)
        # The last resource to be converged is the account's term: each of these carries the subscription's
        # current expiry, and convergence takes the store at its word rather than keeping the first value
        # it ever saw.
        tx_fail = test_notification(fail_after_hold_b, ctx)
        assert_payment_details(
            tx=tx_fail,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=False,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + store_grace.milliseconds,
        )

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User enters grace period as they fail to renew
        3. User cancels, exiting grace period
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760058070950',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'ehkfchpacbicpfpnkedempao.AO-J1OxW86ZtW-xdq2l1Xo5HkpOC2DvuqCL6xKJrMrIib5URdpVL6n0NzbSMkwyOjK6_CR2A9myRvVVqIodIxuSsEFypEByw57XoLN3NKDJPiGnK4zvodQg',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:01:10.821Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3385-3546-4929-55699',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:06:10.406Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-3546-4929-55699',
                    }
                ],
            },
        )
        grace = TestScenario(  # 2. User enters grace period as they fail to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760058375847',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 6,
                    'purchaseToken': 'ehkfchpacbicpfpnkedempao.AO-J1OxW86ZtW-xdq2l1Xo5HkpOC2DvuqCL6xKJrMrIib5URdpVL6n0NzbSMkwyOjK6_CR2A9myRvVVqIodIxuSsEFypEByw57XoLN3NKDJPiGnK4zvodQg',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:01:10.821Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                'latestOrderId': 'GPA.3385-3546-4929-55699..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:11:10.406Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-3546-4929-55699',
                    }
                ],
            },
        )
        cancel_after_grace_a = TestScenario(  # 3. User cancels, exiting grace period
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760058385564',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 3,
                    'purchaseToken': 'ehkfchpacbicpfpnkedempao.AO-J1OxW86ZtW-xdq2l1Xo5HkpOC2DvuqCL6xKJrMrIib5URdpVL6n0NzbSMkwyOjK6_CR2A9myRvVVqIodIxuSsEFypEByw57XoLN3NKDJPiGnK4zvodQg',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:01:10.821Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3385-3546-4929-55699..0',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-10T01:06:25.090Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:06:25.090Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-3546-4929-55699',
                    }
                ],
            },
        )
        cancel_after_grace_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760058388512',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'ehkfchpacbicpfpnkedempao.AO-J1OxW86ZtW-xdq2l1Xo5HkpOC2DvuqCL6xKJrMrIib5URdpVL6n0NzbSMkwyOjK6_CR2A9myRvVVqIodIxuSsEFypEByw57XoLN3NKDJPiGnK4zvodQg',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:01:10.821Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3385-3546-4929-55699..0',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-10T01:06:25.090Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:06:25.090Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-3546-4929-55699',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        tx_subscribe, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """2. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            # tx_grace, not tx_subscribe: entering grace now converges the TERM as well as the grace period.
            # The old IN_GRACE branch wrote only the grace duration and left expiry_at wherever the purchase
            # had put it, so the resource's own view of the term never reached the payment row.
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=store_extension(tx_subscribe, tx_grace),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        run_prune_at_end_of_day(event_ms=tx_grace.event_ms)
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            # tx_grace for the same reason as above: the grace notification converged the term, so the row
            # this is asserting on carries the resource's expiry rather than the purchase's.
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=store_extension(tx_subscribe, tx_grace),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + store_grace.milliseconds,
        )

        """3. User cancels, exiting grace period"""
        test_notification(cancel_after_grace_a, ctx)
        tx_cancel = test_notification(cancel_after_grace_b, ctx)
        assert_payment_details(
            tx=tx_cancel,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=False,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + store_grace.milliseconds,
        )

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User enters grace period as they fail to renew
        3. User enters account hold as they continue to fail to renew
        4. User cancels
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760058562006',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'jcbkgneihmbdlpmngappmhll.AO-J1OwzyOh1uez7lSwcsrAEyQ6eHswTVZXAMKuBqHEIxIJFnbv0u16Cs4qS7xqcB_M0sCMslIajcYdjCaeJ-7SI2NkgUSVwdqj4II5_WatWtfBAa9vgp74',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:09:21.833Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3385-4424-2558-38000',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:14:21.418Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-4424-2558-38000',
                    }
                ],
            },
        )
        grace = TestScenario(  # 2. User enters grace period as they fail to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760058876825',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 6,
                    'purchaseToken': 'jcbkgneihmbdlpmngappmhll.AO-J1OwzyOh1uez7lSwcsrAEyQ6eHswTVZXAMKuBqHEIxIJFnbv0u16Cs4qS7xqcB_M0sCMslIajcYdjCaeJ-7SI2NkgUSVwdqj4II5_WatWtfBAa9vgp74',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:09:21.833Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                'latestOrderId': 'GPA.3385-4424-2558-38000..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:19:21.418Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-4424-2558-38000',
                    }
                ],
            },
        )
        hold = TestScenario(  # 3. User enters account hold as they continue to fail to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760059162455',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 5,
                    'purchaseToken': 'jcbkgneihmbdlpmngappmhll.AO-J1OwzyOh1uez7lSwcsrAEyQ6eHswTVZXAMKuBqHEIxIJFnbv0u16Cs4qS7xqcB_M0sCMslIajcYdjCaeJ-7SI2NkgUSVwdqj4II5_WatWtfBAa9vgp74',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:09:21.833Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ON_HOLD',
                'latestOrderId': 'GPA.3385-4424-2558-38000..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:19:21.418Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-4424-2558-38000',
                    }
                ],
            },
        )
        cancel_after_hold_a = TestScenario(  # 4. User cancels
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760059762429',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 3,
                    'purchaseToken': 'jcbkgneihmbdlpmngappmhll.AO-J1OwzyOh1uez7lSwcsrAEyQ6eHswTVZXAMKuBqHEIxIJFnbv0u16Cs4qS7xqcB_M0sCMslIajcYdjCaeJ-7SI2NkgUSVwdqj4II5_WatWtfBAa9vgp74',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:09:21.833Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3385-4424-2558-38000..0',
                'canceledStateContext': {'systemInitiatedCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:29:22.310Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-4424-2558-38000',
                    }
                ],
            },
        )
        cancel_after_hold_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760059764910',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'jcbkgneihmbdlpmngappmhll.AO-J1OwzyOh1uez7lSwcsrAEyQ6eHswTVZXAMKuBqHEIxIJFnbv0u16Cs4qS7xqcB_M0sCMslIajcYdjCaeJ-7SI2NkgUSVwdqj4II5_WatWtfBAa9vgp74',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T01:09:21.833Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3385-4424-2558-38000..0',
                'canceledStateContext': {'systemInitiatedCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T01:29:22.310Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3385-4424-2558-38000',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User resubscribed"""
        tx_subscribe, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """2. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            # tx_grace, not tx_subscribe: entering grace now converges the TERM as well as the grace period.
            # The old IN_GRACE branch wrote only the grace duration and left expiry_at wherever the purchase
            # had put it, so the resource's own view of the term never reached the payment row.
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=store_extension(tx_subscribe, tx_grace),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        # Expire payments at the EOD of the resubscribe expiry_ts (not the extend expiry_ts from the grace period tx)
        run_prune_at_end_of_day(event_ms=tx_grace.event_ms)
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            # tx_grace for the same reason as above: the grace notification converged the term, so the row
            # this is asserting on carries the resource's expiry rather than the purchase's.
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=store_extension(tx_subscribe, tx_grace),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + store_grace.milliseconds,
        )

        """3. User fails to renew (enter account hold)"""
        tx_hold = test_notification(hold, ctx)
        assert_payment_details(
            # tx_grace for the same reason as above: the grace notification converged the term, so the row
            # this is asserting on carries the resource's expiry rather than the purchase's.
            tx=tx_hold,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + store_grace.milliseconds,
        )

        """4. User cancels"""
        test_notification(cancel_after_hold_a, ctx)
        tx_cancel = test_notification(cancel_after_hold_b, ctx)
        assert_payment_details(
            tx=tx_cancel,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=False,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + store_grace.milliseconds,
        )

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User enters grace period as they fail to renew
        3. User enters account hold as they continue to fail to renew
        4. User renews, exiting account hold
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760063571318',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'fiamkojbeobfecknhdfhfgdk.AO-J1OxpMbHczoHY4AbpJsd9gwqzTs-_9zpEGMedCUMXkjrvBgTVdNyl0eowweuNYlVYTR7_D1NN_LYO8U8ScP8cnqbzZ5qB_TrWWQtXif7Es6Xp2PEE1SI',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T02:32:51.206Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3340-4002-2060-79596',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T02:37:50.765Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3340-4002-2060-79596',
                    }
                ],
            },
        )
        grace = TestScenario(  # 2. User enters grace period as they fail to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760063877258',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 6,
                    'purchaseToken': 'fiamkojbeobfecknhdfhfgdk.AO-J1OxpMbHczoHY4AbpJsd9gwqzTs-_9zpEGMedCUMXkjrvBgTVdNyl0eowweuNYlVYTR7_D1NN_LYO8U8ScP8cnqbzZ5qB_TrWWQtXif7Es6Xp2PEE1SI',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T02:32:51.206Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                'latestOrderId': 'GPA.3340-4002-2060-79596..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T02:42:50.765Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3340-4002-2060-79596',
                    }
                ],
            },
        )
        hold = TestScenario(  # 3. User enters account hold as they continue to fail to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760064172032',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 5,
                    'purchaseToken': 'fiamkojbeobfecknhdfhfgdk.AO-J1OxpMbHczoHY4AbpJsd9gwqzTs-_9zpEGMedCUMXkjrvBgTVdNyl0eowweuNYlVYTR7_D1NN_LYO8U8ScP8cnqbzZ5qB_TrWWQtXif7Es6Xp2PEE1SI',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T02:32:51.206Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ON_HOLD',
                'latestOrderId': 'GPA.3340-4002-2060-79596..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T02:42:50.765Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3340-4002-2060-79596',
                    }
                ],
            },
        )
        renew = TestScenario(  # 4. User renews, exiting account hold (SUBSCRIPTION_RECOVERED)
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760064181132',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 1,
                    'purchaseToken': 'fiamkojbeobfecknhdfhfgdk.AO-J1OxpMbHczoHY4AbpJsd9gwqzTs-_9zpEGMedCUMXkjrvBgTVdNyl0eowweuNYlVYTR7_D1NN_LYO8U8ScP8cnqbzZ5qB_TrWWQtXif7Es6Xp2PEE1SI',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T02:32:51.206Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3340-4002-2060-79596..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T02:48:00.760Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3340-4002-2060-79596..0',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User resubscribed"""
        tx_subscribe, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """2. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            # tx_grace, not tx_subscribe: entering grace now converges the TERM as well as the grace period.
            # The old IN_GRACE branch wrote only the grace duration and left expiry_at wherever the purchase
            # had put it, so the resource's own view of the term never reached the payment row.
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=store_extension(tx_subscribe, tx_grace),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        run_prune_at_end_of_day(event_ms=tx_grace.event_ms)
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            # tx_grace for the same reason as above: the grace notification converged the term, so the row
            # this is asserting on carries the resource's expiry rather than the purchase's.
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=store_extension(tx_subscribe, tx_grace),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + store_grace.milliseconds,
        )

        """3. User fails to renew (enter account hold)"""
        tx_hold = test_notification(hold, ctx)
        assert_payment_details(
            # tx_grace for the same reason as above: the grace notification converged the term, so the row
            # this is asserting on carries the resource's expiry rather than the purchase's.
            tx=tx_hold,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + store_grace.milliseconds,
        )

        """4. User renews (SUBSCRIPTION_RECOVERED)"""
        # NOTE: Auto-redeem kicks in
        tx, platform_refund_expiry_unix_tx_ms = test_make_purchase(
            purchase=renew, plan=base.ProPlan.OneMonth, ctx=ctx, check_payment_is_unredeemed=False
        )
        user_ctx.payments += 1

        assert_has_payment(
            tx=tx,
            plan=base.ProPlan.OneMonth,
            redeemed_ts_ms=None,  # the mule auto-redeemed this one
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

        assert_has_user(tx=tx, user_ctx=user_ctx, ctx=ctx)

        assert_payment_details(
            tx=tx,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User changes to 3-month plan
        3. User renews
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760064664489',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'djmaggipjlbmnncfpnaiecgp.AO-J1OzsodQ6LAqNSpZq4F8pvQCko4BhEvKfI8x4JU95p3v0lVVEIis2J-L8WwifcHwYGuCl0fZ4Tjby9Cyig9R5NUYVGqq156Gezco_-Dbw-pyHAZWVM3E',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T02:51:04.303Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3361-2060-7612-01550',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T02:56:03.854Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3361-2060-7612-01550',
                    }
                ],
            },
        )
        change_plan_a = TestScenario(  # 2. User changes to 3-month plan
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760064707992',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'nbcpbihedkkbpihikkahjhhn.AO-J1OzYWzZdp7VGTVIrZH_WBoLTIBlRN8F_LB5Pu3DK0Hk4GtZzcZzS6tRsVLBLUNH19SxsI6Yq4DFMvyh-SHGT35BXUPg_jufa03is3zDblMMA_FWSwQ4',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T02:51:47.820Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3346-9218-7706-30541',
                'linkedPurchaseToken': 'djmaggipjlbmnncfpnaiecgp.AO-J1OzsodQ6LAqNSpZq4F8pvQCko4BhEvKfI8x4JU95p3v0lVVEIis2J-L8WwifcHwYGuCl0fZ4Tjby9Cyig9R5NUYVGqq156Gezco_-Dbw-pyHAZWVM3E',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T02:56:07.125Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3346-9218-7706-30541',
                    }
                ],
            },
        )
        change_plan_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760064712021',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'djmaggipjlbmnncfpnaiecgp.AO-J1OzsodQ6LAqNSpZq4F8pvQCko4BhEvKfI8x4JU95p3v0lVVEIis2J-L8WwifcHwYGuCl0fZ4Tjby9Cyig9R5NUYVGqq156Gezco_-Dbw-pyHAZWVM3E',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T02:51:04.303Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3361-2060-7612-01550',
                'canceledStateContext': {'replacementCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T02:51:47.692Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3361-2060-7612-01550',
                    }
                ],
            },
        )
        renew = TestScenario(  # 3. User renews
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760065012245',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 2,
                    'purchaseToken': 'nbcpbihedkkbpihikkahjhhn.AO-J1OzYWzZdp7VGTVIrZH_WBoLTIBlRN8F_LB5Pu3DK0Hk4GtZzcZzS6tRsVLBLUNH19SxsI6Yq4DFMvyh-SHGT35BXUPg_jufa03is3zDblMMA_FWSwQ4',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T02:51:47.820Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3346-9218-7706-30541..0',
                'linkedPurchaseToken': 'djmaggipjlbmnncfpnaiecgp.AO-J1OzsodQ6LAqNSpZq4F8pvQCko4BhEvKfI8x4JU95p3v0lVVEIis2J-L8WwifcHwYGuCl0fZ4Tjby9Cyig9R5NUYVGqq156Gezco_-Dbw-pyHAZWVM3E',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:06:07.125Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3346-9218-7706-30541..0',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        test_make_purchase_and_claim_payment(purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx)

        """2. User changes to 3-month plan"""
        test_make_purchase_and_claim_payment(
            purchase=change_plan_a, plan=base.ProPlan.ThreeMonth, user_ctx=user_ctx, ctx=ctx
        )
        test_notification(change_plan_b, ctx)

        """3. User renews"""
        # NOTE: Auto-renew kicks in
        tx, platform_refund_expiry_unix_tx_ms = test_make_purchase(
            purchase=renew, plan=base.ProPlan.ThreeMonth, ctx=ctx, check_payment_is_unredeemed=False
        )
        user_ctx.payments += 1

        assert_has_user(tx=tx, user_ctx=user_ctx, ctx=ctx)

        assert_payment_details(
            tx=tx,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User changes to 3-month plan
        3. User enters grace period as they fail to renew
        4. User renews, exiting grace period
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760065659150',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'cgebhhmdboacddnnibmcmdae.AO-J1Owku1Fiw2R78U5kCf3i0GjH5BtuPn3H6d3KPmbIkUiLFRMgHbxv2YLyFNshn90hQzIf2LGnXfHa_dd3YV7qIyIjrWrvwqeIwaEvtMJvV-WtYmVckSE',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:07:39.032Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3361-4036-2635-52589',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:12:38.652Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3361-4036-2635-52589',
                    }
                ],
            },
        )
        change_plan_a = TestScenario(  # 2. User changes to 3-month plan
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760065678442',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'cmmdicdefdehlffhmchedffo.AO-J1OwdBoWT8t_cCjOY_aa1RcIG6QK31BNBXtXtrNIAqpDQg9w_po6fRIv1vqYPxQFXsay8LjarIwmtamkt4U8moGkk-oq5yLXOUbH8yzpt2JoXhqD9C_U',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:07:58.213Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3307-6442-0359-63641',
                'linkedPurchaseToken': 'cgebhhmdboacddnnibmcmdae.AO-J1Owku1Fiw2R78U5kCf3i0GjH5BtuPn3H6d3KPmbIkUiLFRMgHbxv2YLyFNshn90hQzIf2LGnXfHa_dd3YV7qIyIjrWrvwqeIwaEvtMJvV-WtYmVckSE',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:12:41.697Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3307-6442-0359-63641',
                    }
                ],
            },
        )
        change_plan_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760065680270',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'cgebhhmdboacddnnibmcmdae.AO-J1Owku1Fiw2R78U5kCf3i0GjH5BtuPn3H6d3KPmbIkUiLFRMgHbxv2YLyFNshn90hQzIf2LGnXfHa_dd3YV7qIyIjrWrvwqeIwaEvtMJvV-WtYmVckSE',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:07:39.032Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3361-4036-2635-52589',
                'canceledStateContext': {'replacementCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:07:58.101Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3361-4036-2635-52589',
                    }
                ],
            },
        )
        grace = TestScenario(  # 3. User enters grace period as they fail to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760065966693',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 6,
                    'purchaseToken': 'cmmdicdefdehlffhmchedffo.AO-J1OwdBoWT8t_cCjOY_aa1RcIG6QK31BNBXtXtrNIAqpDQg9w_po6fRIv1vqYPxQFXsay8LjarIwmtamkt4U8moGkk-oq5yLXOUbH8yzpt2JoXhqD9C_U',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:07:58.213Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                'latestOrderId': 'GPA.3307-6442-0359-63641..0',
                'linkedPurchaseToken': 'cgebhhmdboacddnnibmcmdae.AO-J1Owku1Fiw2R78U5kCf3i0GjH5BtuPn3H6d3KPmbIkUiLFRMgHbxv2YLyFNshn90hQzIf2LGnXfHa_dd3YV7qIyIjrWrvwqeIwaEvtMJvV-WtYmVckSE',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:17:41.697Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3307-6442-0359-63641',
                    }
                ],
            },
        )
        renew = TestScenario(  # 4. User renews, exiting grace period
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760065984697',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 2,
                    'purchaseToken': 'cmmdicdefdehlffhmchedffo.AO-J1OwdBoWT8t_cCjOY_aa1RcIG6QK31BNBXtXtrNIAqpDQg9w_po6fRIv1vqYPxQFXsay8LjarIwmtamkt4U8moGkk-oq5yLXOUbH8yzpt2JoXhqD9C_U',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:07:58.213Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3307-6442-0359-63641..0',
                'linkedPurchaseToken': 'cgebhhmdboacddnnibmcmdae.AO-J1Owku1Fiw2R78U5kCf3i0GjH5BtuPn3H6d3KPmbIkUiLFRMgHbxv2YLyFNshn90hQzIf2LGnXfHa_dd3YV7qIyIjrWrvwqeIwaEvtMJvV-WtYmVckSE',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:22:41.697Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3307-6442-0359-63641..0',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        test_make_purchase_and_claim_payment(purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx)

        """2. User changes to 3-month plan"""
        tx_change_plan, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=change_plan_a, plan=base.ProPlan.ThreeMonth, user_ctx=user_ctx, ctx=ctx
        )
        test_notification(change_plan_b, ctx)

        """3. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_change_plan,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=store_extension(tx_change_plan, tx_grace),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        run_prune_at_end_of_day(event_ms=tx_grace.event_ms)

        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            tx=tx_change_plan,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=store_extension(tx_change_plan, tx_grace),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + store_grace.milliseconds,
        )

        """4. User renews"""
        # NOTE: Auto-renew kicks in
        tx, platform_refund_expiry_unix_tx_ms = test_make_purchase(
            purchase=renew, plan=base.ProPlan.ThreeMonth, ctx=ctx, check_payment_is_unredeemed=False
        )
        user_ctx.payments += 1

        assert_has_user(tx=tx, user_ctx=user_ctx, ctx=ctx)

        assert_payment_details(
            tx=tx,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User changes to 3-month plan
        3. User enters grace period as they fail to renew
        4. User enters account hold as they continue to fail to renew
        5. User renews, exiting account hold
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760066883333',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'fmendicbhbajfhkpimcddflh.AO-J1Ow-7gobZJ1nV4R0ou7ItWlVGHJ_6LKU98IeiVYWlgYwF5t7e0Fw8B5MfLjHes7GzqCIUF8xjYw8q7A7vxz7JSKfso_ZlBF9EiX1XW6wRqeOt1lxFIg',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:28:03.223Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3360-4209-1350-91491',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:33:02.513Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3360-4209-1350-91491',
                    }
                ],
            },
        )
        change_plan_a = TestScenario(  # 2. User changes to 3-month plan
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760066932029',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'dilmafpdglapmhabknlhjgje.AO-J1OxX-ApsyARxtSAGIzIXOlhvpK6OCxjuqC5DJzPrO51Os6gHNZq3gPgMaaZc-dsJ-QwYj3oa4PP49HT-ZXoptya257BXC7ggHtIbdB7fnLXatIkETws',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:28:51.780Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3385-9037-2688-17153',
                'linkedPurchaseToken': 'fmendicbhbajfhkpimcddflh.AO-J1Ow-7gobZJ1nV4R0ou7ItWlVGHJ_6LKU98IeiVYWlgYwF5t7e0Fw8B5MfLjHes7GzqCIUF8xjYw8q7A7vxz7JSKfso_ZlBF9EiX1XW6wRqeOt1lxFIg',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:33:04.239Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3385-9037-2688-17153',
                    }
                ],
            },
        )
        change_plan_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760066934397',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'fmendicbhbajfhkpimcddflh.AO-J1Ow-7gobZJ1nV4R0ou7ItWlVGHJ_6LKU98IeiVYWlgYwF5t7e0Fw8B5MfLjHes7GzqCIUF8xjYw8q7A7vxz7JSKfso_ZlBF9EiX1XW6wRqeOt1lxFIg',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:28:03.223Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3360-4209-1350-91491',
                'canceledStateContext': {'replacementCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:28:51.636Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3360-4209-1350-91491',
                    }
                ],
            },
        )
        grace = TestScenario(  # 3. User enters grace period as they fail to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760067219187',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 6,
                    'purchaseToken': 'dilmafpdglapmhabknlhjgje.AO-J1OxX-ApsyARxtSAGIzIXOlhvpK6OCxjuqC5DJzPrO51Os6gHNZq3gPgMaaZc-dsJ-QwYj3oa4PP49HT-ZXoptya257BXC7ggHtIbdB7fnLXatIkETws',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:28:51.780Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                'latestOrderId': 'GPA.3385-9037-2688-17153..0',
                'linkedPurchaseToken': 'fmendicbhbajfhkpimcddflh.AO-J1Ow-7gobZJ1nV4R0ou7ItWlVGHJ_6LKU98IeiVYWlgYwF5t7e0Fw8B5MfLjHes7GzqCIUF8xjYw8q7A7vxz7JSKfso_ZlBF9EiX1XW6wRqeOt1lxFIg',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:38:04.239Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3385-9037-2688-17153',
                    }
                ],
            },
        )
        hold = TestScenario(  # 4. User enters account hold as they continue to fail to renew
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760067515427',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 5,
                    'purchaseToken': 'dilmafpdglapmhabknlhjgje.AO-J1OxX-ApsyARxtSAGIzIXOlhvpK6OCxjuqC5DJzPrO51Os6gHNZq3gPgMaaZc-dsJ-QwYj3oa4PP49HT-ZXoptya257BXC7ggHtIbdB7fnLXatIkETws',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:28:51.780Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ON_HOLD',
                'latestOrderId': 'GPA.3385-9037-2688-17153..0',
                'linkedPurchaseToken': 'fmendicbhbajfhkpimcddflh.AO-J1Ow-7gobZJ1nV4R0ou7ItWlVGHJ_6LKU98IeiVYWlgYwF5t7e0Fw8B5MfLjHes7GzqCIUF8xjYw8q7A7vxz7JSKfso_ZlBF9EiX1XW6wRqeOt1lxFIg',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:38:04.239Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3385-9037-2688-17153',
                    }
                ],
            },
        )
        renew = TestScenario(  # 5. User renews, exiting account hold
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760067523842',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 1,
                    'purchaseToken': 'dilmafpdglapmhabknlhjgje.AO-J1OxX-ApsyARxtSAGIzIXOlhvpK6OCxjuqC5DJzPrO51Os6gHNZq3gPgMaaZc-dsJ-QwYj3oa4PP49HT-ZXoptya257BXC7ggHtIbdB7fnLXatIkETws',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:28:51.780Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3385-9037-2688-17153..0',
                'linkedPurchaseToken': 'fmendicbhbajfhkpimcddflh.AO-J1Ow-7gobZJ1nV4R0ou7ItWlVGHJ_6LKU98IeiVYWlgYwF5t7e0Fw8B5MfLjHes7GzqCIUF8xjYw8q7A7vxz7JSKfso_ZlBF9EiX1XW6wRqeOt1lxFIg',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:48:43.405Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3385-9037-2688-17153..0',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        test_make_purchase_and_claim_payment(purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx)

        """2. User changes to 3-month plan"""
        tx_change_plan, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=change_plan_a, plan=base.ProPlan.ThreeMonth, user_ctx=user_ctx, ctx=ctx
        )
        test_notification(change_plan_b, ctx)

        """2. User fails to renew (enter grace period)"""
        tx_grace = test_notification(grace, ctx)
        assert_payment_details(
            tx=tx_change_plan,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=store_extension(tx_change_plan, tx_grace),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )
        run_prune_at_end_of_day(event_ms=tx_grace.event_ms)
        # Now that payments up to the expiry time has been expired, this user's status should be expired
        assert_payment_details(
            tx=tx_change_plan,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=store_extension(tx_change_plan, tx_grace),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + store_grace.milliseconds,
        )

        """3. User fails to renew (enter account hold)"""
        tx_hold = test_notification(hold, ctx)
        assert_payment_details(
            tx=tx_hold,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Expired,
            auto_renew=True,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_grace.event_ms + store_grace.milliseconds,
        )

        """4. User renews"""
        # NOTE: Auto-renew kicks in
        tx, platform_refund_expiry_unix_tx_ms = test_make_purchase(
            purchase=renew, plan=base.ProPlan.ThreeMonth, ctx=ctx, check_payment_is_unredeemed=False
        )
        user_ctx.payments += 1

        assert_has_user(tx=tx, user_ctx=user_ctx, ctx=ctx)

        assert_payment_details(
            tx=tx,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. User changes to 3-month plan
        3. User changes to 1-month plan
        4. User renews
        """

        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760068190568',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'akknlgeihdpojligdpliahkd.AO-J1OylF_FKqn-mgcFGEP0uPJ3m81pAyz65LNRR2FA7zTmxDLqhzyqAFVlWI_kZ9UKJ6WVTSgCOL8VuyRYw3zjBD_WicdU00dywAxNEvA8RxOEBgt8_A4c',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:49:50.459Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3380-4949-2236-27006',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:54:50.029Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3380-4949-2236-27006',
                    }
                ],
            },
        )
        change_plan_a = TestScenario(  # 2. User changes to 3-month plan
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760068218921',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'ghmgjhcnkdnbhloomlbkdnkn.AO-J1OwyF695Pxv_uwqpulIkOeL5B21_Q1qKNGqVrD7-_Sm4_dkN9pcpRQC1WSlyT32YweRIbuoLIJzJ2VhfbY9VUGyD801SZSiUmRUf62WF1MKu4PzSj-Q',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:50:18.696Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3307-0514-1298-32110',
                'linkedPurchaseToken': 'akknlgeihdpojligdpliahkd.AO-J1OylF_FKqn-mgcFGEP0uPJ3m81pAyz65LNRR2FA7zTmxDLqhzyqAFVlWI_kZ9UKJ6WVTSgCOL8VuyRYw3zjBD_WicdU00dywAxNEvA8RxOEBgt8_A4c',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:54:54.238Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3307-0514-1298-32110',
                    }
                ],
            },
        )
        change_plan_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760068221351',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'akknlgeihdpojligdpliahkd.AO-J1OylF_FKqn-mgcFGEP0uPJ3m81pAyz65LNRR2FA7zTmxDLqhzyqAFVlWI_kZ9UKJ6WVTSgCOL8VuyRYw3zjBD_WicdU00dywAxNEvA8RxOEBgt8_A4c',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:49:50.459Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3380-4949-2236-27006',
                'canceledStateContext': {'replacementCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:50:18.593Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3380-4949-2236-27006',
                    }
                ],
            },
        )
        change_plan_back_a = TestScenario(  # 3. User changes to 1-month plan
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760068282443',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'ndpndadhkkmikonjoplconhp.AO-J1OzO9SK-_SBR9g-TCmf6CodhY-D57xpbXWFbGSp90W49E04JmmJNkjTAYfJXj1C7p6nfo7iHtBTU9SPoG2ov0CCU5b9URNQZfkuozZzdsYWnCe5GFps',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:51:22.253Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3306-9365-6055-58193',
                'linkedPurchaseToken': 'ghmgjhcnkdnbhloomlbkdnkn.AO-J1OwyF695Pxv_uwqpulIkOeL5B21_Q1qKNGqVrD7-_Sm4_dkN9pcpRQC1WSlyT32YweRIbuoLIJzJ2VhfbY9VUGyD801SZSiUmRUf62WF1MKu4PzSj-Q',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:54:59.698Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3306-9365-6055-58193',
                    }
                ],
            },
        )
        change_plan_back_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760068283977',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'ghmgjhcnkdnbhloomlbkdnkn.AO-J1OwyF695Pxv_uwqpulIkOeL5B21_Q1qKNGqVrD7-_Sm4_dkN9pcpRQC1WSlyT32YweRIbuoLIJzJ2VhfbY9VUGyD801SZSiUmRUf62WF1MKu4PzSj-Q',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:50:18.696Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3307-0514-1298-32110',
                'linkedPurchaseToken': 'akknlgeihdpojligdpliahkd.AO-J1OylF_FKqn-mgcFGEP0uPJ3m81pAyz65LNRR2FA7zTmxDLqhzyqAFVlWI_kZ9UKJ6WVTSgCOL8VuyRYw3zjBD_WicdU00dywAxNEvA8RxOEBgt8_A4c',
                'canceledStateContext': {'replacementCancellation': {}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:51:22.124Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '84', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-3-months', 'offerTags': ['three-months']},
                        'latestSuccessfulOrderId': 'GPA.3307-0514-1298-32110',
                    }
                ],
            },
        )
        renew = TestScenario(  # 4. User renews
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760068505712',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 2,
                    'purchaseToken': 'ndpndadhkkmikonjoplconhp.AO-J1OzO9SK-_SBR9g-TCmf6CodhY-D57xpbXWFbGSp90W49E04JmmJNkjTAYfJXj1C7p6nfo7iHtBTU9SPoG2ov0CCU5b9URNQZfkuozZzdsYWnCe5GFps',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T03:51:22.253Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3306-9365-6055-58193..0',
                'linkedPurchaseToken': 'ghmgjhcnkdnbhloomlbkdnkn.AO-J1OwyF695Pxv_uwqpulIkOeL5B21_Q1qKNGqVrD7-_Sm4_dkN9pcpRQC1WSlyT32YweRIbuoLIJzJ2VhfbY9VUGyD801SZSiUmRUf62WF1MKu4PzSj-Q',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T03:59:59.698Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3306-9365-6055-58193..0',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        test_make_purchase_and_claim_payment(purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx)

        """2. User changes to 3-month plan"""
        tx_change_plan, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=change_plan_a, plan=base.ProPlan.ThreeMonth, user_ctx=user_ctx, ctx=ctx
        )
        test_notification(change_plan_b, ctx)

        """3. User changes to 1-month plan"""
        tx_change_plan, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=change_plan_back_a, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )
        test_notification(change_plan_back_b, ctx)

        """4. User renews"""
        # NOTE: Auto-renew kicks in
        tx, platform_refund_expiry_unix_tx_ms = test_make_purchase(
            purchase=renew, plan=base.ProPlan.OneMonth, ctx=ctx, check_payment_is_unredeemed=False
        )
        user_ctx.payments += 1

        assert_has_user(tx=tx, user_ctx=user_ctx, ctx=ctx)

        assert_payment_details(
            tx=tx,
            pro_status=server.UserProStatus.Active,
            payment_status=base.PaymentStatus.Redeemed,
            auto_renew=True,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
        )

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 3-month subscription
        2. Renews
        3. User cancels
        3. Expires
        """

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 12-month subscription
        2. Renews
        3. User cancels
        3. Expires
        """

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 3-month subscription
        2. User changes to 1-month subscription
        3. Renews
        """

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 12-month subscription
        2. User changes to 1-month subscription
        3. Renews
        """

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. Developer refunds subscription (removing entitlement)
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(  # 1. User purchases 1-month subscription
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760069459190',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'aciongiofnlcagplnndcfhnf.AO-J1OyRJ1NXBfFEzDi14GkTdi6d1iJ5XudWH7CY5pMziU2IExCSZHIkc0LXnsqvFr6qxdlSOjuwm2UpaJ4_ev47EPJS3ndl2v_uiHhnztkzLNhE1LUMArA',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T04:10:59.084Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3340-2850-4674-78454',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T04:15:58.601Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3340-2850-4674-78454',
                    }
                ],
            },
        )
        refund_a = TestScenario(  # 2. Developer refunds subscription (removing entitlement)
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760069492722',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 12,
                    'purchaseToken': 'aciongiofnlcagplnndcfhnf.AO-J1OyRJ1NXBfFEzDi14GkTdi6d1iJ5XudWH7CY5pMziU2IExCSZHIkc0LXnsqvFr6qxdlSOjuwm2UpaJ4_ev47EPJS3ndl2v_uiHhnztkzLNhE1LUMArA',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T04:10:59.084Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3340-2850-4674-78454',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-10T04:11:32.330Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T04:11:32.330Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3340-2850-4674-78454',
                    }
                ],
            },
        )
        refund_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760069494987',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'aciongiofnlcagplnndcfhnf.AO-J1OyRJ1NXBfFEzDi14GkTdi6d1iJ5XudWH7CY5pMziU2IExCSZHIkc0LXnsqvFr6qxdlSOjuwm2UpaJ4_ev47EPJS3ndl2v_uiHhnztkzLNhE1LUMArA',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-10T04:10:59.084Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3340-2850-4674-78454',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-10T04:11:32.330Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-10T04:11:32.330Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3340-2850-4674-78454',
                    }
                ],
            },
        )

        assert_clean_state(ctx)
        """1. User purchases 1-month subscription"""
        tx_subscribe, platform_refund_expiry_unix_tx_ms = test_make_purchase_and_claim_payment(
            purchase=purchase, plan=base.ProPlan.OneMonth, user_ctx=user_ctx, ctx=ctx
        )

        """2. Developer refunds subscription (removing entitlement)"""
        # Note that, refund_a is the event that causes the user in question to be revoked. Hence the
        # timestamp that we pass into the verify function uses event 'a'
        tx_refund_a = test_notification(refund_a, ctx)
        test_notification(refund_b, ctx)

        assert_payment_details(
            tx=tx_subscribe,
            pro_status=server.UserProStatus.Expired,
            payment_status=base.PaymentStatus.Revoked,
            auto_renew=False,
            grace_duration=pendulum.duration(),
            platform_refund_expiry_at=platform_refund_expiry_unix_tx_ms,
            user_ctx=user_ctx,
            ctx=ctx,
            unix_ts_ms=tx_refund_a.event_ms + 1000,  # +1s (wire nonce is integer seconds) to cross the expiry threshold
            revoke_unix_ts_ms=tx_refund_a.event_ms,
        )

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 1-month subscription
        2. Developer refunds subscription (removing entitlement)
        3. User purchases 1-month subscription
        4. User renews
        """

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 12-month subscription
        2. Developer refunds subscription (removing entitlement)
        3. User purchases 12-month subscription
        4. User renews
        """

    with TestingContext(pg_database, compressed_store_day=True) as ctx:
        """
        1. User purchases 1-month subscription, but does not redeem it.
        2. Developer refunds subscription (removing entitlement)
        """
        user_ctx = TestUserCtx()
        purchase = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760580587012',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'pnogbppobfdciojgdfgnmeal.AO-J1OxovjqCbzOzNldcpyo1pj4Equw02PLT12L4S1YoQjj6jzPOuYO7AoLrIBAIPS3tAUqHuST716b0a80dlpRriOeMpr6eOxk9aiXpokO2CYOZ7bSOPgs',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-16T02:09:46.878Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3396-6433-5991-21923',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-16T02:14:46.394Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3396-6433-5991-21923',
                    }
                ],
            },
        )
        renew = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760580615882',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 2,
                    'purchaseToken': 'pnogbppobfdciojgdfgnmeal.AO-J1OxovjqCbzOzNldcpyo1pj4Equw02PLT12L4S1YoQjj6jzPOuYO7AoLrIBAIPS3tAUqHuST716b0a80dlpRriOeMpr6eOxk9aiXpokO2CYOZ7bSOPgs',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-16T02:09:46.878Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_ACTIVE',
                'latestOrderId': 'GPA.3396-6433-5991-21923..0',
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-16T02:15:09.687Z',
                        'autoRenewingPlan': {
                            'autoRenewEnabled': True,
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3396-6433-5991-21923..0',
                    }
                ],
            },
        )
        refund_a = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760580644292',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 12,
                    'purchaseToken': 'pnogbppobfdciojgdfgnmeal.AO-J1OxovjqCbzOzNldcpyo1pj4Equw02PLT12L4S1YoQjj6jzPOuYO7AoLrIBAIPS3tAUqHuST716b0a80dlpRriOeMpr6eOxk9aiXpokO2CYOZ7bSOPgs',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-16T02:09:46.878Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3396-6433-5991-21923..0',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-16T02:10:44.089Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-16T02:10:44.089Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3396-6433-5991-21923..0',
                    }
                ],
            },
        )
        refund_b = TestScenario(
            rtdn_event={
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1760580647465',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 13,
                    'purchaseToken': 'pnogbppobfdciojgdfgnmeal.AO-J1OxovjqCbzOzNldcpyo1pj4Equw02PLT12L4S1YoQjj6jzPOuYO7AoLrIBAIPS3tAUqHuST716b0a80dlpRriOeMpr6eOxk9aiXpokO2CYOZ7bSOPgs',
                    'subscriptionId': 'session_pro',
                },
            },
            current_state={
                'kind': 'androidpublisher#subscriptionPurchaseV2',
                'startTime': '2025-10-16T02:09:46.878Z',
                'regionCode': 'AU',
                'subscriptionState': 'SUBSCRIPTION_STATE_EXPIRED',
                'latestOrderId': 'GPA.3396-6433-5991-21923..0',
                'canceledStateContext': {'userInitiatedCancellation': {'cancelTime': '2025-10-16T02:10:44.089Z'}},
                'testPurchase': {},
                'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
                'externalAccountIdentifiers': {
                    'obfuscatedExternalAccountId': f'{user_ctx.google_obfuscated_account_id.hex()}'
                },
                'lineItems': [
                    {
                        'productId': 'session_pro',
                        'expiryTime': '2025-10-16T02:10:44.089Z',
                        'autoRenewingPlan': {
                            'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000}
                        },
                        'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': ['one-month']},
                        'latestSuccessfulOrderId': 'GPA.3396-6433-5991-21923..0',
                    }
                ],
            },
        )
        assert_clean_state(ctx)
        """1. User purchases 1-month subscription, but does not redeem it."""
        tx = test_make_purchase(purchase=purchase, plan=base.ProPlan.OneMonth, ctx=ctx)[0]
        tx = test_make_purchase(purchase=renew, plan=base.ProPlan.OneMonth, ctx=ctx)[0]
        with ctx.connection() as conn:
            unredeemed_payments = backend.get_unredeemed_payments_list(conn)
        for payment in unredeemed_payments:
            assert payment.redeemed_at is None

        """2. Developer refunds subscription (removing entitlement)"""
        test_notification(refund_a, ctx)
        with ctx.connection() as conn:
            unredeemed_payments = backend.get_unredeemed_payments_list(conn)
        for payment in unredeemed_payments:
            assert derived_status(payment) == base.PaymentStatus.Revoked
        test_notification(refund_b, ctx)
        for payment in unredeemed_payments:
            assert derived_status(payment) == base.PaymentStatus.Revoked


# ----------------------------------------------------------------------------------------------------
# Characterisation of the convergence defects (see the simplify-google-processing findings).
#
# These pin what the type-dispatching handler does TODAY, including where that is wrong. Each one names
# the defect it captures; the reconcile rewrite is expected to invert them deliberately, not by accident.
# ----------------------------------------------------------------------------------------------------

_UPGRADE_ACCOUNT_SEED = bytes([0x42] * 32)

# Token -> parsed resource, so the fetch stub can answer per token the way the real API does. Reset by
# TestingContext's fixture scope in practice; harmless across tests since tokens are unique per fixture.
_SNAPSHOTS: dict = {}


def _google_snapshot(
    *,
    state: str,
    expiry: str,
    order_id: str,
    obfuscated_account_id: bytes,
    base_plan: str = 'session-pro-1-month',
    auto_renew: bool = True,
    linked_purchase_token: str | None = None,
    start_time: str = '2026-01-01T00:00:00.000Z',
) -> base.JSONObject:
    """One `purchases.subscriptionsv2.get` response body, as the handler would fetch it."""
    result: base.JSONObject = {
        'kind': 'androidpublisher#subscriptionPurchaseV2',
        'startTime': start_time,
        'regionCode': 'AU',
        'subscriptionState': state,
        'latestOrderId': order_id,
        'testPurchase': {},
        'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
        'externalAccountIdentifiers': {'obfuscatedExternalAccountId': obfuscated_account_id.hex()},
        'lineItems': [
            {
                'productId': 'session_pro',
                'expiryTime': expiry,
                'autoRenewingPlan': {
                    'autoRenewEnabled': auto_renew,
                    'recurringPrice': {'currencyCode': 'AUD', 'units': '16', 'nanos': 990000000},
                },
                'offerDetails': {'basePlanId': base_plan, 'offerTags': ['tag']},
                'latestSuccessfulOrderId': order_id,
            }
        ],
    }
    if linked_purchase_token is not None:
        result['linkedPurchaseToken'] = linked_purchase_token
    return result


def _drive_google_rtdn(
    monkeypatch, ctx, *, notification_type: int, purchase_token: str, event_ms: int, snapshot: base.JSONObject
) -> tuple[bool, base.ErrorSink]:
    """Push one subscription RTDN through handle_parsed_notification against `snapshot`.

    Unlike the driver inside test_google_platform_handle_notification this does NOT assert success: these
    tests are about the paths where handling silently does nothing, or fails and wedges.
    """
    monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')
    err_parse = base.ErrorSink()
    details = google_play.api.parse_get_subscription_v2_response(snapshot, err_parse)
    assert not err_parse.has() and details is not None

    # Keyed by token, because the drain fetches per token and reconciles everything that is due -- including
    # a linked token some earlier notification marked dirty. A stub that ignored the token would answer for
    # one subscription with another's resource, which the real API cannot do and which quietly corrupts any
    # fixture with more than one token in play.
    _SNAPSHOTS[purchase_token] = details

    def _fetch(package_name, token, err):
        known = _SNAPSHOTS.get(token)
        if known is None:
            err.msg_list.append(f'test fixture has no snapshot for {token}')
        return known

    monkeypatch.setattr('providers.google_play.api.fetch_subscription_v2_details', _fetch)
    monkeypatch.setattr('providers.google_play.api.subscription_v1_acknowledge', lambda *a, **k: None)

    rtdn: base.JSONObject = {
        'version': '1.0',
        'packageName': 'network.loki.messenger',
        'eventTimeMillis': str(event_ms),
        'subscriptionNotification': {
            'version': '1.0',
            'notificationType': notification_type,
            'purchaseToken': purchase_token,
            'subscriptionId': 'session_pro',
        },
    }
    err = base.ErrorSink()
    parse = google_play.parse_notification(rtdn, err)
    with ctx.connection() as conn:
        with db.transaction(conn) as tx:
            handled = google_play.handle_parsed_notification(tx, parse, err)

    # The notification now only records that the token owes a look, so drive the drain too: these tests are
    # about what an arriving notification LEAVES BEHIND, and that is still the question worth asking. The
    # fetch is already stubbed to the same snapshot, so the drain sees exactly what the old inline handler
    # would have.
    if handled:
        # The drain owns its own sinks per token, so lift whatever it recorded onto ours: these tests ask
        # "what did this notification end up doing", and after the switchover most of that happens here.
        google_play.drain_due_reconciles(at=base.datetime_from_unix_ms(event_ms))
        with ctx.connection() as conn:
            for row in db.query(conn, 'SELECT last_error FROM google_reconcile_queue WHERE last_error IS NOT NULL'):
                err.msg_list.append(row[0])
    return handled, err


def _payment_rows(ctx) -> list[tuple]:
    with ctx.connection() as conn:
        return db.query(
            conn,
            '''
            SELECT gd.order_id, p.expiry_at, p.revoked_at
            FROM   payments p JOIN google_play_payment_details gd ON gd.payment_id = p.id
            ORDER BY p.id
            ''',
        ).fetchall()


def test_google_purchase_against_a_stale_state_is_registered_anyway(monkeypatch, pg_database):
    # REGRESSION for finding 3.1, the defect this whole branch started from. The PURCHASED branch gates on the state of a FRESHLY FETCHED
    # snapshot (notifications.py), while the notification type comes from the message. Process a PURCHASED
    # once the store already reads CANCELED -- the user bought, then turned auto-renew off, and our
    # subscriber was down in between -- and the guard fails, so the branch is skipped ENTIRELY.
    #
    # The damning part is the two asserts on `handled`/`err`: nothing is recorded, yet handling reports
    # success, so the pull loop acks the message and Google never redelivers it. A purchase token is the one
    # fact in this system that cannot be re-fetched (no endpoint enumerates subscribers), so this is an
    # unrecoverable paid-but-no-Pro.
    #
    # The follow-up CANCELED then wedges: its own guard matches, but the UPDATE it performs finds no row,
    # which is reported as failure -> tx.cancel -> never acked -> retried with backoff forever, waiting on a
    # row that can never appear.
    with TestingContext(pg_database) as ctx:
        account_id = bytes(nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED).verify_key)
        token = 'tok-purchased-then-cancelled'
        snapshot = _google_snapshot(
            state='SUBSCRIPTION_STATE_CANCELED',
            expiry='2026-02-01T00:00:00.000Z',
            order_id='GPA.1111-2222-3333-44444',
            obfuscated_account_id=account_id,
            auto_renew=False,
        )

        handled, err = _drive_google_rtdn(
            monkeypatch, ctx, notification_type=4, purchase_token=token, event_ms=1767225600000, snapshot=snapshot
        )
        assert handled is True and not err.has()
        rows = _payment_rows(ctx)
        assert len(rows) == 1, 'the purchase is recorded -- nothing asks whether the state still reads ACTIVE'
        assert rows[0][0] == 'GPA.1111-2222-3333-44444'

        # And the cancellation that used to wedge forever, waiting on a row that could never appear, now
        # finds one and simply converges it.
        handled, err = _drive_google_rtdn(
            monkeypatch, ctx, notification_type=3, purchase_token=token, event_ms=1767312000000, snapshot=snapshot
        )
        assert handled is True and not err.has()
        assert len(_payment_rows(ctx)) == 1, 'still one cycle'


def test_google_upgrade_leaves_consumed_cycles_alone(monkeypatch, pg_database):
    # REGRESSION for findings 3.3 and 3.6. A monthly subscriber who switches plans gets a NEW purchase
    # token, and the new subscription's snapshot names the old one in linkedPurchaseToken. The handler
    # responds by calling add_google_revocation on the old token -- whose SELECT carries no ORDER BY and no
    # LIMIT, so it revokes EVERY cycle ever recorded under that token, not the live one.
    #
    # Consumed cycles that ended months earlier are therefore stamped revoked_at = the upgrade instant, and
    # get_payment_details reports them to the client as `revoked`. Nothing was refunded. That is revoked_at
    # coming to mean "this payment never existed", which CLAUDE.md's invariant forbids.
    #
    # Its comment claims to "Select the newest google transaction"; it does not.
    with TestingContext(pg_database) as ctx:
        account_id = bytes(nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED).verify_key)
        old_token = 'tok-monthly'
        cycles = [
            ('GPA.9000-0000-0000-00001', '2026-02-01T00:00:00.000Z', 1767225600000),
            ('GPA.9000-0000-0000-00001..0', '2026-03-01T00:00:00.000Z', 1769904000000),
            ('GPA.9000-0000-0000-00001..1', '2026-04-01T00:00:00.000Z', 1772323200000),
        ]
        for index, (order_id, expiry, event_ms) in enumerate(cycles):
            handled, err = _drive_google_rtdn(
                monkeypatch,
                ctx,
                notification_type=4 if index == 0 else 2,  # PURCHASED, then RENEWED
                purchase_token=old_token,
                event_ms=event_ms,
                snapshot=_google_snapshot(
                    state='SUBSCRIPTION_STATE_ACTIVE',
                    expiry=expiry,
                    order_id=order_id,
                    obfuscated_account_id=account_id,
                ),
            )
            assert handled and not err.has()
        assert len(_payment_rows(ctx)) == 3

        # The switch: one PURCHASED, on a new token, naming the old one.
        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=4,
            purchase_token='tok-annual',
            event_ms=1773532800000,  # 2026-03-15, mid-way through the third month
            snapshot=_google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2027-03-15T00:00:00.000Z',
                order_id='GPA.8000-0000-0000-00002',
                obfuscated_account_id=account_id,
                base_plan='session-pro-12-months',
                linked_purchase_token=old_token,
            ),
        )
        assert handled and not err.has()

        rows = _payment_rows(ctx)
        assert len(rows) == 4
        revoked = {order_id: revoked_at for order_id, _, revoked_at in rows}
        # Nothing is revoked. The old token is marked dirty instead, so its own resource decides what became
        # of it -- and consumed cycles, which nobody refunded, keep saying so.
        assert all(value is None for value in revoked.values()), revoked

        with ctx.connection() as conn:
            queued = db.query(conn, 'SELECT payment_token FROM google_reconcile_queue').fetchall()
        assert 'tok-monthly' in [row[0] for row in queued], 'superseded, so it owes a look'


def test_google_upgrade_does_not_revoke_an_account_that_never_lapsed(monkeypatch, pg_database):
    # REGRESSION for findings 3.4 and 3.5. Same upgrade as above, but with the subscription CLAIMED, so
    # the payments carry a user_id and the revocation path actually reaches its broadcast decision.
    #
    # That decision runs BEFORE the replacement payment is inserted (the linked-token revoke is the first
    # statement in the PURCHASED branch, the insert comes after), so it judges an account that appears to
    # have nothing left -- and rolls the generation, invalidating every outstanding proof, and publishes an
    # entry into the revocation list that every client downloads for the 31-day retention. The account's
    # coverage never lapsed for an instant: it upgraded.
    #
    # Which of the two branches is taken is decided by the LAST row of an unordered SELECT (finding 3.4), so
    # the value pinned below is the one this fixture produces; it is not a guarantee of the code's shape.
    with TestingContext(pg_database) as ctx:
        master_key = nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED)
        rotating_key = nacl.signing.SigningKey.generate()
        account_id = bytes(master_key.verify_key)
        old_token = 'tok-monthly'

        for index, (order_id, expiry, event_ms) in enumerate(
            [
                ('GPA.9000-0000-0000-00001', '2026-02-01T00:00:00.000Z', 1767225600000),
                ('GPA.9000-0000-0000-00001..0', '2026-03-01T00:00:00.000Z', 1769904000000),
                ('GPA.9000-0000-0000-00001..1', '2026-04-01T00:00:00.000Z', 1772323200000),
            ]
        ):
            handled, err = _drive_google_rtdn(
                monkeypatch,
                ctx,
                notification_type=4 if index == 0 else 2,
                purchase_token=old_token,
                event_ms=event_ms,
                snapshot=_google_snapshot(
                    state='SUBSCRIPTION_STATE_ACTIVE',
                    expiry=expiry,
                    order_id=order_id,
                    obfuscated_account_id=account_id,
                ),
            )
            assert handled and not err.has()

        # Claim the subscription: the account now has a generation, and outstanding proofs to protect.
        claimed_at = base.datetime_from_unix_ms(1773187200000)  # 2026-03-11, inside the third cycle
        with ctx.connection() as conn:
            _redeem_and_prove(conn, ctx.backend_key, master_key, rotating_key, claimed_at)
            generation_before = backend.get_user(conn, master_key.verify_key).current_generation_id
            assert not backend.get_revocations_list(conn)

        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=4,
            purchase_token='tok-annual',
            event_ms=1773532800000,  # 2026-03-15
            snapshot=_google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2027-03-15T00:00:00.000Z',
                order_id='GPA.8000-0000-0000-00002',
                obfuscated_account_id=account_id,
                base_plan='session-pro-12-months',
                linked_purchase_token=old_token,
            ),
        )
        assert handled and not err.has()

        upgraded_at = base.datetime_from_unix_ms(1773532800000)
        with ctx.connection() as conn:
            user = backend.get_user(conn, master_key.verify_key)
            assert not backend.get_revocations_list(conn), 'upgrading is not a reason to revoke anybody'
            assert user.current_generation_id == generation_before, 'and the generation stands'

            # Nor does the account read as lapsed. The replacement is registered by the same drain pass, so
            # the recompute sees it rather than only the coverage it was replacing.
            assert user.expiry_at is not None and user.expiry_at > upgraded_at


def test_google_upgrade_revocation_does_not_depend_on_physical_row_order(monkeypatch, pg_database):
    # REGRESSION for finding 3.4, and the companion to the test above: the SAME upgrade, differing only by an
    # entitlement-neutral write to one already-expired cycle, must now reach the SAME outcome.
    #
    # It used to differ. The revoke SELECT has no ORDER BY, so rows arrive in heap order -- which
    # approximates least-recently-updated, since an UPDATE writes a new tuple version that migrates -- and
    # revoke_payments_by_id_internal kept only the LAST row's expiry per account to drive its day-boundary
    # early-out. Whichever cycle had been written to least recently therefore decided whether an upgrading
    # subscriber got revoked, and neither answer was reached for a good reason.
    #
    # The decision no longer takes a payment row as input at all: every write lands, the account is
    # recomputed, and the question asked is whether what survives still covers the proofs already signed.
    # The write below (`grace_period = grace_period`) is the shape of the ones
    # set_purchase_grace_period_duration and set_payment_auto_renew perform routinely.
    with TestingContext(pg_database) as ctx:
        master_key = nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED)
        rotating_key = nacl.signing.SigningKey.generate()
        account_id = bytes(master_key.verify_key)
        oldest_order_id = 'GPA.9000-0000-0000-00001'

        for index, (order_id, expiry, event_ms) in enumerate(
            [
                (oldest_order_id, '2026-02-01T00:00:00.000Z', 1767225600000),
                ('GPA.9000-0000-0000-00001..0', '2026-03-01T00:00:00.000Z', 1769904000000),
                ('GPA.9000-0000-0000-00001..1', '2026-04-01T00:00:00.000Z', 1772323200000),
            ]
        ):
            handled, err = _drive_google_rtdn(
                monkeypatch,
                ctx,
                notification_type=4 if index == 0 else 2,
                purchase_token='tok-monthly',
                event_ms=event_ms,
                snapshot=_google_snapshot(
                    state='SUBSCRIPTION_STATE_ACTIVE',
                    expiry=expiry,
                    order_id=order_id,
                    obfuscated_account_id=account_id,
                ),
            )
            assert handled and not err.has()

        with ctx.connection() as conn:
            _redeem_and_prove(
                conn, ctx.backend_key, master_key, rotating_key, base.datetime_from_unix_ms(1773187200000)
            )
            db.query(
                conn,
                '''UPDATE payments SET grace_period = grace_period
                   WHERE id IN (SELECT payment_id FROM google_play_payment_details WHERE order_id = %(order_id)s)''',
                order_id=oldest_order_id,
            )
            conn.commit()
            # Unordered on purpose -- this mirrors the revoke's own SELECT, so it observes heap order.
            # Pinned so that a storage-layer change surfaces here, naming the mechanism, rather than as an
            # unexplained flip in the assertion below.
            order = [
                row[0]
                for row in db.query(
                    conn,
                    f'SELECT gd.order_id FROM {backend.PAYMENTS_FROM} WHERE gd.payment_token = %(token)s',
                    token='tok-monthly',
                ).fetchall()
            ]
            assert order[-1] == oldest_order_id, 'the touched row now sorts last'

        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=4,
            purchase_token='tok-annual',
            event_ms=1773532800000,
            snapshot=_google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2027-03-15T00:00:00.000Z',
                order_id='GPA.8000-0000-0000-00002',
                obfuscated_account_id=account_id,
                base_plan='session-pro-12-months',
                linked_purchase_token='tok-monthly',
            ),
        )
        assert handled and not err.has()

        with ctx.connection() as conn:
            # Identical to the companion test, which runs the same upgrade without the extra write. Both now
            # revoke nothing: the decision reads the account rather than a payment row, so heap order has
            # nothing to say about it, and the reconcile no longer judges an upgrade at all.
            assert not backend.get_revocations_list(conn), 'the same outcome, whatever the row order'
            user = backend.get_user(conn, master_key.verify_key)
            assert user.expiry_at is not None and user.expiry_at > base.datetime_from_unix_ms(1773532800000)


def test_google_expiry_is_revised_when_the_store_changes_the_term(monkeypatch, pg_database):
    # REGRESSION for finding 3.7. A store payment's expiry_at is written once, at insert, and no code
    # path ever revises it: every other UPDATE on payments touches revoked_at, redeemed_at, user_id,
    # auto_renewing or grace_period, and the only write to expiry_at is the credit drain's latch, which never
    # applies to a Google payment.
    #
    # So re-processing the same cycle against a snapshot that now reports a LATER expiry -- what a deferred
    # recurrence change or a recurrence-time extension produces, since Google moves the expiry without
    # issuing a new order -- leaves the stored value untouched. add_unredeemed_payment dedups on
    # (token, order_id) and takes the row as it already stands.
    #
    # This is why convergence needs expiry_at to become mutable: today the only way a new expiry can reach
    # the DB is a new order id, i.e. a new row.
    with TestingContext(pg_database) as ctx:
        account_id = bytes(nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED).verify_key)
        token, order_id = 'tok-extended', 'GPA.7000-0000-0000-00003'

        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=4,
            purchase_token=token,
            event_ms=1767225600000,
            snapshot=_google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2026-02-01T00:00:00.000Z',
                order_id=order_id,
                obfuscated_account_id=account_id,
            ),
        )
        assert handled and not err.has()
        assert _payment_rows(ctx)[0][1] == base.datetime_from_unix_ms(1769904000000)  # 2026-02-01

        # Google now reports the cycle running a month longer, under the SAME order id.
        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=1,  # RECOVERED, which shares the RENEWED branch
            purchase_token=token,
            event_ms=1769000000000,
            snapshot=_google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2026-03-01T00:00:00.000Z',
                order_id=order_id,
                obfuscated_account_id=account_id,
            ),
        )
        assert handled and not err.has()

        rows = _payment_rows(ctx)
        assert len(rows) == 1, 'same (token, order_id): one cycle, converged rather than duplicated'
        assert rows[0][1] == base.datetime_from_unix_ms(1772323200000), 'and the new term is what stands'


def test_google_deferred_notification_is_harmless(monkeypatch, pg_database):
    # REGRESSION for finding 3.8. DEFERRED used to share an explicitly-unsupported arm with PAUSED and
    # PAUSE_SCHEDULE_CHANGED: it appended `unsupported!` and cancelled the transaction, so the message was
    # never acked and retried with backoff indefinitely, flagging the token with a `user_error` that surfaced
    # in that account's `error_report`. Both are gone -- the arm with the dispatch, the flag with the field.
    #
    # The wedge was gratuitous, because the snapshot already carries everything needed: the current expiry,
    # and the incoming product under deferredItemReplacement. Converging on the snapshot has nothing to do
    # here -- the deferral changes nothing yet -- and entitlement self-corrects at the next RENEWED
    # regardless. The wedge existed purely because dispatch was on notification type.
    with TestingContext(pg_database) as ctx:
        account_id = bytes(nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED).verify_key)
        token, order_id = 'tok-deferred', 'GPA.6000-0000-0000-00004'

        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=4,
            purchase_token=token,
            event_ms=1767225600000,
            snapshot=_google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2026-02-01T00:00:00.000Z',
                order_id=order_id,
                obfuscated_account_id=account_id,
            ),
        )
        assert handled and not err.has()

        # The subscription is unchanged -- a deferral takes effect at the next renewal, so the snapshot still
        # reads ACTIVE with the same expiry. There is nothing here that needed handling.
        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=9,  # DEFERRED
            purchase_token=token,
            event_ms=1768000000000,
            snapshot=_google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2026-02-01T00:00:00.000Z',
                order_id=order_id,
                obfuscated_account_id=account_id,
            ),
        )
        assert handled is True, 'acked and done: a deferral changes nothing yet, and the resource says so'
        assert not err.has(), err.msg_list
        assert len(_payment_rows(ctx)) == 1, 'the cycle is untouched, because nothing about it moved'


def test_revoking_a_lapsed_payment_does_not_extend_the_account(monkeypatch, pg_database):
    # REGRESSION for finding 3.7a. The fold clamps a revoked row to `min(expiry_at, revoked_at)`; before that
    # it assigned `revoked_at` outright, and that value becomes users.expiry_at -- the wire's expiry_ts, the
    # Active/Expired decision in get_pro_status, and the ceiling a signed proof is clamped against.
    #
    # So revoking a payment that had ALREADY LAPSED used to move the account's expiry FORWARD, reporting
    # coverage across a gap it never had and letting it mint fresh proofs from the refund instant. Nothing
    # was consumable during the gap itself, since the extension only existed once the refund was processed,
    # so the grant was the prospective one -- bounded by the over-provision window, and unannounced, because
    # the day-boundary early-out sees the payment's own expiry sitting well before the revoke instant,
    # concludes it was expiring anyway, and skips the broadcast.
    #
    # Driven through the Google fixture because it is cheap to build. The live path was APPLE's: a REFUND
    # carries Apple's revocationDate straight into revoke_at (providers/app_store.py), and Apple can process
    # a refund long after the subscription lapsed.
    with TestingContext(pg_database) as ctx:
        master_key = nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED)
        rotating_key = nacl.signing.SigningKey.generate()
        account_id = bytes(master_key.verify_key)
        lapses_at = base.datetime_from_unix_ms(1769904000000)  # 2026-02-01

        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=4,
            purchase_token='tok-lapsed',
            event_ms=1767225600000,
            snapshot=_google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2026-02-01T00:00:00.000Z',
                order_id='GPA.5000-0000-0000-00005',
                obfuscated_account_id=account_id,
            ),
        )
        assert handled and not err.has()
        with ctx.connection() as conn:
            _redeem_and_prove(
                conn, ctx.backend_key, master_key, rotating_key, base.datetime_from_unix_ms(1767830400000)
            )
            # Auto-renewing, so the published expiry carries the grace period on top.
            assert backend.get_user(conn, master_key.verify_key).expiry_at == lapses_at

        # Four months after it lapsed, the payment is refunded.
        refunded_at = base.datetime_from_unix_ms(1780272000000)  # 2026-06-01
        err = base.ErrorSink()
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.add_google_revocation(tx, google_payment_token='tok-lapsed', revoke_at=refunded_at, err=err)
        assert not err.has()

        with ctx.connection() as conn:
            user = backend.get_user(conn, master_key.verify_key)
            # The account keeps the expiry it actually paid for -- NOT the refund instant four months later.
            # It loses the grace period, because revoking clears auto_renewing and only a renewing payment
            # carries grace, which is a reduction and therefore fine.
            assert user.expiry_at == lapses_at
            assert user.expiry_at < refunded_at, 'a refund must never move the account expiry forward'
            assert not backend.get_revocations_list(conn), 'nothing to broadcast: it was already expired'
            # The payment row keeps both facts, each meaning its own thing.
            row = db.query_one(conn, 'SELECT expiry_at, revoked_at FROM payments ORDER BY id DESC LIMIT 1')
            assert row is not None and row[0] == lapses_at and row[1] == refunded_at


def test_proof_expiry_offset_holds_when_the_account_expiry_shrinks(monkeypatch, pg_database):
    # A reduction in entitlement must only ever reduce -- the same rule as the clamp above, applied to the
    # obfuscation grid. The served expiry is the true one rounded UP onto `EPOCH + offset + k*grid`, so it
    # lands in [true, true + grid). Re-drawing the offset on a SHRINK would place the new grid point without
    # reference to the old one, so any shrink smaller than one grid period could serve a LATER expiry than
    # before: a revocation handing out coverage.
    #
    # Holding the offset keeps the grid fixed, and rounding up is monotonic on a fixed grid, so a smaller
    # true expiry cannot produce a larger served one. Extensions still re-draw
    # (test_proof_expiry_offset_redraws_only_when_true_expiry_moves), which is what stops an observer
    # collecting repeated independent samples against one unchanged expiry.
    with TestingContext(pg_database) as ctx:
        master_key = nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED)
        rotating_key = nacl.signing.SigningKey.generate()
        account_id = bytes(master_key.verify_key)
        claimed_at = base.datetime_from_unix_ms(1767830400000)  # 2026-01-08

        # Two subscriptions on one account -- the second device / second Google account case. The account's
        # expiry is the later of the two, and refunding THAT one is what makes the expiry shrink while
        # leaving live coverage behind, which is what lets a proof still be minted afterwards.
        # Both run far enough out that the survivor still covers every outstanding proof, so the revocation
        # below does NOT roll the generation -- which is the case this test is about. The rolling case is
        # test_proof_expiry_offset_redraws_when_a_revocation_rolls_the_generation.
        for token, order_id, expiry in (
            ('tok-shrink-long', 'GPA.4000-0000-0000-00006', '2027-06-01T00:00:00.000Z'),
            ('tok-shrink-short', 'GPA.3000-0000-0000-00007', '2027-01-01T00:00:00.000Z'),
        ):
            handled, err = _drive_google_rtdn(
                monkeypatch,
                ctx,
                notification_type=4,
                purchase_token=token,
                event_ms=1767225600000,
                snapshot=_google_snapshot(
                    state='SUBSCRIPTION_STATE_ACTIVE',
                    expiry=expiry,
                    order_id=order_id,
                    obfuscated_account_id=account_id,
                ),
            )
            assert handled and not err.has()

        with ctx.connection() as conn:
            _redeem_and_prove(conn, ctx.backend_key, master_key, rotating_key, claimed_at)
            before = backend.get_user(conn, master_key.verify_key)
            served_before = _prove_at(conn, ctx.backend_key, master_key, rotating_key, claimed_at).expiry_at

            # Refund the LONGER one, well before it would have expired: the account's expiry shrinks back to
            # the shorter subscription, which is still live.
            revoked_at = base.datetime_from_unix_ms(1769904000000)  # 2026-02-01, inside the paid term
            sink = base.ErrorSink()
            with db.transaction(conn) as tx:
                backend.add_google_revocation(
                    tx, google_payment_token='tok-shrink-long', revoke_at=revoked_at, err=sink
                )
            assert not sink.has()

            after = backend.get_user(conn, master_key.verify_key)
            assert not backend.get_revocations_list(conn), 'precondition: enough survived, so no roll'
            assert after.expiry_at is not None and before.expiry_at is not None
            assert after.expiry_at < before.expiry_at, 'precondition: the account expiry shrank'
            assert after.proof_expiry_offset == before.proof_expiry_offset, 'the offset is held across a shrink'

            # Both expiries here sit far beyond the rolling clamp, so both proofs are slide-capped and this
            # holds by equality. It is a sanity check, not the regression pin -- the assert above is. The
            # arm where the overshoot actually manifests is the PINNED one, covered by the next test.
            served_after = _prove_at(conn, ctx.backend_key, master_key, rotating_key, claimed_at).expiry_at
            assert served_after <= served_before


def test_proof_expiry_offset_redraws_when_a_revocation_rolls_the_generation(monkeypatch, pg_database):
    # The exception to the extension-only rule, and it is load-bearing. A broadcast revocation is a SHRINK,
    # so extension-only alone would carry the offset across the very moment the revocation_tag rolls -- the
    # one point at which the design unlinks an account's proofs. The offset is ~16 bits and readable off
    # every proof (expiry_ts modulo the grid), so an observer could stitch the two generations together.
    #
    # Minting a generation therefore forces a re-draw regardless of what the expiry did. Nothing is given up:
    # monotonicity across a roll would be protecting proofs that were revoked in the same breath.
    with TestingContext(pg_database) as ctx:
        master_key = nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED)
        rotating_key = nacl.signing.SigningKey.generate()
        account_id = bytes(master_key.verify_key)
        claimed_at = base.datetime_from_unix_ms(1767830400000)  # 2026-01-08

        # A survivor is required: _ensure_active_generation returns early when no usable payment is left, so
        # revoking an account's ONLY payment mints nothing and there is no roll to link across. The survivor
        # is deliberately short enough that it does not cover the outstanding proofs, which is what makes the
        # revocation worth broadcasting.
        for token, order_id, expiry in (
            ('tok-rolled', 'GPA.2000-0000-0000-00008', '2026-06-01T00:00:00.000Z'),
            ('tok-rolled-survivor', 'GPA.1000-0000-0000-00009', '2026-03-01T00:00:00.000Z'),
        ):
            handled, err = _drive_google_rtdn(
                monkeypatch,
                ctx,
                notification_type=4,
                purchase_token=token,
                event_ms=1767225600000,
                snapshot=_google_snapshot(
                    state='SUBSCRIPTION_STATE_ACTIVE',
                    expiry=expiry,
                    order_id=order_id,
                    obfuscated_account_id=account_id,
                ),
            )
            assert handled and not err.has()

        with ctx.connection() as conn:
            _redeem_and_prove(conn, ctx.backend_key, master_key, rotating_key, claimed_at)
            before = backend.get_user(conn, master_key.verify_key)

            # Refund mid-term: enough entitlement is destroyed that the generation is rolled and an entry
            # published, which is exactly the unlinking moment.
            sink = base.ErrorSink()
            with db.transaction(conn) as tx:
                backend.add_google_revocation(
                    tx,
                    google_payment_token='tok-rolled',
                    revoke_at=base.datetime_from_unix_ms(1769904000000),  # 2026-02-01
                    err=sink,
                )
            assert not sink.has()

            after = backend.get_user(conn, master_key.verify_key)
            assert len(backend.get_revocations_list(conn)) == 1, 'precondition: the tag rolled'
            assert after.expiry_at is not None and before.expiry_at is not None
            assert after.expiry_at < before.expiry_at, 'precondition: and it was a shrink'
            assert after.proof_expiry_offset != before.proof_expiry_offset, 'so the offset must NOT carry over'


def test_shrinking_the_expiry_never_serves_a_later_proof_in_the_pinned_arm(monkeypatch, pg_database):
    # The arm the defect actually lived in. When the true expiry is inside the rolling clamp the served
    # value TRACKS it, so a shrink must visibly pull the served expiry earlier (or leave it, if both land in
    # one grid cell) -- never push it later. In the sliding arm the clamp hides the whole question.
    #
    # The window is narrow and is computed rather than hard-coded, so it follows the shape constants: the
    # survivor has to outlast every outstanding proof (or the revocation broadcasts and mints a fresh
    # generation, which re-draws by design) while still falling inside the clamp at request time. That needs
    # the request to sit at least a grid period plus the renewal lead after the revocation.
    shape = base.PROOF_EXPIRY_SHAPE
    with TestingContext(pg_database) as ctx:
        master_key = nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED)
        rotating_key = nacl.signing.SigningKey.generate()
        account_id = bytes(master_key.verify_key)

        purchased_at = base.datetime_from_unix_ms(1767225600000)  # 2026-01-01
        revoked_at = purchased_at + 3 * base.DAY
        request_at = revoked_at + 2 * base.DAY
        survivor_expiry = revoked_at + base.DEFAULT_TIMESTAMP_TOLERANCE + shape.max_proof_lifetime + 1 * base.HOUR
        doomed_expiry = survivor_expiry + 5 * base.DAY
        assert survivor_expiry <= request_at + shape.clamp, 'fixture: the survivor must be in the pinned arm'

        def iso(at: pendulum.DateTime) -> str:
            return at.in_timezone('UTC').strftime('%Y-%m-%dT%H:%M:%S.000Z')

        for token, order_id, expiry in (
            ('tok-pinned-doomed', 'GPA.5500-0000-0000-00010', doomed_expiry),
            ('tok-pinned-survivor', 'GPA.5600-0000-0000-00011', survivor_expiry),
        ):
            handled, err = _drive_google_rtdn(
                monkeypatch,
                ctx,
                notification_type=4,
                purchase_token=token,
                event_ms=base.unix_ms_from_datetime(purchased_at),
                snapshot=_google_snapshot(
                    state='SUBSCRIPTION_STATE_ACTIVE',
                    expiry=iso(expiry),
                    order_id=order_id,
                    obfuscated_account_id=account_id,
                ),
            )
            assert handled and not err.has()

        with ctx.connection() as conn:
            _redeem_and_prove(conn, ctx.backend_key, master_key, rotating_key, purchased_at + 1 * base.DAY)
            before = backend.get_user(conn, master_key.verify_key)
            served_before = _prove_at(conn, ctx.backend_key, master_key, rotating_key, request_at).expiry_at

            sink = base.ErrorSink()
            with db.transaction(conn) as tx:
                backend.add_google_revocation(
                    tx, google_payment_token='tok-pinned-doomed', revoke_at=revoked_at, err=sink
                )
            assert not sink.has()

            after = backend.get_user(conn, master_key.verify_key)
            assert not backend.get_revocations_list(conn), 'fixture: enough survived, so the generation held'
            assert after.proof_expiry_offset == before.proof_expiry_offset
            assert after.expiry_at is not None and before.expiry_at is not None
            assert after.expiry_at < before.expiry_at, 'fixture: the account expiry shrank'

            served_after = _prove_at(conn, ctx.backend_key, master_key, rotating_key, request_at).expiry_at
            # The crossover: slide-capped before the refund, pinned to the true expiry after it. So unlike
            # the previous test this is a real comparison, and the post-shrink side is the one that would
            # have overshot on a fresh draw.
            assert before.expiry_at > request_at + shape.clamp, 'fixture: sliding before'
            assert after.expiry_at <= request_at + shape.clamp, 'fixture: pinned after'
            assert served_after <= served_before, 'a shrink must never serve a later proof'


def test_a_late_refund_does_not_shove_a_credits_anchor_forward(monkeypatch, pg_database):
    # The clamp's reach into the credit ledger, which is the one interaction it changes beyond the account
    # expiry itself. Credits extend the LATER of the subscription coverage and the drain checkpoint, so
    # whatever a revoked payment contributes to that max is also the base every remaining credit day stacks
    # on. While a revoked row reported the revoke instant, refunding a long-lapsed subscription dragged that
    # base forward and handed the voucher-holder the whole dead interval on top of their credit.
    #
    # With the clamp the base is the coverage actually paid for, so the refund moves nothing: the credit is
    # worth the same before and after, which is the point of a credit that stacks rather than competes.
    with TestingContext(pg_database) as ctx:
        master_key = nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED)
        rotating_key = nacl.signing.SigningKey.generate()
        account_id = bytes(master_key.verify_key)
        lapses_at = base.datetime_from_unix_ms(1769904000000)  # 2026-02-01
        claimed_at = base.datetime_from_unix_ms(1767830400000)  # 2026-01-08

        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=4,
            purchase_token='tok-credit-holder',
            event_ms=1767225600000,
            snapshot=_google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2026-02-01T00:00:00.000Z',
                order_id='GPA.7700-0000-0000-00012',
                obfuscated_account_id=account_id,
            ),
        )
        assert handled and not err.has()

        with ctx.connection() as conn:
            _grant_voucher(conn, master_key, at=claimed_at, duration=30 * base.DAY)
            _redeem_and_prove(conn, ctx.backend_key, master_key, rotating_key, claimed_at)
            before = backend.get_user(conn, master_key.verify_key)
            assert before.expiry_at is not None
            # Subscription coverage wins the max over the drain checkpoint, and the credit stacks on top.
            assert before.expiry_at > lapses_at

            # Refunded four months after it lapsed.
            refunded_at = base.datetime_from_unix_ms(1780272000000)  # 2026-06-01
            sink = base.ErrorSink()
            with db.transaction(conn) as tx:
                backend.add_google_revocation(
                    tx, google_payment_token='tok-credit-holder', revoke_at=refunded_at, err=sink
                )
            assert not sink.has()

            after = backend.get_user(conn, master_key.verify_key)
            assert after.expiry_at is not None
            # The credit is untouched by the refund: it still runs from the coverage that was really paid
            # for. Losing the subscription's grace period is the only movement, and that is a reduction.
            assert after.expiry_at <= before.expiry_at
            assert after.expiry_at < refunded_at, 'the refund must not become the credit base'


def test_an_unknown_base_plan_is_reported_not_asserted(monkeypatch, pg_database):
    # A base plan added in Play Console is external input. It used to hit `assert result != ProPlan.Nil`,
    # which sent an AssertionError through the handler's blanket except, so the reason was buried in a
    # traceback rather than carried in the ErrorSink. (Under `python -O` the assert vanished and the old code
    # behaved exactly as it does now: the caller has always guarded on the sink, so Nil never reached a
    # write.)
    #
    # Now it is reported: no row is written, the notification is not acked, and the message names the plan.
    # Leaving it unacked is right -- we cannot invent an entitlement for a plan we do not know -- and
    # recovery is open-ended, since the payload is stored before handling and only handled rows are pruned.
    with TestingContext(pg_database) as ctx:
        account_id = bytes(nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED).verify_key)

        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=4,
            purchase_token='tok-unknown-plan',
            event_ms=1767225600000,
            snapshot=_google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2026-02-01T00:00:00.000Z',
                order_id='GPA.8800-0000-0000-00013',
                obfuscated_account_id=account_id,
                base_plan='session-pro-6-months',  # plausible, and not one we know
            ),
        )
        # The notification itself succeeds now -- it only records that the token owes a look, and nothing
        # about an unknown plan is visible until the resource is fetched. The failure has moved to the
        # drain, which the helper drives.
        assert handled is True
        assert err.has() and any('session-pro-6-months' in msg for msg in err.msg_list), err.msg_list
        assert not _payment_rows(ctx), 'and nothing is written from a plan we cannot map'
        # The point of the change, and the only part the assertions above could not distinguish: the
        # failure is REPORTED. Previously the sink carried the message and an AssertionError traceback
        # behind it, having unwound through the blanket except on the way.
        assert not any('AssertionError' in msg for msg in err.msg_list), err.msg_list

        # And the token is retained rather than lost, so deploying support for the plan drains the backlog.
        with ctx.connection() as conn:
            queued = db.query(conn, 'SELECT payment_token, attempts FROM google_reconcile_queue').fetchall()
        assert [row[0] for row in queued] == ['tok-unknown-plan']
        assert queued[0][1] == 1, 'one failed attempt recorded, backed off for the next'


def test_one_token_is_one_subscription_whatever_its_order_ids_look_like(monkeypatch, pg_database):
    # The fold collapses a subscription's billing cycles so only its latest contributes to the max. It used
    # to do that by parsing Google's renewal-suffix convention -- splitting the order id on '..' and
    # prefix-matching the base -- while the purchase token, which IS the subscription's identity, sat
    # unselected in a table the query already joined.
    #
    # Grouping by token costs nothing on the ordinary shape and is right on this one: a subscription whose
    # order-id base changes mid-life. Prefix matching sees two unrelated bases, treats them as two competing
    # subscriptions, and lets the stale cycle keep the account entitled to an expiry it no longer has.
    with TestingContext(pg_database) as ctx:
        master_key = nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED)
        rotating_key = nacl.signing.SigningKey.generate()
        account_id = bytes(master_key.verify_key)
        shortened_to = base.datetime_from_unix_ms(1772323200000)  # 2026-03-01

        for index, (order_id, expiry, event_ms) in enumerate(
            [
                # The first cycle runs to December...
                ('GPA.1234-1234-1234-12341', '2026-12-01T00:00:00.000Z', 1767225600000),
                # ...and the next one, under a wholly different base, runs only to March.
                ('GPA.9876-9876-9876-98769', '2026-03-01T00:00:00.000Z', 1769904000000),
            ]
        ):
            handled, err = _drive_google_rtdn(
                monkeypatch,
                ctx,
                notification_type=4 if index == 0 else 2,
                purchase_token='tok-one-subscription',
                event_ms=event_ms,
                snapshot=_google_snapshot(
                    state='SUBSCRIPTION_STATE_ACTIVE',
                    expiry=expiry,
                    order_id=order_id,
                    obfuscated_account_id=account_id,
                ),
            )
            assert handled and not err.has()

        assert len(_payment_rows(ctx)) == 2, 'two cycles, since (token, order_id) differ'

        with ctx.connection() as conn:
            _redeem_and_prove(
                conn, ctx.backend_key, master_key, rotating_key, base.datetime_from_unix_ms(1770000000000)
            )
            user = backend.get_user(conn, master_key.verify_key)
            assert user.expiry_at is not None
            # Only the newest cycle counts. Under prefix matching the December row survived as a second
            # "subscription" and won the max, entitling the account nine months past its actual term.
            assert user.expiry_at == shortened_to


def test_a_bad_message_cannot_take_the_batch_down_with_it(monkeypatch, pg_database):
    # Notifications are unrelated events, so CLAUDE.md's rule is that a failure is logged and skipped rather
    # than aborting the batch -- "so isolate the decode too". It was not isolated: json.loads raises on a
    # malformed payload, and parse_notification asserts on a voided block missing the fields it requires,
    # and both sat under the pull loop's single try around the WHOLE iteration. One bad message therefore
    # took the parsing, processing and acking of every other message in that pull with it, and they all
    # redelivered into the same message next time round.
    #
    # decode_notification draws the boundary at the message. This is a unit test rather than a loop test
    # because the loop needs google-cloud-pubsub, which is imported lazily precisely so the rest of the
    # module works without it.
    monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')

    # Malformed JSON: raises inside json.loads.
    err = base.ErrorSink()
    assert google_play.decode_notification(b'{"not really js', 'malformed', err) is None

    # Structurally valid JSON whose voided block is missing the fields parse_notification asserts on.
    err = base.ErrorSink()
    assert (
        google_play.decode_notification(
            json.dumps(
                {
                    'version': '1.0',
                    'packageName': 'network.loki.messenger',
                    'eventTimeMillis': '1767225600000',
                    'voidedPurchaseNotification': {'purchaseToken': 'tok'},  # no orderId/productType/refundType
                }
            ),
            'half a voided block',
            err,
        )
        is None
    )

    # And the distinction that matters: a payload that DECODES but is not one we accept comes back as a
    # parse carrying the reason, not as None. Only the un-decodable case is dropped here; this one is
    # reported by the caller with its own message.
    err = base.ErrorSink()
    decoded = google_play.decode_notification(
        json.dumps({'version': '1.0', 'packageName': 'network.loki.messenger', 'eventTimeMillis': '1'}),
        'no notification block',
        err,
    )
    assert decoded is not None and err.has()

    # A good one still parses.
    err = base.ErrorSink()
    decoded = google_play.decode_notification(
        json.dumps(
            {
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1767225600000',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 4,
                    'purchaseToken': 'tok-fine',
                    'subscriptionId': 'session_pro',
                },
            }
        ),
        'good',
        err,
    )
    assert decoded is not None and not err.has()
    assert decoded.purchase_token == 'tok-fine'


def test_voided_notifications_reach_their_handler(monkeypatch, pg_database):
    # parse_notification tagged every voidedPurchaseNotification as `Test`, a one-word typo that made
    # handle_voided_notification unreachable. Live impact was nil, because a subscription full refund is an
    # intentional no-op there (SUBSCRIPTION_REVOKED does that work) -- but it also meant the dormant
    # one-time and partial-refund branches, and any loud guard placed in them, could never run.
    #
    # It was accidentally protective: Test-dispatch quietly acked the voids the real handler wedges on. That
    # trade is worth losing. A refunded one-time purchase keeping Pro is an over-entitlement nobody is told
    # about; a wedged notification is loud, retained, and recoverable once the handler exists.
    monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')

    def voided(product_type: int, refund_type: int) -> google_play.ParsedNotification:
        err = base.ErrorSink()
        decoded = google_play.decode_notification(
            json.dumps(
                {
                    'version': '1.0',
                    'packageName': 'network.loki.messenger',
                    'eventTimeMillis': '1767225600000',
                    'voidedPurchaseNotification': {
                        'purchaseToken': 'tok-voided',
                        'orderId': 'GPA.9999-9999-9999-99999',
                        'productType': product_type,
                        'refundType': refund_type,
                    },
                }
            ),
            'voided',
            err,
        )
        assert decoded is not None and not err.has(), err.msg_list
        return decoded

    # Dispatch now reaches the voided handler rather than being mistaken for a test ping.
    subscription_full = voided(product_type=1, refund_type=1)
    assert subscription_full.payload_type == google_play.ParsedNotificationPayloadType.Voided

    # A subscription's full refund stays a deliberate no-op: SUBSCRIPTION_REVOKED carries that work.
    with TestingContext(pg_database) as ctx:
        err = base.ErrorSink()
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                assert google_play.handle_parsed_notification(tx, subscription_full, err) is True
        assert not err.has(), err.msg_list

        # A one-time product's refund is dormant, and now says so out loud instead of being acked away.
        err = base.ErrorSink()
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                assert google_play.handle_parsed_notification(tx, voided(product_type=2, refund_type=1), err) is False
        assert err.has() and any('unsupported' in msg for msg in err.msg_list), err.msg_list


def test_a_notification_type_google_adds_later_is_retained_not_discarded(monkeypatch, pg_database):
    # A type Google introduces after us used to die at parse: an unrecognised notificationType is an
    # unrecognised INT, the shared enum coercion errs on those, and the message was discarded before it was
    # ever written down -- so it redelivered until Pub/Sub's retention lapsed and was then lost.
    #
    # Parsing now maps an unknown value to UNKNOWN, and because handling no longer consults the type at all,
    # the outcome is better than "retained until a deploy understands it": the token is enqueued and its
    # resource converged exactly as for a type we recognise. There is nothing left to teach the backend.
    monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')
    err = base.ErrorSink()
    decoded = google_play.decode_notification(
        json.dumps(
            {
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1767225600000',
                'subscriptionNotification': {
                    'version': '1.0',
                    'notificationType': 9999,  # not a value this backend knows
                    'purchaseToken': 'tok-future',
                    'subscriptionId': 'session_pro',
                },
            }
        ),
        'future type',
        err,
    )
    # Parsed cleanly, so the subscriber stores it rather than discarding it.
    assert decoded is not None and not err.has(), err.msg_list
    assert decoded.sub_type == google_play.types.SubscriptionNotificationType.UNKNOWN
    assert decoded.payload_type == google_play.ParsedNotificationPayloadType.Subscription

    # And it is handled, not merely retained: the token is queued for a reconcile like any other.
    with TestingContext(pg_database) as ctx:
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                assert google_play.handle_parsed_notification(tx, decoded, err) is True
            assert [r[0] for r in db.query(conn, 'SELECT payment_token FROM google_reconcile_queue')] == ['tok-future']
    assert not err.has(), err.msg_list
    assert decoded.purchase_token == 'tok-future'


def test_a_voided_purchase_with_unset_types_is_reported_not_asserted(monkeypatch, pg_database):
    # NIL is 0 and IS an enum member, so `productType: 0` coerces cleanly at parse and arrives intact. The
    # asserts that used to guard handle_voided_notification were therefore reachable from the wire, not the
    # impossible-state guards they were written as -- harmless only while the whole function was unreachable
    # dead code, and live the moment the dispatch typo was fixed.
    monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')
    err = base.ErrorSink()
    decoded = google_play.decode_notification(
        json.dumps(
            {
                'version': '1.0',
                'packageName': 'network.loki.messenger',
                'eventTimeMillis': '1767225600000',
                'voidedPurchaseNotification': {
                    'purchaseToken': 'tok-nil-types',
                    'orderId': 'GPA.4444-4444-4444-44444',
                    'productType': 0,  # NIL, which coerces fine
                    'refundType': 0,
                },
            }
        ),
        'nil types',
        err,
    )
    assert decoded is not None and not err.has(), err.msg_list

    with TestingContext(pg_database) as ctx:
        err = base.ErrorSink()
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                # Reported and skipped, rather than raising an AssertionError that the branch's except
                # would bury in a traceback.
                assert google_play.handle_parsed_notification(tx, decoded, err) is False
        assert err.has()
        assert not any('AssertionError' in msg for msg in err.msg_list), err.msg_list
        assert any('not handled' in msg for msg in err.msg_list), err.msg_list


def _converge(
    ctx, token: str, order_id: str, *, expiry, auto_renewing=True, in_grace=False, needs_ack=False, at=None
) -> bool:
    payment_tx = base.PaymentProviderTransaction(
        provider=base.PaymentProvider.GooglePlayStore, google_payment_token=token, google_order_id=order_id
    )
    err = base.ErrorSink()
    with ctx.connection() as conn:
        with db.transaction(conn) as tx:
            converged = backend.google_converge_payment(
                tx,
                payment_tx=payment_tx,
                expiry_at=expiry,
                auto_renewing=auto_renewing,
                in_grace=in_grace,
                needs_ack=needs_ack,
                at=at if at is not None else base.utc_now(),
                err=err,
            )
    assert not err.has(), err.msg_list
    return converged


def test_converging_revises_a_term_the_store_has_changed(monkeypatch, pg_database):
    # The write half of "the notification is a hint, the resource is the truth". expiry_at used to be
    # written once at insert, so the only way a new expiry could reach the database was a new order id --
    # which made a deferred change, or any shortening, structurally invisible. Convergence takes the term
    # as the store now states it.
    with TestingContext(pg_database) as ctx:
        master_key = nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED)
        rotating_key = nacl.signing.SigningKey.generate()
        account_id = bytes(master_key.verify_key)
        token, order_id = 'tok-converge', 'GPA.1212-1212-1212-12121'

        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=4,
            purchase_token=token,
            event_ms=1767225600000,
            snapshot=_google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2026-02-01T00:00:00.000Z',
                order_id=order_id,
                obfuscated_account_id=account_id,
            ),
        )
        assert handled and not err.has()
        with ctx.connection() as conn:
            _redeem_and_prove(
                conn, ctx.backend_key, master_key, rotating_key, base.datetime_from_unix_ms(1767830400000)
            )

        # Extended, as a recurrence-date extension would do without issuing a new order.
        extended_to = base.datetime_from_unix_ms(1772323200000)  # 2026-03-01
        assert _converge(ctx, token, order_id, expiry=extended_to) is True
        assert _payment_rows(ctx)[0][1] == extended_to
        with ctx.connection() as conn:
            assert backend.get_user(conn, master_key.verify_key).expiry_at == (extended_to)

        # And shortened, which the write-once column could never express at all.
        shortened_to = base.datetime_from_unix_ms(1769904000000)  # 2026-02-01
        assert _converge(ctx, token, order_id, expiry=shortened_to) is True
        assert _payment_rows(ctx)[0][1] == shortened_to


def test_converging_is_a_true_no_op_so_the_offset_survives_it(monkeypatch, pg_database):
    # Idempotency here is load-bearing rather than an optimisation. Every convergence pass rewrites these
    # columns, and if writing identical values registered as movement in users.expiry_at, the account's
    # proof-expiry offset would re-draw on every pass -- handing an observer repeated independent samples
    # against one unchanged true expiry, whose minimum converges onto it. That is precisely the attack the
    # offset exists to defeat.
    with TestingContext(pg_database) as ctx:
        master_key = nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED)
        rotating_key = nacl.signing.SigningKey.generate()
        account_id = bytes(master_key.verify_key)
        token, order_id = 'tok-idempotent', 'GPA.1313-1313-1313-13131'
        expiry = base.datetime_from_unix_ms(1769904000000)

        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=4,
            purchase_token=token,
            event_ms=1767225600000,
            snapshot=_google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2026-02-01T00:00:00.000Z',
                order_id=order_id,
                obfuscated_account_id=account_id,
            ),
        )
        assert handled and not err.has()
        with ctx.connection() as conn:
            _redeem_and_prove(
                conn, ctx.backend_key, master_key, rotating_key, base.datetime_from_unix_ms(1767830400000)
            )
            before = backend.get_user(conn, master_key.verify_key)

        for _ in range(5):
            assert _converge(ctx, token, order_id, expiry=expiry) is True

        with ctx.connection() as conn:
            after = backend.get_user(conn, master_key.verify_key)
        assert after.expiry_at == before.expiry_at
        assert after.proof_expiry_offset == before.proof_expiry_offset, 'five passes, no re-draw'


def test_converging_leaves_a_revoked_payment_alone(monkeypatch, pg_database):
    # Google reports a refunded subscription as expired, but never reports that money came BACK -- that is
    # the void feed's job. So converging a revoked row on the resource would quietly undo a refund we had
    # already recorded, and could push its expiry past the instant entitlement actually stopped. Terminal
    # means terminal: the row reports "nothing to converge".
    with TestingContext(pg_database) as ctx:
        master_key = nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED)
        rotating_key = nacl.signing.SigningKey.generate()
        account_id = bytes(master_key.verify_key)
        token, order_id = 'tok-revoked', 'GPA.1414-1414-1414-14141'
        revoked_at = base.datetime_from_unix_ms(1769904000000)  # 2026-02-01

        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=4,
            purchase_token=token,
            event_ms=1767225600000,
            snapshot=_google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2026-06-01T00:00:00.000Z',
                order_id=order_id,
                obfuscated_account_id=account_id,
            ),
        )
        assert handled and not err.has()
        with ctx.connection() as conn:
            _redeem_and_prove(
                conn, ctx.backend_key, master_key, rotating_key, base.datetime_from_unix_ms(1767830400000)
            )
            sink = base.ErrorSink()
            with db.transaction(conn) as tx:
                backend.add_google_revocation(tx, google_payment_token=token, revoke_at=revoked_at, err=sink)
            assert not sink.has()
            user_after_revoke = backend.get_user(conn, master_key.verify_key)

        # The store still describes this subscription, and a converge is now told it runs a further year.
        # Neither the row nor the account may move.
        assert _converge(ctx, token, order_id, expiry=base.datetime_from_unix_ms(1798761600000)) is False

        _, expiry_at, revoked = _payment_rows(ctx)[0]
        assert revoked == revoked_at, 'still revoked'
        assert expiry_at == base.datetime_from_unix_ms(1780272000000), 'and its own term is untouched'
        with ctx.connection() as conn:
            assert backend.get_user(conn, master_key.verify_key).expiry_at == user_after_revoke.expiry_at


def test_converging_an_unknown_payment_reports_rather_than_inventing_one(pg_database):
    # Convergence adjusts the terms of a payment that exists; it is not a second way to create one. A token
    # we have never seen means the notification that would have registered it was lost, which is a
    # different problem with a different answer.
    with TestingContext(pg_database) as ctx:
        assert _converge(ctx, 'tok-never-seen', 'GPA.0000-0000-0000-00000', expiry=base.utc_now()) is False
        assert not _payment_rows(ctx)


def test_refunding_a_payment_that_was_not_the_driver_broadcasts_nothing(monkeypatch, pg_database):
    # The delta gate. Refund a subscription that was NOT setting the account's expiry: a longer one survives,
    # so the entitlement does not move and every proof already signed is still honest.
    #
    # Both other gates test absolutes and would let this through -- the survivor clears the day boundary, and
    # it also falls short of the 30-day proof cap -- so without a delta check we would revoke every
    # outstanding proof of an account whose entitlement never changed. The old inline decision got this right
    # only by accident, because it happened to read the refunded payment's own expiry.
    with TestingContext(pg_database) as ctx:
        master_key = nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED)
        rotating_key = nacl.signing.SigningKey.generate()
        account_id = bytes(master_key.verify_key)

        # The driver runs 20 days out; the other ends within the day. Deliberately inside the ~30-day proof
        # cap, which is what makes the surviving-coverage gate insufficient on its own.
        for token, order_id, expiry in (
            ('tok-driver', 'GPA.2323-2323-2323-23231', '2026-01-21T00:00:00.000Z'),
            ('tok-sidecar', 'GPA.2424-2424-2424-24241', '2026-01-01T18:00:00.000Z'),
        ):
            handled, err = _drive_google_rtdn(
                monkeypatch,
                ctx,
                notification_type=4,
                purchase_token=token,
                event_ms=1766966400000,  # 2025-12-29
                snapshot=_google_snapshot(
                    state='SUBSCRIPTION_STATE_ACTIVE',
                    expiry=expiry,
                    order_id=order_id,
                    obfuscated_account_id=account_id,
                ),
            )
            assert handled and not err.has()

        with ctx.connection() as conn:
            _redeem_and_prove(
                conn, ctx.backend_key, master_key, rotating_key, base.datetime_from_unix_ms(1767139200000)
            )
            before = backend.get_user(conn, master_key.verify_key)

            sink = base.ErrorSink()
            with db.transaction(conn) as tx:
                backend.add_google_revocation(
                    tx,
                    google_payment_token='tok-sidecar',
                    revoke_at=base.datetime_from_unix_ms(1767261600000),  # 2026-01-01 10:00, inside its last day
                    err=sink,
                )
            assert not sink.has()

            after = backend.get_user(conn, master_key.verify_key)
            assert after.expiry_at == before.expiry_at, 'the driver still sets the expiry, so nothing moved'
            assert not backend.get_revocations_list(conn), 'and so there is nothing to announce'
            assert after.current_generation_id == before.current_generation_id


def test_the_owned_line_item_is_chosen_not_the_first_one(monkeypatch, pg_database):
    # A deferred change makes Google send a SECOND line item, for the product being replaced *to*, and that
    # item is documented as carrying no latestSuccessfulOrderId because the user does not own it yet. Taking
    # position 0 therefore read whichever the response happened to list first -- and picking the incoming one
    # yields an item with no order id, which is the identity every payment row is keyed by.
    #
    # Ownership is the honest filter, and it is Google's own field semantics. The incoming item is listed
    # FIRST here, which is exactly the arrangement position 0 gets wrong.
    monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')
    account_id = bytes(nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED).verify_key)

    snapshot = _google_snapshot(
        state='SUBSCRIPTION_STATE_ACTIVE',
        expiry='2026-02-01T00:00:00.000Z',
        order_id='GPA.3131-3131-3131-31311',
        obfuscated_account_id=account_id,
    )
    incoming = {
        'productId': 'session_pro',
        'expiryTime': '2026-03-01T00:00:00.000Z',
        'autoRenewingPlan': {'autoRenewEnabled': True, 'recurringPrice': {'currencyCode': 'AUD', 'units': '99'}},
        'offerDetails': {'basePlanId': 'session-pro-12-months', 'offerTags': []},
        # No latestSuccessfulOrderId: the user has not been charged for this one yet.
    }
    owned_items = snapshot['lineItems']
    assert isinstance(owned_items, list)
    snapshot['lineItems'] = [typing.cast(base.JSONValue, incoming), *owned_items]

    err = base.ErrorSink()
    details = google_play.api.parse_get_subscription_v2_response(snapshot, err)
    assert not err.has() and details is not None
    assert len(details.line_items) == 2

    chosen = google_play.api.parse_line_item(details, err)
    assert not err.has(), err.msg_list
    assert chosen is not None
    assert chosen.latest_successful_order_id == 'GPA.3131-3131-3131-31311', 'the item the user owns'
    assert chosen.offer_details.base_plan_id == 'session-pro-1-month', 'not the one being deferred to'


def test_a_subscription_with_no_owned_line_item_is_reported(pg_database):
    # A resource describing a subscription nobody has been charged for yet -- a pending signup -- has no
    # owned item. That is not a malformed response and not something to key a payment on, so it is reported
    # rather than asserted, and the caller's existing sink guard stops it.
    err = base.ErrorSink()
    details = google_play.api.parse_get_subscription_v2_response(
        {
            'kind': 'androidpublisher#subscriptionPurchaseV2',
            'startTime': '2026-01-01T00:00:00.000Z',
            'regionCode': 'AU',
            'subscriptionState': 'SUBSCRIPTION_STATE_PENDING',
            'testPurchase': {},
            'acknowledgementState': 'ACKNOWLEDGEMENT_STATE_PENDING',
            'lineItems': [
                {
                    'productId': 'session_pro',
                    'expiryTime': '2026-02-01T00:00:00.000Z',
                    'autoRenewingPlan': {
                        'autoRenewEnabled': True,
                        'recurringPrice': {'currencyCode': 'AUD', 'units': '16'},
                    },
                    'offerDetails': {'basePlanId': 'session-pro-1-month', 'offerTags': []},
                }
            ],
        },
        err,
    )
    assert not err.has() and details is not None

    assert google_play.api.parse_line_item(details, err) is None
    assert err.has() and any('no owned line item' in msg for msg in err.msg_list), err.msg_list


def _reconcile(ctx, token: str, snapshot: base.JSONObject, at) -> base.ErrorSink:
    err = base.ErrorSink()
    details = google_play.api.parse_get_subscription_v2_response(snapshot, err)
    assert not err.has() and details is not None
    with ctx.connection() as conn:
        with db.transaction(conn) as tx:
            google_play.reconcile_google_subscription(tx, purchase_token=token, details=details, at=at, err=err)
    return err


def test_reconciling_registers_a_purchase_whatever_state_it_has_reached(monkeypatch, pg_database):
    # The defect that started all of this, gone by construction. The old PURCHASED branch required the
    # freshly fetched snapshot to still read ACTIVE and silently did nothing otherwise -- so a purchase
    # followed quickly by the user turning auto-renew off registered NOTHING, was reported handled, and was
    # acked away forever.
    #
    # Reconciling does not ask why it was woken. It writes down what the store says, and the store says
    # this subscription exists, is paid through February, and is not renewing.
    monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')
    monkeypatch.setattr('providers.google_play.api.subscription_v1_acknowledge', lambda *a, **k: None)
    with TestingContext(pg_database) as ctx:
        account_id = bytes(nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED).verify_key)
        at = base.datetime_from_unix_ms(1767225600000)

        err = _reconcile(
            ctx,
            'tok-cancelled-already',
            _google_snapshot(
                state='SUBSCRIPTION_STATE_CANCELED',
                expiry='2026-02-01T00:00:00.000Z',
                order_id='GPA.5151-5151-5151-51511',
                obfuscated_account_id=account_id,
                auto_renew=False,
            ),
            at,
        )
        assert not err.has(), err.msg_list

        rows = _payment_rows(ctx)
        assert len(rows) == 1, 'the purchase is recorded, where the old branch dropped it'
        assert rows[0][0] == 'GPA.5151-5151-5151-51511'
        assert rows[0][1] == base.datetime_from_unix_ms(1769904000000)


def test_reconciling_a_superseded_token_marks_the_old_one_dirty(monkeypatch, pg_database):
    # An upgrade issues a NEW token and names the old one in linkedPurchaseToken. Google sends no further
    # notification for a token it has replaced, so that field is our only chance to learn the old
    # subscription needs revisiting -- but its own resource is the authority on what became of it, exactly
    # as this one is. So it is marked dirty rather than acted on.
    #
    # The old path revoked it inline instead, mid-write and before the replacement payment existed, which is
    # what revoked a subscriber for the crime of upgrading.
    monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')
    monkeypatch.setattr('providers.google_play.api.subscription_v1_acknowledge', lambda *a, **k: None)
    with TestingContext(pg_database) as ctx:
        account_id = bytes(nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED).verify_key)
        at = base.datetime_from_unix_ms(1767225600000)

        err = _reconcile(
            ctx,
            'tok-new',
            _google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2027-01-01T00:00:00.000Z',
                order_id='GPA.5252-5252-5252-52521',
                obfuscated_account_id=account_id,
                base_plan='session-pro-12-months',
                linked_purchase_token='tok-old',
            ),
            at,
        )
        assert not err.has(), err.msg_list

        with ctx.connection() as conn:
            queued = db.query(conn, 'SELECT payment_token, eligible_at FROM google_reconcile_queue').fetchall()
        assert [row[0] for row in queued] == ['tok-old'], 'the superseded token owes a look, nothing more'
        assert queued[0][1] == at

        # And nothing was revoked on the strength of a resource describing a different subscription.
        assert all(row[2] is None for row in _payment_rows(ctx))
        with ctx.connection() as conn:
            assert not backend.get_revocations_list(conn)


def test_reconciling_is_indifferent_to_the_order_notifications_arrive_in(monkeypatch, pg_database):
    # Nothing here applies a delta, so replaying an older view after a newer one cannot undo it: each
    # reconcile fetches and writes the CURRENT resource. This is the property the sorted queue, the
    # event-time sort and the retry backoff were all built to approximate.
    monkeypatch.setattr('providers.google_play.api.package_name', 'network.loki.messenger')
    monkeypatch.setattr('providers.google_play.api.subscription_v1_acknowledge', lambda *a, **k: None)
    with TestingContext(pg_database) as ctx:
        account_id = bytes(nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED).verify_key)
        token, order_id = 'tok-any-order', 'GPA.5353-5353-5353-53531'

        def snapshot(expiry: str, auto_renew: bool) -> base.JSONObject:
            return _google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE' if auto_renew else 'SUBSCRIPTION_STATE_CANCELED',
                expiry=expiry,
                order_id=order_id,
                obfuscated_account_id=account_id,
                auto_renew=auto_renew,
            )

        # Whatever woke us, the resource is the same one, so the result is the same.
        for _ in range(3):
            assert not _reconcile(
                ctx, token, snapshot('2026-03-01T00:00:00.000Z', auto_renew=False), base.utc_now()
            ).has()

        rows = _payment_rows(ctx)
        assert len(rows) == 1, 'three reconciles, one cycle'
        assert rows[0][1] == base.datetime_from_unix_ms(1772323200000)


def test_a_fall_discovered_by_converging_is_announced(monkeypatch, pg_database):
    # Convergence is one of the ways an entitlement FALLS -- a term the store shortened, or a revoke whose
    # notification we never received, whose resource now reads back-dated. Refreshing the account without
    # judging it would leave every outstanding proof certifying a horizon the account no longer has, and
    # nothing would announce it: the client keeps presenting a proof we signed, and peers keep honouring it.
    #
    # So converge routes its recompute through the same rule the revoke path uses, rather than a bare
    # refresh. Same question, whatever moved the rows underneath.
    monkeypatch.setattr('providers.google_play.api.subscription_v1_acknowledge', lambda *a, **k: None)
    with TestingContext(pg_database) as ctx:
        master_key = nacl.signing.SigningKey(_UPGRADE_ACCOUNT_SEED)
        rotating_key = nacl.signing.SigningKey.generate()
        account_id = bytes(master_key.verify_key)
        token, order_id = 'tok-shortened', 'GPA.7171-7171-7171-71711'

        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=4,
            purchase_token=token,
            event_ms=1767225600000,
            snapshot=_google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2026-06-01T00:00:00.000Z',
                order_id=order_id,
                obfuscated_account_id=account_id,
            ),
        )
        assert handled and not err.has()

        claimed_at = base.datetime_from_unix_ms(1767830400000)  # 2026-01-08
        with ctx.connection() as conn:
            _redeem_and_prove(conn, ctx.backend_key, master_key, rotating_key, claimed_at)
            before = backend.get_user(conn, master_key.verify_key)
            assert not backend.get_revocations_list(conn)

        # Google now says the term ended back in January -- what a revoke looks like in the resource, and
        # what a missed REVOKED notification leaves behind for convergence to discover.
        # `at` is the instant the reconcile runs, and must sit inside the fixture's timeline: judged against
        # the real clock the account would read as long expired, and the day-boundary gate would rightly
        # decline to announce anything.
        assert (
            _converge(
                ctx,
                token,
                order_id,
                expiry=base.datetime_from_unix_ms(1767830400000),
                at=base.datetime_from_unix_ms(1768003200000),  # 2026-01-10
            )
            is True
        )

        with ctx.connection() as conn:
            after = backend.get_user(conn, master_key.verify_key)
            assert after.expiry_at is not None and before.expiry_at is not None
            assert after.expiry_at < before.expiry_at, 'the entitlement fell'
            assert len(backend.get_revocations_list(conn)) == 1, 'and it was announced'


def test_google_paused_and_deferred_notifications_converge_instead_of_wedging(monkeypatch, pg_database):
    # `docs/limitations.md` listed PAUSED, PAUSE_SCHEDULE_CHANGED and DEFERRED among the notifications that
    # wedge: the old dispatch had no arm for any of them, so it appended `unsupported!`, cancelled the
    # transaction and left the RTDN redelivering forever with the purchase token in an error state.
    #
    # There is no arm to be missing now -- handling does not consult the notification type -- so each of
    # them records the token, fetches the resource and writes what it says. The arc below follows the
    # documented lifecycle rather than a guess at it:
    #
    #   "A subscription pause takes effect only after the current billing period ends."
    #   schedule change -> state ACTIVE, autoRenewEnabled true, user KEEPS access to the renewal date
    #   pause effective -> state PAUSED, autoRenewEnabled true, user loses access
    #   pause ends      -> SUBSCRIPTION_RECOVERED, and Google attempts to renew
    #   -- https://developer.android.com/google/play/billing/lifecycle/subscriptions
    #
    # Note RECOVERED is also account-hold recovery: two different lifecycle events share one type, which is
    # its own argument against dispatching on the type.
    #
    # What the docs do NOT state is what `expiryTime` holds while paused, so nothing here asserts a value
    # Google has not promised. Every assertion is "the term is whatever the resource said", which is the
    # property convergence actually provides.
    kind = google_play.types.SubscriptionNotificationType
    with TestingContext(pg_database) as ctx:
        account_id = bytes(nacl.signing.SigningKey.generate().verify_key)
        token = 'tok-paused'
        order_id = 'GPA.7777-0000-0000-00001'
        paid_through = '2026-02-01T00:00:00.000Z'

        def snapshot(state: str, expiry: str) -> base.JSONObject:
            return _google_snapshot(state=state, expiry=expiry, order_id=order_id, obfuscated_account_id=account_id)

        def drive(notification: object, snap: base.JSONObject, event_ms: int) -> None:
            handled, err = _drive_google_rtdn(
                monkeypatch,
                ctx,
                notification_type=notification.value,  # type: ignore[attr-defined]
                purchase_token=token,
                event_ms=event_ms,
                snapshot=snap,
            )
            assert handled is True and not err.has(), err.msg_list

        # Keyed by ORDER ID, not just the token: after a resume the same token has two cycles, and asking
        # by token alone would silently answer for whichever row came back first.
        def stored_expiry(cycle: str) -> pendulum.DateTime:
            with ctx.connection() as conn:
                return db.query_scalar(
                    conn,
                    '''SELECT p.expiry_at FROM payments p
                       JOIN google_play_payment_details gd ON gd.payment_id = p.id
                       WHERE gd.payment_token = %s AND gd.order_id = %s''',
                    token,
                    cycle,
                )

        # The user asks to pause. The subscription is still ACTIVE and they keep the term they paid for.
        drive(kind.PAUSE_SCHEDULE_CHANGED, snapshot('SUBSCRIPTION_STATE_ACTIVE', paid_through), 1767225600000)
        assert len(_payment_rows(ctx)) == 1, 'recorded, not left wedged'
        assert stored_expiry(order_id) == pendulum.datetime(2026, 2, 1), 'a pause schedule takes nothing away'

        # The billing period ends and the pause takes effect. `autoRenewEnabled` stays true even here.
        paused = snapshot('SUBSCRIPTION_STATE_PAUSED', paid_through)
        paused['pausedStateContext'] = {'autoResumeTime': '2026-03-01T00:00:00.000Z'}
        drive(kind.PAUSED, paused, 1767312000000)
        assert len(_payment_rows(ctx)) == 1, 'still one cycle: a pause is not a billing period'
        assert stored_expiry(order_id) == pendulum.datetime(2026, 2, 1), 'still the term the store states'

        # The pause ends and Google renews, which is a new cycle with a new order id.
        resumed = _google_snapshot(
            state='SUBSCRIPTION_STATE_ACTIVE',
            expiry='2026-04-01T00:00:00.000Z',
            order_id='GPA.7777-0000-0000-00002',
            obfuscated_account_id=account_id,
        )
        drive(kind.RECOVERED, resumed, 1772323200000)
        assert len(_payment_rows(ctx)) == 2, 'the resumed period is its own cycle'

        # And a deferral, which extends a term in place rather than starting one. Applied to the cycle the
        # user is actually in -- the resumed one -- which is the only cycle a real deferral could name.
        drive(
            kind.DEFERRED,
            _google_snapshot(
                state='SUBSCRIPTION_STATE_ACTIVE',
                expiry='2026-05-15T00:00:00.000Z',
                order_id='GPA.7777-0000-0000-00002',
                obfuscated_account_id=account_id,
            ),
            1772409600000,
        )
        assert len(_payment_rows(ctx)) == 2, 'no new cycle: a deferral revises the term it is given'
        assert stored_expiry('GPA.7777-0000-0000-00002') == pendulum.datetime(2026, 5, 15), 'from the resource'
        assert stored_expiry(order_id) == pendulum.datetime(2026, 2, 1), 'and the earlier cycle is untouched'


def test_google_resubscription_is_attributed_from_the_expired_subscription(monkeypatch, pg_database):
    # A resubscribe after the previous subscription expired COMPLETELY is a brand new purchase with no
    # `linkedPurchaseToken` -- Play says so, "because the original subscription expired completely" -- and
    # when it is not made through our app nothing called setObfuscatedAccountId, so it carries no account id
    # of its own. Play's answer is `outOfAppPurchaseContext`, holding the identifiers from the expired
    # subscription, "present exclusively for unacknowledged resubscription purchases".
    #
    # Without reading it the purchase cannot be attributed, which is not merely paid-but-no-Pro: the
    # reconcile returns before registering the row, so `needs_ack` is never written, the ack sweep never
    # acknowledges it, and Google auto-refunds at three days. The user pays, gets nothing, and is refunded.
    with TestingContext(pg_database) as ctx:
        account_id = bytes(nacl.signing.SigningKey.generate().verify_key)
        snapshot = _google_snapshot(
            state='SUBSCRIPTION_STATE_ACTIVE',
            expiry='2026-03-01T00:00:00.000Z',
            order_id='GPA.4444-0000-0000-00001',
            obfuscated_account_id=account_id,
        )
        # The new purchase carries NO identifiers of its own; only the expired one's are available. And it
        # is PENDING acknowledgement, because Play states outOfAppPurchaseContext is present exclusively on
        # unacknowledged resubscriptions -- an acknowledged one could not carry the field at all.
        del snapshot['externalAccountIdentifiers']
        snapshot['acknowledgementState'] = 'ACKNOWLEDGEMENT_STATE_PENDING'
        snapshot['outOfAppPurchaseContext'] = {
            'expiredExternalAccountIdentifiers': {'obfuscatedAccountId': account_id.hex()},
            'expiredPurchaseToken': 'tok-the-expired-one',
        }

        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=google_play.types.SubscriptionNotificationType.PURCHASED.value,
            purchase_token='tok-resubscribed',
            event_ms=1767225600000,
            snapshot=snapshot,
        )
        assert handled is True and not err.has(), err.msg_list

        with ctx.connection() as conn:
            attributed = db.query_scalar(
                conn,
                '''SELECT gd.obfuscated_account_id FROM google_play_payment_details gd
                   WHERE gd.payment_token = %s''',
                'tok-resubscribed',
            )
            needs_ack = db.query_scalar(
                conn, 'SELECT needs_ack FROM google_play_payment_details WHERE payment_token = %s', 'tok-resubscribed'
            )
        assert attributed is not None and bytes(attributed) == account_id, 'attributed to the resubscribing user'
        assert needs_ack is True, 'and flagged for acknowledgement, which is what averts the auto-refund'


def test_google_a_purchase_prefers_its_own_account_id_over_an_expired_one(monkeypatch, pg_database):
    # The fallback must never override a current fact with a historical one. If the purchase carries its own
    # account id, that is the answer even when an expired subscription's identifiers are also present --
    # otherwise a resubscribe by a DIFFERENT account than the one that let the old subscription lapse would
    # be handed to the wrong user, which is the one failure this fallback could introduce.
    with TestingContext(pg_database) as ctx:
        current = bytes(nacl.signing.SigningKey.generate().verify_key)
        previous = bytes(nacl.signing.SigningKey.generate().verify_key)
        assert current != previous
        snapshot = _google_snapshot(
            state='SUBSCRIPTION_STATE_ACTIVE',
            expiry='2026-03-01T00:00:00.000Z',
            order_id='GPA.4444-0000-0000-00002',
            obfuscated_account_id=current,
        )
        snapshot['outOfAppPurchaseContext'] = {
            'expiredExternalAccountIdentifiers': {'obfuscatedAccountId': previous.hex()},
            'expiredPurchaseToken': 'tok-someone-elses',
        }

        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=google_play.types.SubscriptionNotificationType.PURCHASED.value,
            purchase_token='tok-has-its-own',
            event_ms=1767225600000,
            snapshot=snapshot,
        )
        assert handled is True and not err.has(), err.msg_list

        with ctx.connection() as conn:
            attributed = db.query_scalar(
                conn,
                'SELECT obfuscated_account_id FROM google_play_payment_details WHERE payment_token = %s',
                'tok-has-its-own',
            )
        assert bytes(attributed) == current, "the purchase's own id wins"


def test_google_a_purchase_with_no_identifiers_at_all_is_still_reported(monkeypatch, pg_database):
    # The fallback narrows the unattributable case; it does not remove it. A purchase with neither its own
    # identifiers nor an expired subscription's must still fail loudly rather than be registered against
    # nobody, because an unattributed row is a payment no user can ever claim.
    with TestingContext(pg_database) as ctx:
        snapshot = _google_snapshot(
            state='SUBSCRIPTION_STATE_ACTIVE',
            expiry='2026-03-01T00:00:00.000Z',
            order_id='GPA.4444-0000-0000-00003',
            obfuscated_account_id=bytes(nacl.signing.SigningKey.generate().verify_key),
        )
        del snapshot['externalAccountIdentifiers']

        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=google_play.types.SubscriptionNotificationType.PURCHASED.value,
            purchase_token='tok-anonymous',
            event_ms=1767225600000,
            snapshot=snapshot,
        )
        # `handled` is the NOTIFICATION's outcome, and recording the token succeeded -- the attribution
        # failure happens in the drain, which is the point of decoupling them.
        assert handled is True
        assert err.has() and any('not be attributed' in m for m in err.msg_list), err.msg_list
        assert not _payment_rows(ctx), 'nothing was registered against nobody'
        with ctx.connection() as conn:
            still_queued = db.query(conn, 'SELECT payment_token FROM google_reconcile_queue').fetchall()
        assert [r[0] for r in still_queued] == ['tok-anonymous'], 'the obligation is RETAINED, not discarded'


def test_google_resubscription_is_attributed_through_the_expired_token(monkeypatch, pg_database):
    # The deepest fallback: neither the new purchase nor the EXPIRED subscription carries an account id, so
    # only `expiredPurchaseToken` is left. Our own record answers it -- redemption bound the old row to its
    # owner whatever the store knew -- which is reach the store-side identifiers alone do not have.
    with TestingContext(pg_database) as ctx:
        account_id = bytes(nacl.signing.SigningKey.generate().verify_key)

        # An earlier subscription, claimed by this account, that has since fully expired.
        old = _google_snapshot(
            state='SUBSCRIPTION_STATE_ACTIVE',
            expiry='2026-01-15T00:00:00.000Z',
            order_id='GPA.5555-0000-0000-00001',
            obfuscated_account_id=account_id,
        )
        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=google_play.types.SubscriptionNotificationType.PURCHASED.value,
            purchase_token='tok-old-expired',
            event_ms=1767225600000,
            snapshot=old,
        )
        assert handled is True and not err.has(), err.msg_list
        with ctx.connection() as conn:
            assert (
                backend.reconcile_pending_payments(
                    conn, nacl.signing.VerifyKey(account_id), redeemed_at=pendulum.datetime(2026, 1, 1)
                )
                >= 1
            )

        # The resubscribe: no identifiers anywhere, only the expired token.
        new = _google_snapshot(
            state='SUBSCRIPTION_STATE_ACTIVE',
            expiry='2026-04-01T00:00:00.000Z',
            order_id='GPA.5555-0000-0000-00002',
            obfuscated_account_id=account_id,
        )
        del new['externalAccountIdentifiers']
        new['acknowledgementState'] = 'ACKNOWLEDGEMENT_STATE_PENDING'
        new['outOfAppPurchaseContext'] = {'expiredPurchaseToken': 'tok-old-expired'}

        handled, err = _drive_google_rtdn(
            monkeypatch,
            ctx,
            notification_type=google_play.types.SubscriptionNotificationType.PURCHASED.value,
            purchase_token='tok-resub-by-token',
            event_ms=1772323200000,
            snapshot=new,
        )
        assert handled is True and not err.has(), err.msg_list

        with ctx.connection() as conn:
            attributed = db.query_scalar(
                conn,
                'SELECT obfuscated_account_id FROM google_play_payment_details WHERE payment_token = %s',
                'tok-resub-by-token',
            )
        assert bytes(attributed) == account_id, 'attributed through our own record of the expired token'
