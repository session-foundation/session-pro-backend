'''
Entry point for witnessing notifications from the Google Play store. This layer initiates an
asynchronous fetching operation from Google to monitor for new payments, parsing it and process said
payments into the database layer (backend.py)
'''

import pendulum
import json
import traceback
import logging
import psycopg
import threading
import dataclasses
import typing
import time
import enum

from google.oauth2 import service_account

import googleapiclient.discovery
import google_auth_httplib2
import httplib2

import backend
import base
import db

from base import (
    JSONObject,
    json_dict_require_str,
    json_dict_require_str_coerce_to_int,
    safe_dump_dict_keys_or_data,
    json_dict_optional_obj,
    json_dict_require_int_coerce_to_enum,
    reflect_enum,
)

from . import api
from .api import SubscriptionPlanEventTransaction, VoidedPurchaseTxFields
from .types import (
    SubscriptionNotificationType,
    SubscriptionsV2AcknowledgementState,
    SubscriptionsV2State,
    RefundType,
    ProductType,
    SubscriptionV2Data,
)

log = logging.getLogger('google_play')

# How long the subscriber loop waits before doing its periodic work when nothing wakes it. A FLOOR, not a
# schedule: a callback sets the event as soon as it commits, so an arriving notification is serviced in
# milliseconds and this only paces the work no notification announces — the drain's own retry backoffs, and
# tokens a reconcile enqueued rather than a message. An idle pass is two indexed queries.
SUBSCRIBER_POLL_FLOOR_S: int = 15

# Paces reconnection after the stream dies for good, so a subscribe() that fails instantly — bad
# credentials, a deleted subscription — cannot spin the mule at the speed of the error.
SUBSCRIBER_RECONNECT_DELAY_S: int = 5

# How long a callback already running is given to finish once shutdown is signalled. Nothing is lost by
# cutting it short: an abandoned callback's transaction rolls back, and the message was never acked.
SUBSCRIBER_SHUTDOWN_GRACE_S: int = 2


@dataclasses.dataclass
class ThreadContext:
    thread: threading.Thread | None = None
    kill_thread: bool = False
    sleep_event: threading.Event = threading.Event()


class ParsedNotificationPayloadType(enum.Enum):
    Nil = 0
    Subscription = 1
    Voided = 2
    Test = 3
    OneTimeProduct = 4


@dataclasses.dataclass
class ParsedNotification:
    payload_type: ParsedNotificationPayloadType = ParsedNotificationPayloadType.Nil
    payload_version: str = ''
    sub_type: SubscriptionNotificationType = SubscriptionNotificationType.NIL
    voided: VoidedPurchaseTxFields = dataclasses.field(default_factory=VoidedPurchaseTxFields)
    body_version: str = ''
    event_time_ms: int = 0
    package_name: str = ''
    purchase_token: str = ''


@dataclasses.dataclass
class SortedMessage:
    """One RTDN on its way through `_process_notification_message`.

    The name is a fossil of the sorted queue that no longer exists, kept because the tests that pin the
    transaction composition are written against it. There is nothing left to sort: ordering stopped being a
    requirement when handling became convergent, and the per-message backoff this once carried is now the
    subscription's retry policy (see `docs/deploy.md`).
    """

    event_unix_ts_ms: int = 0
    message_id: str = ''
    parse: ParsedNotification = dataclasses.field(default_factory=ParsedNotification)
    raw: object | None = None  # a pubsub message at runtime; only ever str()'d, so untyped here


def init_api(package_name: str, subscription_product_id: str, app_credentials_path: str | None) -> None:
    '''Build the Play Developer API client and record the identifiers every call needs, in the globals
    `api` reads them from. Idempotent, so a caller may call it on every use rather than tracking whether
    it has run.

    EVERY process that reaches Google has to call this, not just the one that runs the Pub/Sub subscriber:
    `api.credentials` / `api.publisher_service` are module globals (Google's callbacks take no per-callback
    context), and a mule is a separate process with its own copy. The reconcile-queue drain fetches the
    subscription resource, and it runs in the maintenance mule as well as from the subscriber's pull loop —
    a process that registers the task without calling this asserts on every attempt instead.

    Split out of `init` so a process can have this WITHOUT the subscriber. It is everything Google except
    the subscriber: no thread, no socket (httplib2 connects on first request), no grpc — that arrives with
    `google-cloud-pubsub`, imported inside the subscriber thread — and no network, because the discovery
    document for androidpublisher v3 ships with the client library and is read from disk. So a mule that
    only reconciles pays a file read and a key parse for it.

    The memo is `publisher_service`, deliberately not `credentials`: if the file loads but the client fails
    to build, credentials are set while the service is not, and only re-reading gets out of that — guarding
    on credentials instead would leave `get_publisher_service` asserting forever with no route back.'''
    if app_credentials_path and api.publisher_service is None:
        api.credentials = service_account.Credentials.from_service_account_file(
            app_credentials_path, scopes=['https://www.googleapis.com/auth/androidpublisher']
        )
        # Bound every Play API call with a socket timeout. googleapiclient's default httplib2 transport
        # has NO timeout, so a hung Google request would block the subscriber's single worker
        # indefinitely (there's no harakiri leash on the mule like there is on the request workers). 15s
        # is plenty; a timeout just fails the call, and the mule retries — nothing it does is time-critical.
        authed_http = google_auth_httplib2.AuthorizedHttp(api.credentials, http=httplib2.Http(timeout=15))
        api.publisher_service = googleapiclient.discovery.build('androidpublisher', 'v3', http=authed_http)

    api.package_name = package_name
    api.subscription_product_id = subscription_product_id


def init(
    cloud_project_id: str,
    package_name: str,
    cloud_subscription_name: str,
    subscription_product_id: str,
    app_credentials_path: str | None,
) -> ThreadContext:
    # NOTE: Setup credentials global variable
    assert api.credentials is None and api.publisher_service is None and len(api.package_name) == 0, (
        "Initialise was called twice. Google uses callbacks with no way to pass in a per-callback context"
        " so it needs global variables"
    )

    init_api(
        package_name=package_name,
        subscription_product_id=subscription_product_id,
        app_credentials_path=app_credentials_path,
    )

    # NOTE: Setup thread for caller to use. daemon=True is load-bearing for uWSGI reloads: a callback
    # already executing cannot be interrupted (no Python thread can), and CPython's interpreter shutdown
    # JOINS every non-daemon thread BEFORE atexit runs — so a non-daemon subscriber wedges the whole mule
    # and uWSGI NO-MERCY-kills it. As a daemon it's abandoned at exit instead (stop_subscriber still gives
    # it a brief chance to finish); an abandoned callback's transaction rolls back and its message was
    # never acked, so Google redelivers it — nothing is lost.
    result = ThreadContext()
    result.thread = threading.Thread(
        target=thread_entry_point,
        args=(result, app_credentials_path, cloud_project_id, cloud_subscription_name),
        daemon=True,
    )
    return result


def start_subscriber(
    cloud_project_id: str,
    package_name: str,
    cloud_subscription_name: str,
    subscription_product_id: str,
    app_credentials_path: str | None,
) -> ThreadContext:
    '''
    Initialise + start the Google Pub/Sub notification subscriber. Runs a background streaming
    subscriber. All
    Google/gRPC state is constructed here, so the caller (the maintenance mule) invokes this
    post-fork.
    '''
    if base.PROVIDER_DRY_RUN:
        # Dry-run: consuming real Pub/Sub notifications is outbound provider I/O, so don't start the loop
        # (this also keeps the notification-path fetch/monetization egress from ever firing). Return an
        # inert context so the caller's stop_subscriber()/atexit teardown is still safe to call.
        log.info('Google subscriber not started (provider_dry_run)')
        return ThreadContext(kill_thread=True)

    context = init(
        cloud_project_id=cloud_project_id,
        package_name=package_name,
        cloud_subscription_name=cloud_subscription_name,
        subscription_product_id=subscription_product_id,
        app_credentials_path=app_credentials_path,
    )
    assert context.thread
    context.thread.start()
    return context


def stop_subscriber(context: ThreadContext) -> None:
    '''
    Signal the subscriber to stop and wait briefly for it to finish (idempotent; safe to call on
    shutdown even if never started). Setting `sleep_event` is what makes this immediate: the loop waits on
    that event, so it wakes at once rather than serving out its poll floor.

    The thread is a daemon (see init): a callback that cannot finish within the window is abandoned at
    interpreter exit rather than wedging the mule — its transaction rolls back and its message was never
    acked, so Google redelivers it.
    '''
    context.kill_thread = True
    context.sleep_event.set()
    if context.thread and context.thread.is_alive():
        # Outlasts SUBSCRIBER_SHUTDOWN_GRACE_S deliberately: the loop spends that long waiting for an
        # executing callback, so joining for less would return before the grace it configures could
        # elapse, making the grace period decorative.
        context.thread.join(timeout=SUBSCRIBER_SHUTDOWN_GRACE_S + 1)


def handle_parsed_notification(tx: db.SQLTransaction, parse: ParsedNotification, err: base.ErrorSink) -> bool:
    result = False
    match parse.payload_type:
        case ParsedNotificationPayloadType.Nil:
            pass

        case ParsedNotificationPayloadType.Subscription:
            try:
                # Record that this token owes a look, and stop. No fetch, no dispatch on type: the
                # notification's whole content is "something about this subscription changed", and the
                # resource — which the drain fetches on its own schedule — is what says what it changed to.
                #
                # This is what decouples acking from handling. One small write is now the only step that has
                # to succeed before the message can be acked, and it is the only step whose failure loses
                # anything: a first sighting of a token cannot be recovered from anywhere else, while
                # everything downstream is re-derivable from the resource for as long as the token is known.
                # Dated from the store's event instant rather than our clock, because provider time stays
                # coherent for a replay (already past, so still immediately due) and in the compressed
                # testing environment, where a "day" is ten seconds.
                #
                # Clamped to now, though, because `eligible_at` is a FLOOR: a clock-skewed or malformed
                # eventTimeMillis an hour ahead would defer this token for an hour with nothing reporting
                # it, where the old path processed immediately. Past values pass through untouched.
                event_at = base.datetime_from_unix_ms(parse.event_time_ms)
                enqueue_now = base.utc_now()
                backend.google_enqueue_reconcile(
                    tx,
                    payment_token=parse.purchase_token,
                    eligible_at=event_at if event_at < enqueue_now else enqueue_now,
                )
                # DEBUG because a notification is not itself an event: it says only that this token needs a
                # look, and whatever it turns out to have changed is reported by the converge. The type is
                # logged all the same — it is the store's own account of why it woke us, and it is the last
                # place the type is visible now that nothing dispatches on it.
                log.debug(
                    f'RTDN {reflect_enum(parse.sub_type)} for {base.maybe_obfuscate(parse.purchase_token)}: '
                    f'queued for reconcile at {base.readable(min(event_at, enqueue_now))}'
                )

                # The one fact the resource cannot express, so the one thing the type still decides. A
                # revoked subscription reads EXPIRED with a back-dated term, which is indistinguishable from
                # one that simply ran out — and that difference belongs in the payment record even though
                # entitlement no longer depends on it (the drain's converge would end the entitlement either
                # way). Safe without the state guard the old branch used: a revoked subscription is
                # terminated permanently, so a replayed REVOKED can only ever be about this token's ending,
                # and the `revoked_at IS NULL` guard makes re-stamping a no-op.
                if parse.sub_type == SubscriptionNotificationType.REVOKED:
                    backend.add_google_revocation(
                        tx,
                        google_payment_token=parse.purchase_token,
                        revoke_at=base.datetime_from_unix_ms(parse.event_time_ms),
                        err=err,
                    )
            except Exception:
                err.msg_list.append(f"Handling notification failed: {traceback.format_exc()}")

            if err.has():
                tx.cancel = True
        case ParsedNotificationPayloadType.Voided:
            try:
                log.debug(
                    f'Voided purchase RTDN ({reflect_enum(parse.voided.product_type)}, '
                    f'{reflect_enum(parse.voided.refund_type)}); a subscription revocation arrives separately'
                )
                handle_voided_notification(parse.voided, err)
            except Exception:
                err.msg_list.append(f"Handling notification failed: {traceback.format_exc()}")
            # The subscription path cancels from inside its own handler; this one has to do it here, and
            # the tail below asserts that it happened. Missing while the branch was unreachable dead code
            # (see the payload_type typo it was hiding behind), it would have turned the first unsupported
            # void into an AssertionError instead of the reported skip it is meant to be.
            if err.has():
                tx.cancel = True

        case ParsedNotificationPayloadType.OneTimeProduct:
            err.msg_list.append('One time product is not supported!')
            tx.cancel = True

        case ParsedNotificationPayloadType.Test:
            # Logged because this is what somebody clicking "Send test notification" in the Play Console is
            # looking for: the one message whose whole purpose is to prove the pipeline is connected.
            log.info('Received a Google Play test notification; the Pub/Sub pipeline is connected')

    result = not err.has()
    if err.has():
        assert tx.cancel
    return result


def _process_notification_message(
    conn: psycopg.Connection, msg: SortedMessage, err: base.ErrorSink, now_s: float
) -> bool:
    """
    Process one queued RTDN message inside a single DB transaction and report whether it was handled
    (True → ack; False → nack for redelivery). Marking the message handled happens in the SAME transaction
    as handle_parsed_notification, so a handling failure that sets tx.cancel rolls back that bookkeeping
    too. Extracted from the subscriber callback so this transaction-composition is unit-testable (the loop
    itself, which owns the gRPC client, is not).

    Where a failure becomes visible: the token's `google_reconcile_queue` row, which the drain stamps with
    `attempts` and `last_error`. This used to also write a `user_error` row, surfaced to the account as the
    wire's `error_report` — one undocumented bit with no reason and no remedy, which a handling failure then
    rolled back anyway. Deleted rather than repointed; a stuck purchase is operator information.
    """

    handled = False
    with db.transaction(conn) as tx:
        # NOTE: The caller records the message in the DB before reaching here. So if for some reason the
        # notification doesn't exist anymore (maybe someone deleted it
        # out-of-band, e.g. via the SET_GOOGLE_NOTIFICATION command) then we skip the notification.
        lookup = backend.google_notification_message_id_is_in_db(tx, msg.message_id)
        if not lookup.present or lookup.present and lookup.handled:
            handled = True
        else:
            handled = handle_parsed_notification(tx, msg.parse, err)

        if lookup.present and handled:
            backend.google_set_notification_handled(tx, message_id=msg.message_id, delete=False)
    return handled


def _sweep_pending_acks() -> None:
    """Acknowledge to Google every Google purchase still flagged needs_ack, then clear the flag. This is
    the SOLE acker: notification handling only records needs_ack, and the subscriber loop calls this once per
    iteration (right before blocking on the next pull), so a fresh purchase is acked the next cycle and a
    crash between committing a payment and acking it is picked up by the next sweep — startup included, no
    special case. Google 400s an already-acknowledged purchase with no cleanly-identifiable error, so on
    ANY ack failure we consult the authoritative acknowledgement_state and clear the flag iff Google
    already considers it acked (the "acked, then crashed before clearing" case); otherwise leave it set to
    retry. Best-effort — never raises, so it can't break the subscriber loop."""
    try:
        with db.connection() as conn:
            tokens = backend.google_payment_tokens_needing_ack(conn)
    except Exception:
        log.error(f'needs_ack sweep: failed to load pending acks. Error was {traceback.format_exc()}')
        return

    for token, purchased_at in tokens:
        ack_err = base.ErrorSink()
        api.subscription_v1_acknowledge(purchase_token=token, err=ack_err)
        acked = not ack_err.has()
        if not acked:
            # Ack failed: either a transient error, or we already acked and crashed before clearing the
            # flag. Read the authoritative state rather than trying to parse Google's ambiguous 400.
            fetch_err = base.ErrorSink()
            details = api.fetch_subscription_v2_details(api.package_name, token, fetch_err)
            acked = (
                not fetch_err.has()
                and details is not None
                and details.acknowledgement_state == SubscriptionsV2AcknowledgementState.ACKNOWLEDGED
            )
        if acked:
            try:
                with db.connection() as conn:
                    backend.google_clear_needs_ack(conn, payment_token=token)
                # INFO rather than DEBUG: this is the step that stops Google auto-refunding the purchase at
                # three days, so "did it ever happen" is a question worth being able to answer from the log.
                log.info(f'Acknowledged Google purchase {base.maybe_obfuscate(token)}')
            except Exception:
                log.error(
                    f'needs_ack sweep: acked but failed to clear flag for {base.maybe_obfuscate(token)}. '
                    f'Error was {traceback.format_exc()}'
                )
        else:
            # Escalated against Google's own clock, not ours: an unacknowledged purchase is automatically
            # refunded and its entitlement revoked three days after purchase, so a failing ack is a blip on
            # the first sweep and an emergency on the third day. Anchored on the purchase instant because
            # that is when the store starts counting, and on the token's EARLIEST cycle because a token is
            # acknowledged as a whole.
            age = base.utc_now() - purchased_at
            token_label = base.maybe_obfuscate(token)
            if age >= ACK_DEADLINE_ALERT_AFTER:
                log.critical(
                    f'needs_ack sweep: ack has been failing for {token_label} since '
                    f'{base.readable(purchased_at)} ({age.in_hours():.0f}h). Google auto-refunds an '
                    f'unacknowledged purchase at {ACK_DEADLINE.in_hours():.0f}h and revokes the '
                    f'entitlement with it — this needs intervention now'
                )
            else:
                log.warning(
                    f'needs_ack sweep: ack still failing for {token_label} '
                    f'({age.in_hours():.0f}h since purchase); will retry next sweep'
                )


def thread_entry_point(
    context: ThreadContext, app_credentials_path: str, cloud_project_id: str, cloud_subscription_name: str
):
    # grpcio (via google-cloud-pubsub) is imported HERE, not at module scope, deliberately: this is the
    # subscriber thread body and runs only post-fork, inside the mule. A module-level import pulls
    # grpcio's background C threads into the uWSGI master, and the forked mule then segfaults on the
    # dead inherited threads. DO NOT HOIST these to the top of the file.
    import concurrent.futures

    from google.cloud import pubsub_v1  # type: ignore[attr-defined]

    # Imported by its full path rather than reached through `pubsub_v1.subscriber.scheduler`: that package's
    # __init__ exports only `Client`, so the attribute path works or not depending on what else happened to
    # import the submodule first.
    from google.cloud.pubsub_v1.subscriber.scheduler import ThreadScheduler

    _replay_unhandled_backlog()

    # Set by a callback once its work is committed, so the drain runs promptly after a burst rather than on
    # the next poll. `Event.set()` is idempotent, so a hundred messages wake the loop once and cost one
    # drain pass — the trigger is coalesced, not per-message. `stop_subscriber` sets the same event, which
    # is what makes shutdown immediate rather than waiting out a poll.
    def _on_message(message: typing.Any) -> None:
        _handle_streamed_message(message)
        context.sleep_event.set()

    while not context.kill_thread:
        try:
            with pubsub_v1.SubscriberClient.from_service_account_file(app_credentials_path) as client:
                sub_path = client.subscription_path(project=cloud_project_id, subscription=cloud_subscription_name)

                # ONE worker, deliberately, and not a throughput oversight. Every line of this pipeline was
                # written and reviewed under a serial handler, and a callback no longer does network I/O —
                # the fetch moved into the drain, so what runs here is a decode and a couple of small
                # writes. Concurrency would buy nothing measurable at this volume and would cost the
                # property that makes the handler easy to reason about. Revisit with volume evidence, not
                # on principle. Flow control is explicit for the same reason the old loop capped
                # `max_messages`: an unbounded lease is a memory leak wearing a queue's clothes.
                scheduler = ThreadScheduler(executor=concurrent.futures.ThreadPoolExecutor(max_workers=1))
                future = client.subscribe(
                    subscription=sub_path,
                    callback=_on_message,
                    flow_control=pubsub_v1.types.FlowControl(max_messages=100),
                    scheduler=scheduler,
                    # Without this the default is False, and `result()` after `cancel()` returns while
                    # callbacks are still running — which would make the shutdown grace below do nothing at
                    # all. It does not close the commit-then-ack window (nothing can), but it stops us
                    # abandoning work we could simply have waited a moment for.
                    await_callbacks_on_shutdown=True,
                )
                log.info('Google subscriber streaming')
                try:
                    while not context.kill_thread:
                        # Woken by a callback, by shutdown, or by the poll floor. The floor is what services
                        # the drain's own backoffs and anything enqueued by a reconcile rather than by a
                        # notification; the mule's periodic task is still the backstop for both.
                        context.sleep_event.wait(timeout=SUBSCRIBER_POLL_FLOOR_S)
                        context.sleep_event.clear()
                        if context.kill_thread:
                            break

                        if future.done():
                            # Transient stream errors are retried inside the library, so reaching here means
                            # it gave up. Surface the reason rather than reconnecting blind.
                            future.result()
                            break

                        # Best-effort: neither of these may break the loop, and everything they leave
                        # undone is still queued or still flagged.
                        try:
                            drain_due_reconciles(at=base.utc_now())
                        except Exception:
                            log.error(f'Reconcile drain failed from the subscriber. Error was {traceback.format_exc()}')
                        try:
                            _sweep_pending_acks()
                        except Exception:
                            log.error(f'Ack sweep failed from the subscriber. Error was {traceback.format_exc()}')
                finally:
                    # Undispatched messages are dropped unacked and redelivered; a callback already running
                    # is allowed to finish, because no Python thread can be killed. See
                    # `_handle_streamed_message` for why being abandoned mid-flight is harmless.
                    future.cancel()
                    try:
                        future.result(timeout=SUBSCRIBER_SHUTDOWN_GRACE_S)
                    except Exception:
                        # Including the CancelledError the line above is expected to raise.
                        pass
        except Exception:
            log.error(f'Google subscriber stream failed. Error was {traceback.format_exc()}')

        # Paced, so a subscribe() that fails immediately -- bad credentials, a deleted subscription -- does
        # not spin the mule at the speed of the error.
        if not context.kill_thread:
            context.sleep_event.wait(timeout=SUBSCRIBER_RECONNECT_DELAY_S)
            context.sleep_event.clear()

    # Reaching here without being asked to stop means the loop gave up. The mule blocks on this thread and
    # uWSGI respawns it, so the supervision is already right -- but a respawn loop is indistinguishable from
    # health in the logs unless the exit says so. Everything inside is wrapped, so this needs a BaseException
    # to happen at all, which is exactly why it should be loud rather than assumed impossible.
    if not context.kill_thread:
        log.critical('Google subscriber loop exited without being asked to stop; the mule will restart it')


def _handle_streamed_message(message: typing.Any) -> None:
    """Record one streamed RTDN, process it, and ack or nack it.

    Runs on the subscriber's callback thread. Every failure path here nacks, which returns the message for
    redelivery; the pacing of that redelivery is the SUBSCRIPTION's retry policy, not ours. The old loop
    carried its own 1 s -> 600 s backoff, and there is no code left holding that responsibility -- see
    `docs/deploy.md` for the settings that have to exist before this ships.

    Being abandoned between the commit and the ack is possible and harmless: the message is redelivered,
    `_process_notification_message` finds its row already marked handled, and acks it. That is the same
    mechanism that makes at-least-once delivery a non-event, and it is why the history row is written
    BEFORE the message is processed rather than alongside it.
    """

    err = base.ErrorSink()
    published = base.readable(base.datetime_from_unix_ms(message.publish_time.timestamp() * 1000))
    label = f'{message.message_id} (published at {published})'

    parse = decode_notification(message.data, label, err)
    if parse is None or err.has():
        # Left unacked deliberately, rather than dropped. A payload we cannot read is either a format we do
        # not understand yet or a bug, and both are better answered by a redelivery after a deploy than by
        # silence. Its history row, if one was written, keeps it replayable past Pub/Sub's retention.
        log.warning(
            f'Could not decode notification {label}: {err.build() if err.has() else "no payload type"}\n'
            f'Message was:\n{base.maybe_obfuscate(str(message.data))}'
        )
        message.nack()
        return

    try:
        with db.connection() as conn:
            with db.transaction(conn) as tx:
                # BEFORE handling, because `_process_notification_message` reads an absent row as "handled"
                # (someone cleared it out-of-band) and acks. A message that reaches processing without its
                # row would therefore be acked unprocessed, and an acked notification is never redelivered.
                #
                # Stored as JSON because a message that needs this row needs a human to read it. `event_at`
                # is Google's own instant, verbatim: the prune applies our retention window to it on read.
                backend.google_add_notification_id(
                    tx,
                    message_id=message.message_id,
                    event_at=base.datetime_from_unix_ms(parse.event_time_ms),
                    payload=json.dumps({'data': message.data.decode('utf-8', errors='replace')}),
                )

            sorted_msg = SortedMessage(
                event_unix_ts_ms=parse.event_time_ms, message_id=message.message_id, parse=parse, raw=message
            )
            handled = _process_notification_message(conn, sorted_msg, err, time.time())
    except Exception:
        log.error(f'Failed to handle notification {label}. Error was {traceback.format_exc()}')
        message.nack()
        return

    if handled:
        message.ack()
    else:
        log.error(f'Failed to handle notification {label}. Reason was:\n{err.build()}')
        message.nack()


def _replay_unhandled_backlog() -> None:
    """Re-run notifications recorded but never handled, once, at subscriber startup.

    Not redundant with Pub/Sub redelivery, which covers the same ground for seven days: past that the
    history row is the only copy of the message anywhere, and this is the only thing that replays it. That
    is what makes "ship the fix weeks later, restart, and the backlog applies itself" true -- which this
    project has already relied on once, for notifications that wedged on an unrecognised base plan.

    Guarded as a whole and per row, because this thread is a daemon started once per mule: an exception
    escaping here kills it silently and Google processing is off until somebody reloads. Replaying less than
    everything is survivable in a way that not running at all is not.
    """
    replayed = 0
    try:
        with db.connection() as conn:
            with db.transaction(conn) as tx:
                rows = list(backend.google_get_unhandled_notification_iterator(tx))

            for row in rows:
                message_id, payload = row[0], row[1]
                if not payload:
                    continue

                err = base.ErrorSink()
                try:
                    stored = json.loads(payload)
                    data = stored['data'].encode('utf-8') if isinstance(stored, dict) and 'data' in stored else None
                except Exception:
                    log.warning(f'Skipping stored notification {message_id}: its envelope no longer decodes.')
                    continue
                if data is None:
                    log.warning(f'Skipping stored notification {message_id}: no payload recorded.')
                    continue

                parse = decode_notification(data, f'stored notification {message_id}', err)
                if parse is None or err.has():
                    # Left unhandled rather than marked done. A failed parse carries payload_type Nil, which
                    # handle_parsed_notification treats as nothing-to-do and reports as SUCCESS -- so this
                    # is how a notification we never understood would disappear silently.
                    log.warning(
                        f'Skipping stored notification {message_id}, leaving it unhandled: '
                        f'{err.build() if err.has() else "payload could not be decoded"}'
                    )
                    continue

                # No ack path: any stored ack_id is long dead, and a message still live at Pub/Sub is
                # redelivered anyway and acked by the dedup once this marks it handled.
                msg = SortedMessage(event_unix_ts_ms=parse.event_time_ms, message_id=message_id, parse=parse)
                if _process_notification_message(conn, msg, err, time.time()):
                    replayed += 1
    except Exception:
        log.error(f'Failed to replay the unhandled notification backlog. Reason was:\n{traceback.format_exc()}')

    if replayed:
        log.info(f'Replayed {replayed} unhandled notification(s) from the DB')


def require_obfuscated_external_account_id(
    tx_event: SubscriptionPlanEventTransaction, tx: db.SQLTransaction, err: base.ErrorSink
) -> bytes:
    """The account this purchase belongs to, as the 32-byte master-pkey hash our attribution keys on.

    Normally the purchase carries it, because our billing flow calls setObfuscatedAccountId. One documented
    case does not: a resubscribe after the previous subscription expired COMPLETELY is a brand new purchase
    with no `linkedPurchaseToken` -- Play states that explicitly -- and if it was not made through our app
    there was no opportunity to set an account id on it. Play's answer is `outOfAppPurchaseContext`, which
    carries the identifiers from the EXPIRED subscription, "present exclusively for unacknowledged
    resubscription purchases".

    So that value is the fallback rather than a nicety. Without it the chain is: no id -> this reports ->
    the caller returns before registering the payment -> `needs_ack` is never written -> the ack sweep never
    acknowledges it -> Google auto-refunds at three days. The user pays, gets nothing, and is refunded
    without either side being told why.

    Preferring the purchase's own id keeps the fallback from ever overriding a current fact with a
    historical one -- it is only consulted when the present is silent.

    One case this attributes WRONGLY, accepted: a user who lost their Session identity between subscriptions
    resubscribes, and the expired subscription names the master pkey they no longer hold, so the payment
    waits for keys that may not exist. It is the narrow intersection of two uncommon events, it is what Play
    prescribes, and a support-minted voucher covers it -- but it is why this is documented in
    `docs/limitations.md` rather than left for someone to discover as a mystery.

    The identifiers are also TRANSIENT: `outOfAppPurchaseContext` is present only while the purchase is
    unacknowledged. Attribution must therefore happen before the acknowledgement, which is the order the
    caller uses -- register (flagging needs_ack), then let the sweep acknowledge. Anything that acknowledged
    first would destroy the only evidence of ownership permanently.
    """
    account_id_hex = tx_event.obfuscated_external_account_id
    source = 'the purchase'
    if account_id_hex is None:
        account_id_hex = tx_event.expired_obfuscated_external_account_id
        source = 'the expired subscription it resubscribes (outOfAppPurchaseContext)'
        if account_id_hex is not None:
            log.info(f'Attributing a resubscription from {source}: the purchase itself carries no account id')

    # Deeper still: the expired subscription may never have carried an account id either, in which case the
    # token is all that is left. Our own record answers what the store cannot, because redemption bound that
    # old row to its owner regardless of what Google knew about it.
    if account_id_hex is None and tx_event.expired_purchase_token is not None:
        owner = backend.google_owner_of_purchase_token(tx, tx_event.expired_purchase_token)
        if owner is not None:
            log.info(
                'Attributing a resubscription through the expired purchase token: neither the purchase nor '
                'the expired subscription carries an account id'
            )
            return owner

    result: bytes = b''
    if account_id_hex is None:
        # Left unattributed on purpose. Google auto-refunds a purchase left unacknowledged for three days,
        # and since nothing here registers a row, nothing ever flags it for acknowledgement — so an
        # unattributable purchase ends in the store making the user whole. That is a better outcome than
        # acknowledging it and stranding paid money in a row no account can ever claim.
        err.msg_list.append(
            'Google user submitted a payment and did not set a setObfuscatedAccountId, and neither the '
            'expired subscription it resubscribes nor our record of it identifies an owner; payment will '
            'not be attributed to the user'
        )
    else:
        if account_id_hex.startswith('0x'):
            account_id_hex = account_id_hex[2:]

        if len(account_id_hex) != 64:
            err.msg_list.append(
                f'Google account id from {source} is not a 32 byte hash, received: {len(account_id_hex)/2}b'
            )

        try:
            result = bytes.fromhex(account_id_hex)
        except Exception:
            err.msg_list.append(f'Google account id from {source} could not be parsed from hex into bytes')
    return result


# How many tokens one drain pass claims. Bounds the DB read and, more importantly, the number of Google API
# calls a single pass can make; the rest simply wait for the next one.
RECONCILE_BATCH_LIMIT = 32

# How long a claimed token is held. DERIVED, not chosen: the pass is serial, so its worst case is every
# token in the batch taking a full socket timeout, and a lease shorter than that expires under the worker
# still holding it -- handing live tokens to the next pass, which is the exact race the lease exists to
# prevent. Doubled for the DB work between fetches and for a slow host. Change either input and this
# follows; pick them independently and they drift apart silently, which is how the first version of this
# ended up with a 5 minute lease over an 8 minute worst case.
RECONCILE_LEASE = pendulum.duration(seconds=2 * RECONCILE_BATCH_LIMIT * api.SOCKET_TIMEOUT_S)

# Backoff after a failed reconcile, doubling per consecutive failure to a ceiling. The ceiling matters more
# than the curve: a token that is permanently unreconcilable must not consume a claim slot on every pass,
# because the claim is ordered by eligible_at and a limited batch would otherwise let stuck tokens crowd out
# newly-arrived work indefinitely.
RECONCILE_RETRY_MIN = pendulum.duration(minutes=1)
RECONCILE_RETRY_MAX = pendulum.duration(hours=6)

# Attempts before the drain stops retrying a token and parks it for manual review (see `parked_at`, added
# by migration 008_google_convergence).
#
# 36 is about a week of wall clock: the doubling reaches the six-hour ceiling by the tenth attempt, having
# spent ~14 h getting there, and the remaining 26 attempts are six hours each. A week is chosen against two
# other clocks rather than picked round — it outlives Pub/Sub's 7-day message retention, so a token still
# failing has outlived the notification that created it, and it is well past the three days after which
# Google auto-refunds an unacknowledged purchase, so the subscriber has already been made whole. Retrying
# past that point cannot help them; it only spends quota and crowds the queue.
RECONCILE_MAX_ATTEMPTS = 36

# Attempts before a token is reported as stuck rather than merely retrying. Two failures are a blip — a
# hung fetch, a momentary DB error — and the backoff absorbs them silently. By the fifth, roughly half an
# hour in, something is wrong that will not fix itself, and the operator should hear about it long before
# the token is parked a week later.
RECONCILE_STUCK_ATTEMPTS = 5

# Google auto-refunds a purchase left unacknowledged for this long and revokes the entitlement with it:
# "must be done within three days so that the purchase isn't automatically refunded and entitlement revoked"
# -- https://developer.android.com/google/play/billing/integrate
ACK_DEADLINE = 3 * base.DAY

# When a failing acknowledgement stops being a blip and becomes an emergency. Two thirds of the way to the
# deadline leaves a full day to act, and the sweep runs on every subscriber wake, so the alert repeats.
ACK_DEADLINE_ALERT_AFTER = 2 * base.DAY


def reconcile_retry_delay(attempts: int) -> pendulum.Duration:
    """Exponential backoff, bounded. `attempts` counts failures BEFORE this one."""
    doubled = RECONCILE_RETRY_MIN * (2 ** min(attempts, 16))
    return doubled if doubled < RECONCILE_RETRY_MAX else RECONCILE_RETRY_MAX


def drain_due_reconciles(at: pendulum.DateTime) -> int:
    """Reconcile every token whose turn has come, and report how many were attempted.

    The claim and the work are deliberately in SEPARATE transactions. Reconciling makes a Play API call, and
    holding row locks across an external request would pin a transaction open for its duration; the lease
    taken at claim time is what protects the token instead. A pass that dies mid-fetch therefore leaves the
    lease to lapse and the token comes due again on its own.

    Each token then gets its own transaction, so one failure is logged and skipped rather than costing the
    batch — the same rule the notification handlers follow, and for the same reason: these are unrelated
    subscriptions that happen to be due at the same moment.
    """
    with db.connection() as conn:
        with db.transaction(conn) as tx:
            claims = backend.google_claim_due_reconciles(
                tx, now=at, lease_until=at + RECONCILE_LEASE, limit=RECONCILE_BATCH_LIMIT
            )

    for claim in claims:
        err = base.ErrorSink()
        try:
            log.debug(f'Reconciling {base.maybe_obfuscate(claim.payment_token)} (attempt {claim.attempts + 1})')
            # Outside any transaction, on purpose. See above.
            details = api.fetch_subscription_v2_details(api.package_name, claim.payment_token, err)
            if err.has() or details is None:
                err.msg_list.append('Failed to fetch subscription V2 details from Google')
            else:
                with db.connection() as conn:
                    with db.transaction(conn) as tx:
                        reconcile_google_subscription(
                            tx, purchase_token=claim.payment_token, details=details, at=at, err=err
                        )
                        if err.has():
                            tx.cancel = True
        except Exception:
            err.msg_list.append(f'Reconcile raised: {traceback.format_exc()}')

        with db.connection() as conn:
            with db.transaction(conn) as tx:
                if err.has():
                    retry_at = at + reconcile_retry_delay(claim.attempts)
                    attempt = claim.attempts + 1
                    park = attempt >= RECONCILE_MAX_ATTEMPTS
                    token_label = base.maybe_obfuscate(claim.payment_token)
                    if park:
                        # The loudest thing this module says, because it is the end of the line: a purchase
                        # that will now never register unless a human intervenes. The token is retained, so
                        # clearing `parked_at` re-queues it once whatever broke is fixed.
                        log.critical(
                            f'Reconcile PARKED for {token_label} after {attempt} attempts — this purchase '
                            f'will not register without intervention. Last error: {err.build()}'
                        )
                    elif attempt >= RECONCILE_STUCK_ATTEMPTS:
                        log.error(
                            f'Reconcile STUCK for {token_label} (attempt {attempt} of '
                            f'{RECONCILE_MAX_ATTEMPTS}, retrying at {base.readable(retry_at)}): {err.build()}'
                        )
                    else:
                        log.warning(
                            f'Reconcile failed for {token_label} '
                            f'(attempt {attempt}, retrying at {base.readable(retry_at)}): {err.build()}'
                        )
                    backend.google_reconcile_failed(tx, claim, retry_at=retry_at, error=err.build(), park=park)
                else:
                    backend.google_reconcile_done(tx, claim)

    return len(claims)


def reconcile_google_subscription(
    tx: db.SQLTransaction, purchase_token: str, details: SubscriptionV2Data, at: pendulum.DateTime, err: base.ErrorSink
) -> None:
    """Bring our record of one purchase token into line with the subscription resource Google just gave us.

    The whole of the type dispatch collapses into this. A notification says only "something about this
    subscription changed"; the resource says what it now IS, and every field the old per-type branches wrote
    is in it — the term, whether it renews, whether it still owes an acknowledgement, which plan it is on.
    So there is nothing for a PURCHASED branch to do that a RENEWED branch would not, and nothing for either
    to do that is not simply "write down what the store says".

    Consequences worth stating, because they are what the old shape got wrong:

    * A notification arriving for a state that has since moved on is harmless. It triggers a fetch, the fetch
      returns the CURRENT resource, and we converge on that. Order stops mattering, because nothing here
      applies a delta.
    * A purchase is never dropped for arriving late. The old PURCHASED branch required the snapshot to still
      read ACTIVE and silently did nothing otherwise, so a purchase followed quickly by a cancellation
      registered nothing at all.
    * A revoked row stays revoked: `google_converge_payment` will not touch one, so a resource that still
      describes the subscription cannot resurrect it.

    `linked_purchase_token` is handled by marking the OLD token dirty rather than acting on it here. Its
    resource is the authority on what became of it, exactly as this one is, and we are not holding it.
    """
    line_item = api.parse_line_item(details, err)
    payment_tx = api.parse_subscription_purchase_tx(purchase_token=purchase_token, details=details, err=err)
    tx_event = api.parse_subscription_plan_event_tx(
        details, base.unix_ms_from_datetime(at), SubscriptionNotificationType.UNKNOWN, err=err
    )
    if err.has() or line_item is None:
        err.msg_list.append('Failed to read the subscription resource well enough to reconcile it')
        return

    # Straight from the resource rather than inferred from why we were woken: a plan that does not renew
    # says so here, and a plan that is not auto-renewing at all (prepaid) has no such block.
    auto_renewing = line_item.auto_renewing_plan is not None and line_item.auto_renewing_plan.auto_renew_enabled

    # Nothing here reads the base plan's grace period. Play applies grace by EXTENDING `expiryTime`, so a
    # subscription in grace already states its grace-inclusive end above and converging that captures it —
    # whether or not the notification that woke us was the IN_GRACE_PERIOD one. Fetching the plan to store
    # the number separately used to make the same span arrive twice, once inside the expiry and once beside
    # it, with nothing marking which of the two the column held.
    needs_ack = tx_event.purchase_acknowledged != SubscriptionsV2AcknowledgementState.ACKNOWLEDGED
    expiry_at = base.datetime_from_unix_ms(tx_event.expiry_time.unix_milliseconds)

    # From the resource's own state, never from the notification type. A grace-extended `expiryTime` is
    # indistinguishable from any other extension by its value alone, so this is what lets the converge keep
    # the paid term and record the extension beside it rather than overwriting one with the other.
    in_grace = tx_event.subscription_state == SubscriptionsV2State.IN_GRACE_PERIOD

    # The resource as fetched, before anything is written from it: the input to every decision below, and
    # the only record of what the store actually said if a converge later looks wrong.
    log.debug(
        f'Subscription resource for {base.maybe_obfuscate(purchase_token)}: '
        f'{reflect_enum(tx_event.subscription_state)}, plan={tx_event.pro_plan.name}, '
        f'expiry={base.readable(expiry_at)}, auto_renewing={auto_renewing}, needs_ack={needs_ack}'
    )

    converged = backend.google_converge_payment(
        tx,
        payment_tx=payment_tx,
        expiry_at=expiry_at,
        auto_renewing=auto_renewing,
        in_grace=in_grace,
        needs_ack=needs_ack,
        at=at,
        err=err,
    )
    if err.has():
        return

    if not converged:
        # No row for this (token, order id): either a cycle we have never seen, or one whose row is revoked
        # and therefore terminal. add_unredeemed_payment dedups on the same pair, so the revoked case is a
        # no-op rather than a resurrection.
        obfuscated_external_account_id = require_obfuscated_external_account_id(tx_event, tx, err)
        if err.has():
            return
        backend.add_unredeemed_payment(
            tx,
            payment_tx=payment_tx,
            plan=tx_event.pro_plan,
            expiry_at=expiry_at,
            # `at` stands in for the instant the cycle was bought. A snapshot does not carry a per-cycle
            # purchase time — only the subscription's own start_time — so reconciling a cycle whose
            # notification we never saw dates it from when we noticed. It feeds the refund deadline and the
            # payment's displayed purchase date, never entitlement, which comes from expiry_at.
            purchased_at=at,
            platform_refund_expiry_at=base.datetime_from_unix_ms(
                base.unix_ms_from_datetime(at) + api.refund_deadline_duration_ms
            ),
            platform_obfuscated_account_id=obfuscated_external_account_id,
            err=err,
            needs_ack=needs_ack,
            auto_renewing=auto_renewing,
        )
        if err.has():
            return

    if tx_event.linked_purchase_token is not None:
        # Superseded, not refunded. The old token's own resource is the authority on what became of it, and
        # it is the only place that says so — Google sends no further notification for a token it has
        # replaced, so this marker is our sole chance to learn the subscription needs revisiting. Enqueued
        # rather than acted on inline, because judging an account mid-write is what made the old path revoke
        # a subscriber for upgrading.
        backend.google_enqueue_reconcile(tx, payment_token=tx_event.linked_purchase_token, eligible_at=at)


def handle_voided_notification(tx: VoidedPurchaseTxFields, err: base.ErrorSink):
    # Reported, never asserted, and with a default arm on each match — the same treatment the plan mappers
    # and the subscription match received. It matters more here than it looks: NIL is 0 and IS an enum
    # member, so `productType: 0` coerces cleanly at parse and arrives intact, which made the asserts this
    # replaced reachable from the wire rather than being the impossible-state guards they were written as.
    # They were harmless only while the whole function was unreachable dead code.
    match tx.product_type:
        case ProductType.SUBSCRIPTION:
            match tx.refund_type:
                case RefundType.FULL_REFUND:
                    # A deliberate no-op: subscription revocation arrives separately, as SUBSCRIPTION_REVOKED.
                    pass
                case RefundType.QUANTITY_BASED_PARTIAL_REFUND:
                    err.msg_list.append(f'voided purchase refundType {reflect_enum(tx.refund_type)} is unsupported!')
                case _:
                    err.msg_list.append(
                        f'voided purchase of a subscription has refundType {reflect_enum(tx.refund_type)}, '
                        f'which is not handled!'
                    )
        case ProductType.ONE_TIME:
            err.msg_list.append(f'voided purchase productType {reflect_enum(tx.product_type)} is unsupported!')
        case _:
            err.msg_list.append(f'voided purchase productType {reflect_enum(tx.product_type)} is not handled!')

    if err.has():
        # Labelled by the pair, not by the refund type alone: a ONE_TIME failure is a product-type problem
        # and used to be reported under whatever refund type happened to accompany it.
        err.msg_list.append(
            f'Failed to handle voided purchase ' f'({reflect_enum(tx.product_type)}, {reflect_enum(tx.refund_type)})'
        )


def decode_notification(data: str | bytes, label: str, err: base.ErrorSink) -> ParsedNotification | None:
    '''JSON-decode and parse one RTDN payload, or None if it could not be decoded at all.

    The decode gets its OWN guard because both halves raise on bad input: `json.loads` on a malformed
    payload, and `parse_notification` on a voided block missing the fields its asserts require. Under the
    batched pull loop this replaced, an unguarded raise unwound to the batch handler and took the parsing,
    processing and acking of every other message in that pull with it; per-message callbacks make that
    blast radius one message, so this now buys a clean skip rather than protecting the neighbours.

    Returning None is distinct from returning a parse with `err` set: the latter decoded fine and simply is
    not a notification we accept. Neither is acked, so Google redelivers and a transient cause gets another
    chance, while a permanently undecodable message keeps failing here in isolation.
    '''
    try:
        return parse_notification(json.loads(data), err)
    except Exception:
        log.warning(f'Discarding message {label}: could not decode it.\nReason was:\n{traceback.format_exc()}')
        return None


def parse_notification(body: JSONObject, err: base.ErrorSink) -> ParsedNotification:
    result = ParsedNotification()
    result.body_version = json_dict_require_str(body, "version", err)
    result.package_name = json_dict_require_str(body, "packageName", err)
    result.event_time_ms = json_dict_require_str_coerce_to_int(body, "eventTimeMillis", err)

    if result.package_name != api.package_name:
        err.msg_list.append(
            f'{result.package_name} does not match google_package_name ' f'({api.package_name}) from the .INI file!'
        )

    subscription = json_dict_optional_obj(body, "subscriptionNotification", err)
    one_time_product = json_dict_optional_obj(body, "oneTimeProductNotification", err)
    voided_purchase = json_dict_optional_obj(body, "voidedPurchaseNotification", err)
    test_obj = json_dict_optional_obj(body, "testNotification", err)

    # Exactly one notification block must be present.
    notif_count = sum(notif is not None for notif in (subscription, one_time_product, voided_purchase, test_obj))
    if notif_count == 0:
        err.msg_list.append(
            f'No subscription notification for {result.package_name} {safe_dump_dict_keys_or_data(body)}'
        )
    elif notif_count > 1:
        err.msg_list.append(
            f'Multiple subscription notification for {result.package_name} {safe_dump_dict_keys_or_data(body)}'
        )

    if err.has():
        return result

    if subscription is not None:
        result.purchase_token = json_dict_require_str(subscription, "purchaseToken", err)
        result.payload_version = json_dict_require_str(subscription, "version", err)
        # Coerced by hand rather than through json_dict_require_int_coerce_to_enum, which ERRS on a value
        # it does not recognise. Erring here would reject a notificationType Google adds later before the
        # message is written down, so it would redeliver until retention lapsed and then be lost.
        #
        # Mapping to UNKNOWN instead means a type we have never heard of is handled correctly rather than
        # merely survived: handling does not consult the type at all any more, so the token is enqueued and
        # its resource converged exactly as for a type we do know. The value is retained only so an operator
        # reading the stored message can see what arrived.
        raw_sub_type = base.json_dict_require_int(subscription, "notificationType", err)
        result.sub_type = SubscriptionNotificationType._value2member_map_.get(  # type: ignore[assignment]
            raw_sub_type, SubscriptionNotificationType.UNKNOWN
        )
        if result.sub_type == SubscriptionNotificationType.UNKNOWN:
            log.warning(
                f'Google sent subscription notificationType {raw_sub_type}, which this backend does not '
                f'know. Handled anyway -- the type is not consulted -- and recorded here so it can be seen.'
            )
        result.payload_type = ParsedNotificationPayloadType.Subscription

    elif voided_purchase is not None:
        result.purchase_token = json_dict_require_str(voided_purchase, "purchaseToken", err)
        order_id = json_dict_require_str(voided_purchase, "orderId", err)
        product_type = json_dict_require_int_coerce_to_enum(voided_purchase, "productType", ProductType, err)
        refund_type = json_dict_require_int_coerce_to_enum(voided_purchase, "refundType", RefundType, err)

        assert (
            refund_type is not None
            and product_type is not None
            and len(result.purchase_token) > 0
            and len(order_id) > 0
            and isinstance(product_type, ProductType)
            and isinstance(refund_type, RefundType)
        )
        result.voided = VoidedPurchaseTxFields(
            purchase_token=result.purchase_token,
            order_id=order_id,
            event_ts_ms=result.event_time_ms,
            product_type=product_type,
            refund_type=refund_type,
        )
        result.payload_type = ParsedNotificationPayloadType.Voided

    elif one_time_product is not None:
        result.payload_type = ParsedNotificationPayloadType.Nil

    elif test_obj is not None:
        result.payload_type = ParsedNotificationPayloadType.Test

    return result
