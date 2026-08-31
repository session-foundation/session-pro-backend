'''
Common utilities shared by the rest of the project (and by the test suite).

This module must not import any other project module — that keeps it at the bottom of the dependency
graph, so anything may import it without risking a cycle. Third-party packages are fair game.

Instants and durations here are pendulum's `DateTime` and `Duration`, NOT the stdlib's, because stdlib
`aware_datetime + timedelta` cannot express what we mean and cannot be made to:

  - It is **wall-clock arithmetic** — the clock fields advance and the tzinfo is carried over untouched
    ("no time zone adjustments are done even if the input is an aware object", per the stdlib docs). So
    whenever the span crosses a DST transition the real elapsed time is not the duration you added. This
    is not a large-duration problem: adding 2 hours across a spring-forward advances 1 real hour, and
    adding 90 minutes can land on a local time that does not exist that day. It fails silently in all
    of these cases.
  - And you **cannot dodge it by choosing units**, because `timedelta` force-normalises on construction
    to (days, seconds, microseconds) and keeps nothing else: `timedelta(hours=24)` *is*
    `timedelta(days=1)` — equal, same repr — and `timedelta(hours=25)` is `days=1, seconds=3600`. No
    record of the original denomination survives, so there is nothing for the arithmetic to honour.

Pendulum keeps that denomination, so the distinction becomes expressible: adding a `Duration` built from
hours or smaller moves an exact span, while one built from days or larger moves a calendar step. Every
duration in this codebase is a span, so they are all built from hours or smaller — see HOUR/DAY below,
and note that scaling (`29 * DAY`) always yields an exact span.
'''

import dataclasses
import datetime
import enum
import glob
import json
import logging
import math
import os
import pathlib
import pendulum
import sys
import threading
import time
import typing
import typing_extensions
import urllib.request

# NOTE: Constants
# Backend software version, reported by the /status health endpoint. Bump on release; there is no other
# version marker in the system (the wire/proof formats are versioned separately — see the wire spec).
BACKEND_VERSION: str = '0.3.0'
SECONDS_IN_DAY: int = 60 * 60 * 24
MILLISECONDS_IN_DAY: int = 60 * 60 * 24 * 1000
MILLISECONDS_IN_MONTH: int = MILLISECONDS_IN_DAY * 30
SECONDS_IN_MONTH: int = SECONDS_IN_DAY * 30
MILLISECONDS_IN_YEAR: int = MILLISECONDS_IN_DAY * 365
SECONDS_IN_YEAR: int = SECONDS_IN_DAY * 365

# How far the timestamp in a signed request may differ from the backend's clock. This currently matches
# the storage server's store tolerance for onion-request forwarded messages as per:
#
#   https://github.com/session-foundation/session-storage-server/blob/3d159a10d465678d758131c1075c9a6e5b4d95cc/oxenss/rpc/request_handler.h#L48
#
# We choose the upper-bound of tolerance for requests for maximum compatibility. Currently, in the flask
# context, no information is available to indicate if the request was forwarded or not so we default to
# assuming it is. All platforms are designed to interact with the backend using onion requests.
#
# It is a protocol constant, not merely a server-side check: the backend's revocation-skip math
# (revoke_payments_by_id_internal) depends on the same skew bound, so both must read this one value.
DEFAULT_TIMESTAMP_TOLERANCE: pendulum.Duration = pendulum.duration(seconds=70)

# Exact-span building blocks, for composing the durations below as `29 * DAY` rather than repeating an
# hours= arithmetic expression. Built from hours because that is what makes them true elapsed time: a
# Duration built with `days=` or larger is a CALENDAR step, which a DST transition stretches or shrinks by
# an hour (module docstring). Scaling always yields an exact span, so DAY is 24 real hours and `29 * DAY`
# is 696 of them — never "the same clock time 29 days later".
HOUR: pendulum.Duration = pendulum.duration(hours=1)
DAY: pendulum.Duration = 24 * HOUR

# --- Revocation-list timings (wire spec §4). ---
# The re-poll cadence we recommend to clients, served as the list's `retry_in`. It bounds how long a
# client can go without seeing a new entry, so REVOCATION_EFFECTIVE_DELAY below is derived from it.
REVOCATION_POLL_INTERVAL: pendulum.Duration = 1 * DAY
# How long after we RECORD a revocation peers begin rejecting proofs carrying its tag. Anchored to our
# processing instant, never to the store's `revocationDate`: a stale notification (a backlog drained after
# an outage) would otherwise arrive with the delay already elapsed, so peers would enforce before the
# revoked sender could possibly have learnt of it — exactly the compose-then-truncate gap this delay
# exists to prevent. One poll interval is the floor (a client that polls on schedule sees the entry inside
# it), and the margin on top covers a poll that lands while we are down: it can be retried and still beat
# the deadline.
REVOCATION_EFFECTIVE_DELAY: pendulum.Duration = REVOCATION_POLL_INTERVAL + 2 * HOUR
# How long a revocation entry is kept (by clients, and by our own served list). Must be at least the
# maximum proof lifetime so an entry is never dropped while a proof carrying its tag could still verify
# (asserted below, once the proof-expiry shape is defined).
REVOCATION_RETAIN_FOR: pendulum.Duration = 31 * DAY

# Every instant in this codebase is a tz-aware pendulum `DateTime` and every duration a `Duration`. Integer
# epochs live ONLY in the converters below, at two kinds of boundary with distinct units:
#   - MILLISECONDS: the payment providers (Apple/Google App Store APIs) genuinely speak ms, so their
#     ingest/egress uses the `*_ms` pair.
#   - SECONDS: our own wire + proof format is seconds (the wire spec's unit), so every
#     client-facing boundary and every signed hash uses the `*_seconds` pair. Wire seconds are integer
#     everywhere except two upstream provider event instants (`purchased_ts`, `revoked_ts`) that keep
#     the provider's sub-second precision as a float via `unix_seconds_float_from_datetime` — see the
#     wire spec §1. Nothing hashed is ever a float.
# The two never mix: a value crossing the provider boundary is ms, a value crossing our wire is seconds.
EPOCH: pendulum.DateTime = pendulum.datetime(1970, 1, 1)


def datetime_from_unix_ms(unix_ms: int) -> pendulum.DateTime:
    return EPOCH + pendulum.duration(milliseconds=unix_ms)


def unix_ms_from_datetime(value: pendulum.DateTime) -> int:
    # Exact integer milliseconds via integer division — never float `.timestamp()` truncation.
    return (value - EPOCH) // pendulum.duration(milliseconds=1)


def duration_from_ms(ms: int) -> pendulum.Duration:
    return pendulum.duration(milliseconds=ms)


def ms_from_duration(value: pendulum.Duration) -> int:
    return value // pendulum.duration(milliseconds=1)


def datetime_from_unix_seconds(unix_s: int) -> pendulum.DateTime:
    return EPOCH + pendulum.duration(seconds=unix_s)


def unix_seconds_from_datetime(value: pendulum.DateTime) -> int:
    # Exact integer seconds via integer division — never float `.timestamp()` truncation. Sub-second
    # precision (a provider ms value) is floored: our wire is second-resolution by spec.
    return (value - EPOCH) // pendulum.duration(seconds=1)


def duration_from_seconds(s: int) -> pendulum.Duration:
    return pendulum.duration(seconds=s)


def seconds_from_duration(value: pendulum.Duration) -> int:
    return value // pendulum.duration(seconds=1)


def utc_now() -> pendulum.DateTime:
    '''The backend's own wall clock, as a tz-aware UTC instant.

    Deliberately distinct from the provider-supplied instants that ride inside a store notification
    (`revocationDate`, `event_ts_ms`, ...): this answers "when did *we* handle it", which is what a
    broadcast anchor must key off. Funnelled through one function so a test can pin it.
    '''
    return pendulum.now(pendulum.UTC)


def unix_seconds_float_from_datetime(value: pendulum.DateTime) -> float:
    # Fractional UNIX seconds (true division) — preserves the sub-second precision of an upstream
    # provider instant on the wire. ONLY for the enumerated float display fields (wire spec §1); never
    # for a hashed value, which must be integer seconds via `unix_seconds_from_datetime`.
    return (value - EPOCH) / pendulum.duration(seconds=1)


# How long we keep honouring a RENEWING subscription past its paid-through instant while we wait to learn
# whether it renewed. Without it a user watching their status across that boundary sees it flicker
# Pro → not-Pro → Pro as the renewal lands.
#
# This is OURS, and it is not a store grace period. A store grace period is the window a store keeps
# entitling a user while it retries a declined card — a different quantity, with a different cause, an order
# of magnitude larger (Google: 1 day, configured in the Play Console). Apple states its own separately and
# leaves its expiry untouched, so that has to be stored per payment; Google folds its own into the expiry it
# reports, so there is nothing to store. Neither is this.
#
# The distinction is load-bearing. `payments.grace_period` used to hold whichever of the two wrote last —
# this value on the purchase path, Google's dunning window on the in-grace path, differing by 24x with
# nothing marking which was present — and converging the store's already-extended expiry on top of it
# counted a subscriber's grace twice.
#
# One value across providers, because it describes OUR pipeline's latency, and our pipeline is not slower
# for Apple. Settable as `renewal_latency_allowance` in the [base] config so it can be raised ahead of
# planned maintenance.
#
# It has a FLOOR set by the clients rather than by anything on this side: every client runs a renewal timer
# one hour before expiry, and that timer must not outlast this allowance, or the client wakes to renew after
# we have stopped honouring the old term and the subscriber sees Pro flicker off. The floor holds in a
# provider testing deployment too — the same clients, the same fixed hour, however fast the store's test
# clock runs. A compressed clock changes how long a subscription lasts, not when a client wakes up.
RENEWAL_LATENCY_ALLOWANCE: pendulum.Duration = 1 * HOUR

# The span a proof-issuance count covers before it restarts. Anchored per account on the issue that opened
# the window, not on a shared grid — a rate is being measured, and nothing compares one account's window to
# another's.
#
# Seven days is long enough that a legitimate account's whole renewal cycle sits inside one window (proofs
# run to ~30 days, so a client's renewal timer fires well under once a week) and short enough that a seed
# handed to a fleet exceeds any sane cap within one. The cap itself is config — see
# `MAX_PROOFS_PER_WINDOW`, which is 0/unlimited unless an operator sets it.
PROOF_ISSUE_WINDOW: pendulum.Duration = 7 * DAY

# NOTE: Global variables
UNSAFE_LOGGING = False

# When set, every payment provider treats all of its OUTBOUND interactions as already-succeeded and
# performs no external side-effect: mutations (e.g. Google acknowledge) become no-ops and gating reads
# return a synthetic success. Each provider module owns what dry-run means for it (see providers/).
# It does NOT fabricate payments — a real witnessed payment must still exist — so it is not a "grant
# arbitrary Pro" backdoor; worst-case misuse breaks real subscriptions, it does not mint entitlements.
PROVIDER_DRY_RUN = False

# How many proofs one account may be issued per `PROOF_ISSUE_WINDOW`. 0 = unlimited, and that is the
# default: the counters are for SEEING the traffic first — a cap set before anyone has looked at real
# numbers would refuse legitimate users on a guess. Settable as `max_proofs_per_window` in the [base]
# config, applied on read so raising or lowering it takes effect without touching a stored row.
MAX_PROOFS_PER_WINDOW: int = 0


@dataclasses.dataclass(frozen=True)
class ProofExpiryShape:
    '''The three quantities that decide how far ahead a proof certifies. A proof issued at `request_at`
    against an account whose true (grace-inclusive) entitlement ends at `true` expires at

        round_up_onto_grid( min(request_at + clamp, true) + renewal_lead )

    where the grid is that account's private daily one: `{ UTC midnight + offset + k * grid }`, with
    `offset` the stored `users.proof_expiry_offset` — a uniform draw in [0, grid) re-drawn every time the
    account's true expiry moves. Protocol values (the proof builder, the revocation-skip math and the
    served revocation list all key off them); see `backend._build_proof_clamped_expiry_time` for the
    reasoning behind each.
    '''

    clamp: pendulum.Duration  # rolling cap: how far ahead a proof may reach while the sub outlives it
    renewal_lead: pendulum.Duration  # keeps a renewing client's attempt on the far side of `true`
    grid: pendulum.Duration  # expiry grid period; the per-account offset spans exactly one of these

    @property
    def offset_range(self) -> int:
        '''Exclusive upper bound on `users.proof_expiry_offset`, in seconds.'''
        return seconds_from_duration(self.grid)

    @property
    def max_proof_lifetime(self) -> pendulum.Duration:
        '''Strict upper bound on how far past its request instant a proof can reach. Not attained (the
        round-up adds strictly less than `grid`), so it is safe as an inclusive bound.'''
        return self.clamp + self.renewal_lead + self.grid


# `clamp` is 29 d rather than 30 so that the whole expression stays just over 30 d. `renewal_lead` is the
# clients' one-hour pre-expiry renewal timer plus a minute of slack, so a client that wakes to renew is
# still holding a valid proof when it does.
#
# One shape in every deployment, a store's compressed test clock included: `renewal_lead` is denominated in
# CLIENT behaviour, and a client's renewal timer is a fixed hour however fast a test subscription runs.
# Scaling it down puts the client's wake-up after the expiry of the proof it holds. Same floor, same
# reason, as RENEWAL_LATENCY_ALLOWANCE.
PROOF_EXPIRY_SHAPE: ProofExpiryShape = ProofExpiryShape(
    clamp=29 * DAY, renewal_lead=pendulum.duration(seconds=3660), grid=1 * DAY
)


assert REVOCATION_RETAIN_FOR >= PROOF_EXPIRY_SHAPE.max_proof_lifetime

# NOTE: Restricted type-set, JSON obviously supports much more than this, but
# our use-case only needs a small subset of it as of current so KISS.
JSONPrimitive: typing.TypeAlias = str | int | float | bool | None
JSONValue: typing.TypeAlias = JSONPrimitive | dict[str, 'JSONValue'] | list['JSONValue']
JSONObject: typing.TypeAlias = dict[str, JSONValue]
JSONArray: typing.TypeAlias = list[JSONValue]


@dataclasses.dataclass
class BackupRotationDryRun:
    to_keep: list[pathlib.Path] = dataclasses.field(default_factory=list)
    to_delete: list[pathlib.Path] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class PaymentProviderData:
    id: int = 0


class PaymentProvider(enum.StrEnum):
    # Values are the wire/DB `code` strings (see docs/pro-wire-protocol.md §1). Nil is an in-Python
    # sentinel only — it is never a wire value and is never seeded into the payment_providers lookup.
    Nil = 'nil'
    GooglePlayStore = 'google_play'
    iOSAppStore = 'app_store'
    SessionFoundation = 'stf'


@dataclasses.dataclass
class PaymentProviderTransaction:
    provider: PaymentProvider = PaymentProvider.Nil
    apple_original_tx_id: str = ''
    apple_tx_id: str = ''
    apple_web_line_order_tx_id: str = ''
    google_payment_token: str = ''
    google_order_id: str = ''
    stf_order_id: str = ''


class PaymentStatus(enum.StrEnum):
    # A DERIVED display value (wire/logging), NOT a stored column — computed from a payment's
    # redeemed/revoked/expiry timestamps against a caller-supplied clock (see
    # backend.derive_payment_status). Values are the wire `code`s (docs/pro-wire-protocol.md §1), and
    # only payments bound to a user have one: an unclaimed payment is the `redeemed_at IS NULL` fact,
    # tested directly, never a status.
    Redeemed = 'redeemed'
    Expired = 'expired'
    Revoked = 'revoked'


class ProPlan(enum.StrEnum):
    """Universal Pro Plan Identifier.

    Values are the wire/DB `code` strings — compact billing-period codes (see
    docs/pro-wire-protocol.md §1). Nil is an in-Python sentinel only (never a wire/DB value).
    """

    Nil = 'nil'
    OneMonth = '1m'
    ThreeMonth = '3m'
    TwelveMonth = '1y'

    @classmethod
    def from_string(cls, val: str):
        # Accept either the member name ("OneMonth") or the code value ("1m"), case-insensitively.
        val_lower = val.lower()
        for it in ProPlan:
            if it.name.lower() == val_lower or it.value == val_lower:
                return it
        return None


class LogFormatter(logging.Formatter):
    @typing_extensions.override
    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None):
        dt = datetime.datetime.fromtimestamp(record.created)
        result = dt.strftime('%y-%m-%d %H:%M:%S.%f')[:-3]
        return result


# Every logger this application writes through, by the name that appears in the log line and in the
# `[logging]` config section's `level-<name>` keys.
#
# Named, and fetched with `getLogger`, because both matter. `logging.Logger('X')` builds an object OUTSIDE
# the logging manager's registry, so a second `logging.Logger('X')` elsewhere is a DIFFERENT logger with the
# same name -- which is what `main.py` and `maintenance.py` each had for 'PRO'. Nothing could configure them
# both, and their level stayed NOTSET, which is why every level was on regardless of intent.
LOG_CATEGORIES: tuple[str, ...] = ('pro', 'backend', 'google_play', 'app_store')

LOG_FORMAT = '%(asctime)s %(levelname)s %(name)s %(message)s'


def install_log_handler(logger: logging.Logger, level: int, use_colour: bool = True) -> None:
    '''Give one logger a console handler at `level`, replacing whatever it had.

    Handlers are cleared first, unconditionally: startup attaches a bootstrap handler before the config is
    read -- otherwise a config error would have nowhere to go -- and the mule inherits the master's handlers
    across the fork, so without this a line is emitted once per accumulated handler.

    Used for Flask's `app.logger` as well as our own categories, which is why it takes a logger rather than
    a name: that one is created by the app factory and named after the import path.'''
    logger.handlers.clear()
    if use_colour:
        import coloredlogs

        coloredlogs.install(logger=logger, level=level, fmt=LOG_FORMAT, milliseconds=True, isatty=True)
    else:
        handler = logging.StreamHandler()
        handler.setFormatter(LogFormatter(LOG_FORMAT))
        logger.addHandler(handler)
    logger.setLevel(level)


def bootstrap_logging() -> None:
    '''Minimal handlers so a failure BEFORE the config is read has somewhere to go.

    `configure_logging` replaces whatever this installed once the config is known, so the only lines that
    ever come out of here are startup errors -- which is why it is unconditional and unconfigurable.'''
    handler = logging.StreamHandler()
    handler.setFormatter(LogFormatter(LOG_FORMAT))
    for name in LOG_CATEGORIES:
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.addHandler(handler)


def configure_logging(default_level: int, per_logger_levels: dict[str, int], use_colour: bool = True) -> None:
    '''Install log handlers and apply levels. Call once, as soon as the config has been read.

    `per_logger_levels` overrides `default_level` for a named logger, and is not restricted to this
    application's own categories -- `level-werkzeug = error` works, which is the point of keying it on the
    logger name rather than a fixed enum.

    Colour goes through coloredlogs with `isatty=True`, matching session-pysogs: under uWSGI the vassal's
    `logto` captures stderr into a file, so the escapes end up in the log rather than on a terminal, which is
    what `tail`/`less -R` want anyway. Set `use_colour=False` for a consumer that cannot cope.
    '''
    for name in LOG_CATEGORIES:
        install_log_handler(logging.getLogger(name), per_logger_levels.get(name, default_level), use_colour)

    # Anything named that is not one of ours: third-party loggers an operator wants turned up or down.
    for name, level in per_logger_levels.items():
        if name not in LOG_CATEGORIES:
            logging.getLogger(name).setLevel(level)


@dataclasses.dataclass
class ErrorSink:
    '''
    Helper class to pass to functions that want to return error messages without unwinding the stack
    by using throwing exceptions.

    The typical pattern in that this construct is used is calling a sequence of functions that can
    error but have no dependency on each other. Errors are accumulated into the sink and checked at
    the end where it reports the error from the sink and returns a failure if there is one.

    See the parsing code in server.py for an example of where this is useful.
    '''

    msg_list: list[str] = dataclasses.field(default_factory=list)

    def has(self) -> bool:
        result = len(self.msg_list) > 0
        return result

    def build(self) -> str:
        result = '\n  '.join(self.msg_list)
        return result


class ErrorCode(enum.StrEnum):
    '''Machine slugs for the response envelope's `error_code` (wire spec §5.1). Stable, additive: a client
    keys its localized (Crowdin) message off these; an unrecognised one degrades to status-level handling.'''

    invalid_request = 'invalid_request'  # fail:  malformed/missing/wrong-type field, bad hex, bad provider
    bad_signature = 'bad_signature'  # fail:  a request signature failed to verify
    stale_request = 'stale_request'  # fail:  request timestamp outside the replay-tolerance window
    # NB: `subscription_expired`, NOT `expired` — the error_code vocabulary is deliberately DISJOINT from
    # get-details `user_status` {never,active,expired}, so no token identifies two different fields.
    subscription_expired = 'subscription_expired'  # fail:  the user's entitlement has lapsed
    not_subscribed = 'not_subscribed'  # fail:  no entitlement on record (never subscribed / pruned)
    revoked = 'revoked'  # fail:  the user's current entitlement was revoked
    rate_limited = 'rate_limited'  # fail:  too many proofs issued to this account this window
    internal_error = 'internal_error'  # error: backend fault


class ApiError(Exception):
    '''An error that renders as a response envelope `{status, error_code, error}` (server.py's error
    handler catches it). Raise these instead of threading an ErrorSink through the HTTP request path.'''

    wire_status: str = 'error'
    default_code: ErrorCode = ErrorCode.internal_error

    def __init__(self, message: str, code: ErrorCode | None = None, data: dict[str, typing.Any] | None = None):
        super().__init__(message)
        self.code: ErrorCode = code if code is not None else self.default_code
        # Optional extra top-level fields the error handler merges into the response envelope alongside
        # {status, error_code, error} — e.g. a subscription_expired fail carrying `account_expiry_ts` so
        # the client can refresh its cached horizon without a separate get_pro_status. Empty by default.
        self.data: dict[str, typing.Any] = data if data is not None else {}


class FailError(ApiError):
    '''The request was understood but rejected by the client's input or a state precondition (wire
    `status: "fail"`). Default slug `invalid_request`; pass a more specific `code` where one applies.'''

    wire_status = 'fail'
    default_code = ErrorCode.invalid_request


class ServerError(ApiError):
    '''The backend faulted handling the request (wire `status: "error"`). The client did nothing wrong.'''

    wire_status = 'error'
    default_code = ErrorCode.internal_error


@dataclasses.dataclass
class TableStrings:
    name: str = ''
    contents: list[list[str]] = dataclasses.field(default_factory=list)


class AsyncSessionWebhookLogHandler(logging.Handler):
    webhook_url: str
    display_name: str
    _submit_thread: threading.Thread
    timeout: int = 2

    def __init__(self, url: str, name: str):
        super().__init__()
        self.webhook_url = url
        self.display_name = name
        assert len(self.display_name) <= 100, f'Display name must be less than 100 characters: {len(self.display_name)}'
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._queue_dirtied = threading.Event()
        self.msg_queue: list[str] = []
        self._submit_thread = threading.Thread(target=self._worker, daemon=True)
        self._stop_event = threading.Event()
        self._submit_thread.start()

    def emit_text(self, text: str, date_prefix: bool = True):
        prefix: str = ''
        if date_prefix:
            date = datetime.datetime.fromtimestamp(time.time())
            prefix = date.strftime('%y-%m-%d %H:%M:%S.%f')[:-3]

        max_size = 128
        with self._lock:
            if len(self.msg_queue) >= max_size:
                self.msg_queue = self.msg_queue[-(max_size - 2) :]
                self.msg_queue.append(f"{prefix} Message queue was full, overwriting old message")
            self.msg_queue.append(f"{prefix} {text}"[:2000])
        self._queue_dirtied.set()

    @typing_extensions.override
    def emit(self, record: logging.LogRecord):
        if record.levelno < logging.WARNING:
            return
        self.emit_text(self.format(record)[:2000], date_prefix=False)

    def _worker(self):
        while True:
            self._queue_dirtied.wait()
            if self._stop_event.is_set():
                break
            self._queue_dirtied.clear()

            # Extract batch of messages to send with lock
            while True:
                batch: list[str] = []
                with self._lock:
                    batch_size = min(len(self.msg_queue), 8)  # Pump at most, 8 at a time then yield
                    batch = self.msg_queue[:batch_size]
                    self.msg_queue = self.msg_queue[batch_size:]

                for it in batch:  # Blocking send
                    payload: dict[str, str] = {"text": "```\n" + it + "\n```", "display_name": self.display_name}
                    request = urllib.request.Request(
                        self.webhook_url,
                        data=json.dumps(payload).encode('utf-8'),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    try:
                        urllib.request.urlopen(request, timeout=self.timeout)
                    except Exception as e:
                        print(f"Session webhook send failed: {e}", file=sys.stderr)

                with self._lock:
                    if len(self.msg_queue) == 0:
                        break

    @typing_extensions.override
    def close(self):
        self._stop_event.set()
        self._queue_dirtied.set()
        if self._submit_thread.is_alive():
            self._submit_thread.join(timeout=2)
        super().close()


def verify_payment_provider(payment_provider: PaymentProvider | str, err: ErrorSink | None = None) -> bool:
    if isinstance(payment_provider, PaymentProvider):
        provider = payment_provider
    else:
        try:
            provider = PaymentProvider(payment_provider)
        except ValueError:
            _require_fail('Unrecognised payment provider: {}'.format(payment_provider), err)
            return False

    if provider == PaymentProvider.Nil:
        _require_fail('Nil payment provider is invalid, must be set to a provider', err)
        return False

    return True


def hex_to_bytes(hex: str, label: str, hex_len: int, err: ErrorSink | None = None) -> bytes:
    if len(hex) != hex_len:
        _require_fail(f'{label} was not {hex_len} characters, was {len(hex)} characters', err)
        return b''
    try:
        return bytes.fromhex(hex)
    except Exception as e:
        _require_fail(f'{label} was not valid hex: {e}', err)
    return b''


def readable(value: pendulum.DateTime) -> str:
    # Compact UTC timestamp for logs, millisecond precision (no strftime %f-slice hack).
    return value.astimezone(pendulum.UTC).isoformat(sep=' ', timespec='milliseconds')


def round_datetime_up_onto_offset_grid(
    value: pendulum.DateTime, period: pendulum.Duration, offset_seconds: int
) -> pendulum.DateTime:
    '''Ceil `value` onto the grid `{ EPOCH + offset_seconds + k * period }`.

    EPOCH is itself a UTC midnight, so with a one-day period this is "the next UTC midnight shifted by
    `offset_seconds`" — the per-account proof-expiry grid (see ProofExpiryShape). A value already exactly on
    the grid stays put, matching round_datetime_to_next_day. `offset_seconds` is reduced modulo the period
    so an offset drawn against a wider period (a database written before the period changed) still names a
    real grid point. The result is always a whole second, since both the origin and the period are.
    '''
    origin = EPOCH + pendulum.duration(seconds=offset_seconds % seconds_from_duration(period))
    units = -((-(value - origin)) // period)  # ceil-divide the duration
    return origin + units * period


def format_bytes(size: int):
    units = [(1 << 40, 'TB'), (1 << 30, 'GB'), (1 << 20, 'MB'), (1 << 10, 'kB'), (1, 'B')]
    for base, prefix in units:
        if size >= base:
            formatted_size = size / base
            return f'{formatted_size:.2f} {prefix}'
    return '0.00 B'


def format_seconds(duration_s: float) -> str:
    hours = int(duration_s // 3600)
    minutes = int((duration_s % 3600) // 60)
    seconds = duration_s % 60
    result = ''
    if hours > 0:
        result += f"{hours}h"
    if minutes > 0:
        result += f"{' ' if result else ''}{minutes}m"
    # For seconds: show decimals only if there's a fractional part
    if seconds >= 1 or result == '':  # Always show seconds if no higher units
        if seconds == int(seconds):
            sec_str = str(int(seconds))
        else:
            # Show up to 3 decimal places, strip trailing zeros
            sec_str = f"{seconds:.3f}".rstrip('0').rstrip('.')
        result += f"{' ' if result else ''}{sec_str}s"
    return result if result else '0s'


def obfuscate(val: str) -> str:
    """
    Obfuscate a string by masking the contents preserving the prefix and suffix. If the string is
    less than 3 characters, the original string is retuned.
    """
    if len(val) < 3:
        return val
    n_ends = max(math.floor(len(val) * 0.3), 1)
    return f"{val[:n_ends]}…{val[-n_ends:]}"


def maybe_obfuscate(val: typing.Any) -> str:
    if UNSAFE_LOGGING:
        return str(val) if val is not None else 'None'
    if val is None:
        return 'None'
    return obfuscate(str(val))


def maybe_obfuscate_bytes(val: typing.Any) -> str:
    return maybe_obfuscate(bytes(val).hex())


def payment_provider_tx_to_safe_string(tx: PaymentProviderTransaction) -> str:
    # Only the active provider's ids are populated; show just those rather than dumping every
    # provider's (mostly-empty) fields.
    match tx.provider:
        case PaymentProvider.iOSAppStore:
            detail = (
                f"apple(orig/tx/web)=({maybe_obfuscate(tx.apple_original_tx_id)}/"
                f"{maybe_obfuscate(tx.apple_tx_id)}/{maybe_obfuscate(tx.apple_web_line_order_tx_id)})"
            )
        case PaymentProvider.GooglePlayStore:
            detail = f"google=({maybe_obfuscate(tx.google_payment_token)}/{maybe_obfuscate(tx.google_order_id)})"
        case PaymentProvider.SessionFoundation:
            detail = f"stf={maybe_obfuscate(tx.stf_order_id)}"
        case _:
            detail = "(no provider ids)"
    return f"{tx.provider.name}, {detail}"


def reflect_enum(enum_value: enum.Enum) -> str:
    name = enum_value.name
    value = None
    if isinstance(enum_value, enum.IntEnum):
        value = enum_value.value
    return f'{name} ({value})' if value is not None else name


def extract_keys_recursive(d: dict[str, typing.Any]) -> str:
    """
    Recursively extract keys from a nested dictionary and format them.

    Args:
        d: Dictionary to extract keys from

    Returns:
        The keys as a comma-separated string, nested dicts shown as `key: {subkeys}`, e.g.
        "key1, key2: {subkey1, subkey2}, key3: {subkey: {subsubkey}}". No outer braces — the
        caller wraps them (see safe_dump_dict_keys_or_data).
    """

    return ", ".join(
        f"{key}: {{{extract_keys_recursive(value)}}}" if isinstance(value, dict) else key for key, value in d.items()
    )


def safe_dump_dict_keys_or_data(d: dict[str, typing.Any] | None) -> str:
    """Dump the dict or just the keys if UNSAFE_LOGGING is set"""
    if d is None:
        return "None"
    if UNSAFE_LOGGING:
        return json.dumps(d)
    return "dictionary w/ keys: {" + extract_keys_recursive(d) + "}"


def safe_dump_arbitrary_value_or_type(v: typing.Any) -> str:
    """Dump the value or just its type if UNSAFE_LOGGING is set"""
    result = f'({type(v)}) {v}' if UNSAFE_LOGGING else f'{type(v)}'
    return result


def safe_get_dict_value_type(d: dict[str, typing.Any], key: str) -> str:
    v = d.get(key)
    return safe_dump_arbitrary_value_or_type(v)


# Typed JSON accessors. Two callers, two error models, ONE branch point (`_require_fail`): the HTTP
# request path (server.py) omits `err` → the first bad field raises a client-facing FailError; the
# provider-notification parsers (providers.google_play*) pass an `err` sink → errors accumulate. (The `err`
# arm is transitional — it retires when google_play's error flow moves to exceptions in the
# ErrorSink-removal sweep; see the refactor plan.)
def _require_fail(msg: str, err: ErrorSink | None) -> None:
    if err is not None:
        err.msg_list.append(msg)
    else:
        raise FailError(msg, code=ErrorCode.invalid_request)


# A JSON bool is-a int in Python; exclude it so `true` never satisfies an int/number field.
def _json_is_int(v: typing.Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _json_is_number(v: typing.Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


# Single core for every typed accessor below: `ok` tests the value, `convert` normalises it. `required`
# selects the missing-key behaviour — an error (require_*) vs. return `default` (optional_*).
def _json_get(
    d: JSONObject,
    key: str,
    type_name: str,
    ok: typing.Callable[[typing.Any], bool],
    convert: typing.Callable[[typing.Any], typing.Any],
    default: typing.Any,
    required: bool,
    err: ErrorSink | None,
) -> typing.Any:
    if key not in d:
        if required:
            _require_fail(f'Required key "{key}" is missing from JSON: {safe_dump_dict_keys_or_data(d)}', err)
        return default
    if ok(d[key]):
        return convert(d[key])
    _require_fail(f'Key "{key}" value was not {type_name}: "{safe_get_dict_value_type(d, key)}"', err)
    return default


def json_dict_require_str(d: JSONObject, key: str, err: ErrorSink | None = None) -> str:
    return _json_get(d, key, 'a string', lambda v: isinstance(v, str), lambda v: v, '', True, err)


def json_dict_require_int(d: JSONObject, key: str, err: ErrorSink | None = None) -> int:
    return _json_get(d, key, 'an integer', _json_is_int, lambda v: v, 0, True, err)


def json_dict_require_float(d: JSONObject, key: str, err: ErrorSink | None = None) -> float:
    # Accepts a JSON int or float (the wire's fractional-second fields may serialise as `X` or `X.0`).
    return _json_get(d, key, 'a number', _json_is_number, float, 0.0, True, err)


def json_dict_require_bool(d: JSONObject, key: str, err: ErrorSink | None = None) -> bool:
    return _json_get(d, key, 'a bool', lambda v: isinstance(v, bool), lambda v: v, False, True, err)


def json_dict_require_array(d: JSONObject, key: str, err: ErrorSink | None = None) -> JSONArray:
    return _json_get(d, key, 'an array', lambda v: isinstance(v, list), lambda v: v, [], True, err)


def json_dict_require_obj(d: dict[str, JSONValue], key: str, err: ErrorSink | None = None) -> JSONObject:
    return _json_get(d, key, 'an object', lambda v: isinstance(v, dict), lambda v: v, {}, True, err)


def json_dict_optional_bool(d: JSONObject, key: str, default: bool, err: ErrorSink | None = None) -> bool:
    return _json_get(d, key, 'a bool', lambda v: isinstance(v, bool), lambda v: v, default, False, err)


def json_dict_optional_str(d: JSONObject, key: str, err: ErrorSink | None = None) -> str | None:
    return _json_get(d, key, 'a string', lambda v: isinstance(v, str), lambda v: v, None, False, err)


def json_dict_optional_obj(d: JSONObject, key: str, err: ErrorSink | None = None) -> JSONObject | None:
    return _json_get(d, key, 'an object', lambda v: isinstance(v, dict), lambda v: v, None, False, err)


def json_dict_require_str_coerce_to_int(d: JSONObject, key: str, err: ErrorSink | None = None) -> int:
    result_str = json_dict_require_str(d, key, err)
    try:
        return int(result_str)
    except Exception as e:
        _require_fail(f'Unable to parse {key} type to an int: {e}', err)
    return 0


def json_dict_require_str_coerce_to_enum(
    d: JSONObject, key: str, my_enum: typing.Type[enum.StrEnum], err: ErrorSink | None = None
):
    result = my_enum._value2member_map_.get(json_dict_require_str(d, key, err))
    if result is None:
        _require_fail(f'Unable to parse {key} type to an enum', err)
    return result


def json_dict_require_int_coerce_to_enum(
    d: JSONObject, key: str, my_enum: typing.Type[enum.IntEnum], err: ErrorSink | None = None
):
    result = my_enum._value2member_map_.get(json_dict_require_int(d, key, err))
    if result is None:
        _require_fail(f'Unable to parse {key} type to an enum', err)
    return result


def validate_string_list(items: list[JSONValue]) -> typing.TypeGuard[list[str]]:
    return all(isinstance(item, str) for item in items)


def handle_not_implemented(name: str, err: ErrorSink):
    """Report a store feature we do not support, loudly.

    This is the single funnel for every dormant feature `docs/limitations.md` lists — prepaid plans,
    one-time products, partial refunds. Reaching it means a real customer bought or was refunded something
    this backend cannot process, so the ErrorSink alone is not enough: the sink tells the caller to decline
    the write, and CRITICAL tells a human that a feature was enabled in a store console without the handler
    to match. Every one of these is a paid-but-no-Pro or an unreflected refund until someone acts.
    """
    logging.getLogger('pro').critical(
        f"Unsupported store feature '{name}' was reached — a customer is affected and this needs a handler"
    )
    err.msg_list.append(f"'{name}' is not implemented!")


def os_get_boolean_env(var_name: str, default: bool = False):
    value = os.getenv(var_name, str(int(default)))  # Default to 0 or 1
    if value == '1':
        return True
    elif value == '0':
        return False
    else:
        raise ValueError(f"Invalid value for environment variable '{var_name}': {value}. Allowed values are 0 or 1.")


def backup_file_path(base_file_path: pathlib.Path, now: datetime.datetime) -> str:
    date: str = now.strftime("%Y-%m-%d_%H%M%S")
    file_name: str = base_file_path.name
    parent: pathlib.Path = base_file_path.parent
    result = str(parent / f'{date}_{file_name}.bak')
    return result


def backup_rotation_from_dated_files_dry_run(
    backup_files_listing: list[str], now: datetime.datetime
) -> BackupRotationDryRun:
    """
    Given a list of files in the format "YYYY-MM-DD_HHMMSS_<rest_of_file_name_and>.<extension>"
    return the list of those files to delete to fulfill the rotating backup criteria:

    - Keep the last 180 days worth of backups
    - AND Keep the earliest backup for each month

    The rotating date filter to all files in the list even if "<rest_of_file_name_and>.<extension>"
    are different from each other.
    """

    @dataclasses.dataclass
    class BackupItem:
        date: datetime.datetime
        path: pathlib.Path
        keep: bool = False

    # NOTE: Parse the list of on-disk backups into (year) -> (month) -> [(date, path)] entries
    year_backups: dict[int, dict[int, list[BackupItem]]] = {}
    for item in backup_files_listing:
        try:
            file_name: str = pathlib.Path(item).name  # Extract file name
            # Extract timestamp from filename of format
            # "YYYY-MM-DD_HHMMSS_<rest_of_file_name_and>.<extension>"
            expected_prefix: str = "YYYY-MM-DD_HHMMSS"
            ts_str: str = file_name[: len(expected_prefix)]
            dt = datetime.datetime.strptime(ts_str, "%Y-%m-%d_%H%M%S")  # Parse the timestamp
            if dt.year not in year_backups:
                year_backups[dt.year] = {}
            if dt.month not in year_backups[dt.year]:
                year_backups[dt.year][dt.month] = []
            year_backups[dt.year][dt.month].append(BackupItem(date=dt, path=pathlib.Path(item)))
        except Exception:
            continue  # skip malformed

    # NOTE: Sort each list of backups belonging to the (year, month)
    for year in year_backups:
        for month in year_backups[year]:
            year_backups[year][month] = sorted(year_backups[year][month], key=lambda it: it.date)

    # NOTE: Determine which backup to keep
    cutoff_unix_ts_s: int = int(now.timestamp()) - (SECONDS_IN_DAY * 180)
    for year in year_backups:
        for month in year_backups[year]:
            backups: list[BackupItem] = year_backups[year][month]

            # NOTE: If we're within the recent cutoff date, keep the file
            for backup_it in backups:
                if backup_it.date.timestamp() >= cutoff_unix_ts_s:
                    backup_it.keep = True

            # NOTE: We keep the earliest one we have for that month
            backups[0].keep = True

    # NOTE: Generate the final result (the 2 lists, keep or delete)
    result = BackupRotationDryRun()
    for year in year_backups:
        for month in year_backups[year]:
            backups = year_backups[year][month]
            for backup_it in backups:
                if backup_it.keep:
                    result.to_keep.append(backup_it.path)
                else:
                    result.to_delete.append(backup_it.path)

    return result


def backup_rotation_dry_run(base_file_path: pathlib.Path, now: datetime.datetime) -> BackupRotationDryRun:
    """
    Given a path to the file denoted by 'base_file_path' enumerate for other files in the directory
    with the format "YYYY-MM-DD_HHMMSS_<base_file_name>" and return the list of those files to
    keep and delete for the rotating backup criteria (see: dry_run_backup_rotation_from_dated_files)
    """

    backup_dir: pathlib.Path = pathlib.Path(base_file_path).parent
    backup_name: str = pathlib.Path(base_file_path).name

    # NOTE: Retrieve the list of backups
    backup_files_listing: list[str] = glob.glob(str(backup_dir / f"*_{backup_name}.bak"))
    result: BackupRotationDryRun = backup_rotation_from_dated_files_dry_run(backup_files_listing, now)
    return result
