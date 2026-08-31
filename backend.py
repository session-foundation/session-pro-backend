import nacl.signing
import pendulum
import nacl.utils
import nacl.bindings
import functools
import hashlib
import typing
import collections.abc
import dataclasses
import logging
import enum
import csv
import io

import base
import db
import migrations
import psycopg
import psycopg_pool

ZERO_BYTES32 = bytes(32)
BLAKE2B_DIGEST_SIZE = 32
log = logging.getLogger('backend')
# 16-byte domain-separation prefix on the signed MESSAGE (signatures are Ed25519 over the message
# directly — no BLAKE2b, so this is a domain prefix, not a hash personalisation; see signed_message).
DOMAIN_SIZE = 16
GENERATE_PROOF_DOMAIN = b'ProGenerateProof'
BUILD_PROOF_DOMAIN = b'ProProof_v0_____'  # the proof version lives IN the prefix, not in a signed field
GET_PAYMENT_DETAILS_DOMAIN = b'ProGetPayDetails'
GET_PRO_STATUS_DOMAIN = b'ProGetProStatus_'
assert all(
    len(p) == DOMAIN_SIZE
    for p in (GENERATE_PROOF_DOMAIN, BUILD_PROOF_DOMAIN, GET_PAYMENT_DETAILS_DOMAIN, GET_PRO_STATUS_DOMAIN)
)

# Explicit column list for payments table queries. Rows are read with `db.dict_row` and unpacked by
# name in `payment_row_from_dict`, so order here is cosmetic (no positional coupling).
# `master_pkey` lives only in `users` now, so payments reads come from `PAYMENTS_FROM` (payments LEFT
# JOIN users) and pull the pkey from the joined users row — NULL for an unredeemed payment (user_id
# NULL).
# Provider-specific ids come from the per-provider detail tables (LEFT JOINed below — a payment is in
# exactly one, the rest are NULL) and are aliased back to the historical column names so the row→PaymentRow
# mapping (payment_row_from_dict) is unchanged.
PAYMENTS_COLUMNS = ", ".join(
    (
        "p.id",
        "u.master_pkey",
        "p.plan",
        "p.payment_provider",
        "p.auto_renewing",
        "p.purchased_at",
        "p.redeemed_at",
        "p.expiry_at",
        "p.grace_period",
        "p.platform_refund_expiry_at",
        "p.revoked_at",
        "ad.original_tx_id AS apple_original_tx_id",
        "ad.tx_id AS apple_tx_id",
        "ad.web_line_order_tx_id AS apple_web_line_order_tx_id",
        "gd.payment_token AS google_payment_token",
        "gd.order_id AS google_order_id",
        "rd.order_id AS stf_order_id",
        "gd.obfuscated_account_id AS google_obfuscated_account_id",
        "ad.app_account_token AS apple_app_account_token",
    )
)
PAYMENTS_FROM = " LEFT JOIN ".join(
    (
        "payments p",
        "users u ON u.id  = p.user_id",
        "google_play_payment_details gd ON gd.payment_id = p.id",
        "app_store_payment_details ad ON ad.payment_id = p.id",
        "stf_payment_details rd ON rd.payment_id = p.id",
    )
)


# Single source of truth for reading a user row (mirrors PAYMENTS_*). The join to `generations` pulls the
# current generation's `token` (the proof's revocation_tag); it's an INNER JOIN because
# users.current_generation_id is NOT NULL, so every user always has a current generation.
USERS_COLUMNS = ", ".join(
    (
        "u.id",
        "u.master_pkey",
        "u.current_generation_id",
        "g.token",
        "u.expiry_at",
        # Coalesced at the read, not in the column. NULL there says "no store grace applies to this
        # account", which is the honest fact; no consumer of the user row distinguishes it from zero — the
        # wire reports 0 either way and the coverage arithmetic adds 0 either way — so the query hands
        # callers the form they want rather than making each of them handle the absence.
        "COALESCE(u.grace_period, '0'::interval) AS grace_period",
        "u.auto_renewing",
        "u.proof_expiry_offset",
        "u.proofs_issued_total",
        "u.proofs_issued_window",
        "u.proofs_issued_past_expiry_window",
        "u.proofs_window_start",
    )
)
USERS_FROM = "users u JOIN generations g ON g.id = u.current_generation_id"

# payments.payment_provider / .plan store the string `code` directly
# (the lookup tables payment_providers/pro_plans use the code as their PRIMARY KEY, FK'd for validity).
# So there's no id indirection: the enum's `.value` IS the stored value, and reads map it straight back
# via base.PaymentProvider(...)/base.ProPlan(...).


class ReportPeriod(enum.Enum):
    Daily = 0
    Weekly = 1
    Monthly = 2


class ReportType(enum.Enum):
    Human = 0
    CSV = 1


@dataclasses.dataclass(frozen=True)
class ReportRow:
    period: str
    active_users: int
    unredeemed: int
    new_subs: int
    google: int
    apple: int
    stf: int
    plan_1m: int
    plan_3m: int
    plan_12m: int
    revoked: int
    cancelled: int


@dataclasses.dataclass
class GoogleNotificationMessageIDInDB:
    present: bool = False
    handled: bool = False


@dataclasses.dataclass
class ProSubscriptionProof:
    revocation_tag: bytes = b''  # the generation's stored random 32-byte token
    rotating_pkey: nacl.signing.VerifyKey = nacl.signing.VerifyKey(ZERO_BYTES32)
    expiry_at: pendulum.DateTime = base.EPOCH
    sig: bytes = b''

    # --- Advisory account-entitlement value: NOT signed and NOT part of the proof message (the signed
    # message is revocation_tag ‖ rotating_pkey ‖ expiry_at). Populated by
    # build_current_entitlement_proof from the SAME DB snapshot that produced the proof, so a proof
    # fetch also hands the client its current subscription horizon in one response. This is the TRUE end
    # of the paid term, matching what get_pro_status reports and carrying NEITHER the store's grace nor
    # our renewal-latency allowance — those are how long we keep SERVING, not how long was paid for.
    # Deliberately distinct from `expiry_at` above, which is the rolling, clamped (~30 d) proof validity,
    # and which may therefore run PAST this value — never conflate the two.
    # Display state only; the signed proof + revocation list remain authoritative.
    # Left at the default on any proof built without a user context (none today). ---
    account_expiry_at: pendulum.DateTime = base.EPOCH

    # --- How much longer we keep serving PAST `account_expiry_at` — the store's dunning window plus our
    # renewal-latency allowance, exactly as `get_pro_status` reports it. Zero when the subscription is not
    # auto-renewing, because neither span applies to a term that is simply ending.
    #
    # Why it rides along with the expiry rather than only on get_pro_status: clients persist the account
    # expiry into synced config from BOTH responses and hold this beside it, because coverage ends at
    # `account_expiry_ts + account_grace_period_duration` and neither value means anything without the
    # other. A proof fetch that refreshed the expiry alone would leave a span measured from a different
    # instant sitting next to it, and the pair would silently disagree about when service stops.
    #
    # Display/state only, unsigned, like the expiry it qualifies. ---
    account_grace_period: pendulum.Duration = dataclasses.field(default_factory=pendulum.duration)

    # --- Whether the subscription behind `account_expiry_at` renews itself, from the same snapshot.
    # Mirrors what get_pro_status reports as `auto_renewing`.
    #
    # It rides along for the same reason the grace period does: clients persist the account expiry into
    # synced config from BOTH responses and persist the renewal flag beside it. If only get_pro_status
    # carried it, a proof fetch would write a fresh expiry and leave the flag untouched -- and because
    # config stores that flag presence-only (absent reads as "not renewing"), an account whose expiry has
    # only ever been written by a proof reads back as terminal. Clients gate their startup status fetch on
    # exactly that pair, so the config state saying "no need to check" would be the one reached by never
    # having checked.
    #
    # Display/state only, unsigned, like the two fields above. ---
    account_auto_renewing: bool = False

    def to_dict(self) -> dict[str, str | int | bool]:
        # The proof's format version is NOT here: it is bound into the signature through the domain prefix
        # (BUILD_PROOF_DOMAIN, `ProProof_v0_____`), and a peer learns which version it is holding from the
        # protobuf envelope that carries the proof between clients — which is the layer where an offline
        # verifier that never made this request can actually read it.
        #
        # `bool` in the annotation earns its keep: mypy accepts a bool wherever an int is declared, so
        # `account_auto_renewing` type-checked silently under `str | int` while serialising as JSON `true`,
        # not `1`. The annotation is the only place this response's wire types are written down.
        result: dict[str, str | int | bool] = {
            "revocation_tag": self.revocation_tag.hex(),
            "rotating_pkey": bytes(self.rotating_pkey).hex(),
            # Whole seconds by construction — a store expiry (µs-capable) only reaches here through
            # _build_proof_clamped_expiry_time, and the signed message needs an exact integer (wire §2).
            "expiry_ts": base.unix_seconds_from_datetime(self.expiry_at),
            "sig": self.sig.hex(),
            # Advisory, UNSIGNED (see field comment): the account's true entitlement end, distinct from
            # the clamped proof `expiry_ts` above. Lets a proof fetch refresh the client's cached expiry.
            "account_expiry_ts": base.unix_seconds_from_datetime(self.account_expiry_at),
            # Advisory, UNSIGNED: how much longer service continues past `account_expiry_ts`, so a client
            # holding both knows coverage ends at their sum. Sent alongside the expiry so the two can
            # never be persisted out of step with each other.
            "account_grace_period_duration": base.seconds_from_duration(self.account_grace_period),
            # Advisory, UNSIGNED: whether the subscription behind `account_expiry_ts` renews. Sent
            # alongside the expiry for the same reason the grace period is -- a client that persists the
            # expiry from this response persists this with it, rather than leaving a stale flag.
            "account_auto_renewing": self.account_auto_renewing,
        }
        return result


@dataclasses.dataclass
class LookupUserExpiry:
    # `None` expiry = "no such payment found yet". `None` grace = the winning payment declares no store
    # grace, carried through rather than flattened because this is what gets written back to `users`.
    expiry_from_redeemed: pendulum.DateTime | None = None
    grace_from_redeemed: pendulum.Duration | None = None
    auto_renewing_from_redeemed: bool = False

    best_expiry: pendulum.DateTime | None = None
    best_grace: pendulum.Duration | None = None
    best_auto_renewing: bool = False


AddRevocationIterator: typing.TypeAlias = tuple[
    int, bytes | None, pendulum.DateTime  # (row) id  # master_pkey
]  # expiry_at

GoogleUnhandledNotificationIterator: typing.TypeAlias = tuple[
    str, str | None, pendulum.DateTime  # message_id (opaque string)  # payload
]  # expiry_at


@dataclasses.dataclass
class UserPaymentTransaction:
    provider: base.PaymentProvider = base.PaymentProvider.Nil
    apple_tx_id: str = ''
    stf_order_id: str = ''
    google_payment_token: str = ''
    google_order_id: str = ''


# Google folds its two identifiers into one opaque `payment_id` as `token | order_id`, split once on the
# first delimiter. The token is base64url and the order id is `GPA.####-…`, so neither contains `|`.
GOOGLE_PAYMENT_ID_DELIMITER = '|'


def encode_payment_id(
    provider: base.PaymentProvider,
    *,
    google_payment_token: str = '',
    google_order_id: str = '',
    apple_tx_id: str = '',
    stf_order_id: str = '',
) -> str:
    # Fold a payment's provider-specific identifier(s) into the single opaque `payment_id` returned on
    # get_payment_details items (§5.2). The backend owns this encoding; clients treat it as opaque.
    match provider:
        case base.PaymentProvider.GooglePlayStore:
            return f'{google_payment_token}{GOOGLE_PAYMENT_ID_DELIMITER}{google_order_id}'
        case base.PaymentProvider.iOSAppStore:
            return apple_tx_id
        case base.PaymentProvider.SessionFoundation:
            return stf_order_id
        case _:
            return ''


@dataclasses.dataclass
class AppleTransaction:
    original_tx_id: str = ''
    tx_id: str = ''
    web_line_order_tx_id: str = ''


@dataclasses.dataclass
class PaymentRow:
    id: int = 0
    master_pkey: bytes | None = None
    # No stored `status`: derive it from the timestamps below via backend.derive_payment_status(row, now).
    plan: base.ProPlan = base.ProPlan.Nil
    payment_provider: base.PaymentProvider = base.PaymentProvider.Nil
    auto_renewing: bool = False
    purchased_at: pendulum.DateTime = base.EPOCH
    redeemed_at: pendulum.DateTime | None = None
    # None while a live credit's length has not run out: nothing has determined where its coverage ends yet.
    # Set for every store subscription, and latched by the drain when a credit is spent.
    expiry_at: pendulum.DateTime | None = None
    # A store grace currently in effect that the store declared SEPARATELY from its own expiry — Apple does,
    # Play instead extends `expiryTime`. None everywhere else, including a payment grace cannot apply to at
    # all (a credit, a one-shot), which is why this is not derivable from `payment_provider`.
    grace_period: pendulum.Duration | None = None
    platform_refund_expiry_at: pendulum.DateTime = base.EPOCH
    revoked_at: pendulum.DateTime | None = None
    apple: AppleTransaction = dataclasses.field(default_factory=AppleTransaction)
    google_payment_token: str = ''
    google_order_id: str = ''
    stf_order_id: str = ''
    google_obfuscated_account_id: bytes | None = None
    apple_app_account_token: str | None = None


def payment_id_from_payment_row(row: PaymentRow) -> str:
    # Egress: fold a stored payment's typed columns back into the opaque `payment_id` (§5.2).
    return encode_payment_id(
        row.payment_provider,
        google_payment_token=row.google_payment_token,
        google_order_id=row.google_order_id,
        apple_tx_id=row.apple.tx_id,
        stf_order_id=row.stf_order_id,
    )


@dataclasses.dataclass
class UserRow:
    found: bool = False
    id: int = 0
    master_pkey: bytes | None = None
    current_generation_id: int = 0
    token: bytes = b''  # current generation's token (proof revocation_tag)
    expiry_at: pendulum.DateTime = base.EPOCH
    grace_period: pendulum.Duration = pendulum.duration()
    auto_renewing: bool = False
    # This account's private proof-expiry grid: expiries land on `UTC midnight + this + k * one day`.
    # Re-drawn when `expiry_at` EXTENDS, and whenever a generation is minted; a shrink keeps it. See
    # _offset_redrawn_if_expiry_extends for why, and _build_proof_clamped_expiry_time for what it buys.
    proof_expiry_offset: int = 0

    # How many proofs this account has been issued, ever and in the current window, and how many of that
    # window's were issued past its expiry (a SUBSET of `proofs_issued_window`, not a separate bucket). See
    # `_record_proof_issued` for what advances them, `_ensure_active_generation` for the one thing that
    # clears the window, and `schema/009_proof_issue_counters.sql` for why they exist.
    # `proofs_window_start` is None when no window is open, which is not the same fact as one that opened
    # at the epoch.
    proofs_issued_total: int = 0
    proofs_issued_window: int = 0
    proofs_issued_past_expiry_window: int = 0
    proofs_window_start: pendulum.DateTime | None = None


@dataclasses.dataclass
class GetUserAndPayments:
    payments_it: db.Result
    user: UserRow = dataclasses.field(default_factory=UserRow)
    payments_count: int = 0


@dataclasses.dataclass
class RevocationRow:
    '''A revoked generation (admin/raw view of the revocation list).'''

    generation_id: int = 0
    token: bytes = b''
    revoked_at: pendulum.DateTime = base.EPOCH


@dataclasses.dataclass
class AllocatedGenID:
    found: bool = False
    expiry_at: pendulum.DateTime | None = None
    grace_period: pendulum.Duration | None = None
    generation_id: int = 0
    token: bytes = b''


def load_backend_signing_key(path: str) -> nacl.signing.SigningKey:
    '''Load the backend Ed25519 signing key from disk.

    The file holds 128 hex characters (optionally followed by whitespace): the libsodium-style
    64-byte secret key, i.e. the 32-byte seed followed by the 32-byte precomputed public key
    (matching oxen-core's on-disk ed25519 key format). The key lives ONLY on disk, never in the
    database (and therefore never in a DB backup). Raises on any problem; the caller must refuse to
    start rather than run with a missing or malformed signing key.
    '''
    with open(path, 'r') as f:
        text: str = f.read().strip()
    if len(text) != 128 or any(c not in '0123456789abcdefABCDEF' for c in text):
        raise ValueError(f'expected 128 hex characters (a 64-byte libsodium ed25519 secret key), got {len(text)}')
    raw: bytes = bytes.fromhex(text)
    seed: bytes = raw[:32]
    pub: bytes = raw[32:]
    skey = nacl.signing.SigningKey(seed)
    if bytes(skey.verify_key) != pub:
        raise ValueError('embedded public key does not match the seed; the key file is corrupt')
    return skey


def backend_signing_key_to_hex(skey: nacl.signing.SigningKey) -> str:
    '''Serialise a signing key to the 128-hex libsodium-style representation (seed || public key).'''
    return (bytes(skey) + bytes(skey.verify_key)).hex()


def payment_provider_tx_log_label_safe(tx: base.PaymentProviderTransaction) -> str:
    # Only the active provider's ids are populated; show just those (obfuscated).
    match tx.provider:
        case base.PaymentProvider.iOSAppStore:
            ids = (
                f'apple(orig/tx/web)=({base.maybe_obfuscate(tx.apple_original_tx_id)}/'
                f'{base.maybe_obfuscate(tx.apple_tx_id)}/{base.maybe_obfuscate(tx.apple_web_line_order_tx_id)})'
            )
        case base.PaymentProvider.GooglePlayStore:
            ids = f'google=({base.maybe_obfuscate(tx.google_payment_token)}/{base.maybe_obfuscate(tx.google_order_id)})'
        case base.PaymentProvider.SessionFoundation:
            ids = f'stf={base.maybe_obfuscate(tx.stf_order_id)}'
        case _:
            ids = '(no provider ids)'
    return f'{tx.provider.name}, {ids}'


def user_payment_tx_to_safe_string(tx: UserPaymentTransaction) -> str:
    # Only the active provider's ids are populated; show just those (obfuscated).
    match tx.provider:
        case base.PaymentProvider.iOSAppStore:
            ids = f'apple={base.maybe_obfuscate(tx.apple_tx_id)}'
        case base.PaymentProvider.GooglePlayStore:
            ids = f'google=({base.maybe_obfuscate(tx.google_payment_token)}/{base.maybe_obfuscate(tx.google_order_id)})'
        case base.PaymentProvider.SessionFoundation:
            ids = f'stf={base.maybe_obfuscate(tx.stf_order_id)}'
        case _:
            ids = '(no provider ids)'
    return f'{tx.provider.name}, {ids}'


# The bytes we Ed25519-sign directly (NO pre-hash — wire spec §1): a 16-byte domain prefix then the fields,
# each encoded by TYPE — VerifyKey/bytes verbatim (fixed-width, self-delimiting); datetime → its UNIX
# **seconds** then decimal ASCII (pass an int explicitly if you ever need other units); int as canonical
# locale-independent decimal ASCII (matches C++ std::to_chars: no grouping/leading zeros, '-' for
# negatives, so count=-1 and unbounded values Just Work); str as UTF-8. A `\0` separates two ADJACENT
# variable-length (datetime/int/str) fields; fixed-width fields need no separator. Only payment_id can
# contain a `\0` and it is always the final field, so the framing is unambiguous.
def signed_message(domain: bytes, *fields: nacl.signing.VerifyKey | bytes | pendulum.DateTime | int | str) -> bytes:
    assert len(domain) == DOMAIN_SIZE
    out = bytearray(domain)
    prev_variable = False
    for field in fields:
        if isinstance(field, (nacl.signing.VerifyKey, bytes, bytearray)):
            data, variable = bytes(field), False
        elif isinstance(field, pendulum.DateTime):
            data, variable = str(base.unix_seconds_from_datetime(field)).encode('ascii'), True  # → int seconds
        elif isinstance(field, int):
            data, variable = str(field).encode('ascii'), True  # canonical decimal
        elif isinstance(field, str):
            data, variable = field.encode('utf-8'), True
        else:
            raise TypeError(
                f'signed_message: unsupported field type {type(field).__name__} '
                f'(expected VerifyKey/bytes, datetime, int, or str)'
            )
        if variable and prev_variable:
            out += b'\x00'
        out += data
        prev_variable = variable
    return bytes(out)


def make_get_pro_status_message(master_pkey: nacl.signing.VerifyKey, request_at: pendulum.DateTime) -> bytes:
    return signed_message(GET_PRO_STATUS_DOMAIN, master_pkey, request_at)


def make_get_payment_details_message(
    master_pkey: nacl.signing.VerifyKey, request_at: pendulum.DateTime, limit: int, before: str
) -> bytes:
    return signed_message(GET_PAYMENT_DETAILS_DOMAIN, master_pkey, request_at, limit, before)


# --- get-payment-details keyset pagination cursor ------------------------------------------------
# Seek pagination keys on the payment's surrogate id, but that id is a global identity sequence, so
# handing the raw value to the client would leak system-wide payment volume/ordering (the same reason
# `payment_id` is opaque, §5.2). So we hand back the boundary id sealed in an XChaCha20-Poly1305 token
# the client echoes verbatim. The key is derived from the backend signing key via a domain-separated
# BLAKE2b — no separate secret to provision; rotating the signing key just invalidates outstanding
# cursors (harmless — the client re-fetches from the newest page). The master_pkey is the AEAD
# associated data, binding a cursor to the user it was issued to.
_CURSOR_KEY_DOMAIN = b'SeshProCursorKey'  # 16-byte BLAKE2b personalisation


@functools.lru_cache(maxsize=None)
def _derive_cursor_key(seed: bytes) -> bytes:
    return hashlib.blake2b(seed, digest_size=32, person=_CURSOR_KEY_DOMAIN).digest()


def payment_cursor_key(signing_key: nacl.signing.SigningKey) -> bytes:
    '''The 32-byte XChaCha20-Poly1305 cursor key derived from the signing seed. The derivation is constant
    for a given key and memoized, so calling this per request just returns the cached bytes.'''
    return _derive_cursor_key(bytes(signing_key))


def encrypt_payment_cursor(cursor_key: bytes, master_pkey: nacl.signing.VerifyKey, payment_id: int) -> str:
    nonce = nacl.utils.random(nacl.bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        payment_id.to_bytes(8, 'big'), bytes(master_pkey), nonce, cursor_key
    )
    return (nonce + ct).hex()


def decrypt_payment_cursor(cursor_key: bytes, master_pkey: nacl.signing.VerifyKey, cursor: str) -> int:
    '''Decrypt a pagination cursor to its boundary payment id. Raises on tamper / wrong user / garbage.'''
    raw = bytes.fromhex(cursor)
    npub = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    nonce, ct = raw[:npub], raw[npub:]
    pt = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, bytes(master_pkey), nonce, cursor_key)
    return int.from_bytes(pt, 'big')


def payment_row_from_dict(row: dict[str, typing.Any]) -> PaymentRow:
    # Rows come from a dict row factory (SELECT PAYMENTS_COLUMNS FROM PAYMENTS_FROM, row_factory=
    # db.dict_row) so columns are addressed by name — adding/removing a column no longer renumbers
    # anything here. `master_pkey` is joined from users (NULL for an unredeemed payment).
    result = PaymentRow()
    result.id = row['id']
    result.master_pkey = bytes(row['master_pkey']) if row['master_pkey'] is not None else None
    result.plan = base.ProPlan(row['plan'])
    result.payment_provider = base.PaymentProvider(row['payment_provider'])
    result.auto_renewing = bool(row['auto_renewing'])
    result.purchased_at = row['purchased_at']
    result.redeemed_at = row['redeemed_at']  # NULL until redeemed
    result.expiry_at = row['expiry_at']
    result.grace_period = row['grace_period']
    result.platform_refund_expiry_at = row['platform_refund_expiry_at']
    result.revoked_at = row['revoked_at']  # NULL unless revoked
    result.apple.original_tx_id = str(row['apple_original_tx_id']) if row['apple_original_tx_id'] else ''
    result.apple.tx_id = str(row['apple_tx_id']) if row['apple_tx_id'] else ''
    result.apple.web_line_order_tx_id = (
        str(row['apple_web_line_order_tx_id']) if row['apple_web_line_order_tx_id'] else ''
    )
    result.google_payment_token = str(row['google_payment_token']) if row['google_payment_token'] else ''
    result.google_order_id = str(row['google_order_id']) if row['google_order_id'] else ''
    result.stf_order_id = str(row['stf_order_id']) if row['stf_order_id'] else ''
    result.google_obfuscated_account_id = (
        bytes(row['google_obfuscated_account_id']) if row['google_obfuscated_account_id'] is not None else None
    )
    result.apple_app_account_token = row['apple_app_account_token']  # nullable
    return result


def derive_payment_status(payment: PaymentRow, now: pendulum.DateTime) -> base.PaymentStatus:
    """Derive the single display status from a payment's timestamps against `now`.

    `status` is not stored; it's computed with precedence revoked > expired > redeemed. Only a payment
    bound to a user has a status at all — an unclaimed one carries no user_id, so it never reaches a
    user-scoped response; test `redeemed_at IS NULL` for that instead of asking for a status.
    """
    if payment.revoked_at is not None:
        return base.PaymentStatus.Revoked
    assert payment.redeemed_at is not None, 'an unclaimed payment has no status; test redeemed_at IS NULL'
    if payment.expiry_at is not None and now >= payment.expiry_at:
        return base.PaymentStatus.Expired
    return base.PaymentStatus.Redeemed


def subscription_coverage_end(
    expiry_at: pendulum.DateTime, store_grace: pendulum.Duration | None, auto_renewing: bool
) -> pendulum.DateTime:
    """The instant a subscription payment stops covering the account: its paid-through expiry, plus any
    window we are still honouring on top — but only while a renewal is going to be attempted.

    Two spans, both applied HERE and neither stored:

    * `store_grace` — the dunning window the store granted, reached by a different route per provider but
      meaning the same span in both. Apple states it directly. Play does not: it extends `expiryTime`
      instead, so `google_converge_payment` keeps the stored paid term as `expiry_at` and records the
      extension here rather than letting one overwrite the other. NULL only where grace is not a concept
      for the payment (a credit, a one-shot), or where Play's first notification for a row already
      carried the extension — there being no earlier paid term to measure it against, that expiry is
      stored as-is and the grace reads zero.
    * `base.RENEWAL_LATENCY_ALLOWANCE` — ours, config, covering the gap between a term ending and us
      learning whether it renewed. Read at call time rather than captured, so raising the setting ahead of
      maintenance moves accounts that already have payments; a stored copy would fossilise and protect
      nobody who mattered.

    BOTH are gated on `auto_renewing`, which is the whole reason no mechanism is needed to clear store
    grace when it ends. Grace is the window after a renewal payment FAILS, so it exists only while one is
    still being attempted: a subscriber who cancels mid-billing-retry keeps a 16-day value in the column
    and is covered to the end of the paid term and not a moment longer. Gating only the allowance would
    over-entitle that account by the remainder of the store's window.

    Shared by the entitlement fold and the credit drain deliberately: if the two disagreed about when
    coverage ends, an account could be entitled while its credits drain, or hold protected credits while
    reading as expired."""
    if not auto_renewing:
        return expiry_at
    grace = store_grace if store_grace is not None else pendulum.duration()
    return expiry_at + grace + base.RENEWAL_LATENCY_ALLOWANCE


def account_coverage_end(user: UserRow) -> pendulum.DateTime:
    """`subscription_coverage_end` asked of the account snapshot rather than of one payment row.

    Same shape at a different level: `users` carries the winning payment's raw expiry, its store grace and
    its renewal flag, so the arithmetic is identical and deliberately not duplicated. Every consumer asking
    "is this account still covered" goes through one of these two, because a consumer that reads
    `users.expiry_at` directly is reading the TRUE end of the paid term — which is the honest thing to show
    a user, and the wrong thing to make a serving decision on."""
    return subscription_coverage_end(user.expiry_at, user.grace_period, user.auto_renewing)


def account_grace_span(user: UserRow) -> pendulum.Duration:
    """How much longer the account is served past `user.expiry_at` — the store's dunning window plus our
    renewal-latency allowance, as one span.

    The value every response reports beside the account expiry (`get_pro_status`'s account-level
    `grace_period_duration`, and `account_grace_period_duration` on a proof response and on a
    `subscription_expired` failure). It lives here, in one place, because a client adds it to the expiry to
    learn when service stops: two endpoints deriving it separately could drift, and the pair would then say
    two different things about the same instant depending on which one a client happened to call.

    Zero for a subscription that is not auto-renewing, out of `account_coverage_end`'s gate rather than a
    second test of the flag here."""
    return account_coverage_end(user) - user.expiry_at


@dataclasses.dataclass
class CreditToDrain:
    """One live credit as the drain sees it: its row id and how much length it still has to give."""

    payment_id: int
    remaining: pendulum.Duration


@dataclasses.dataclass
class CreditDrainResult:
    # (payment id, new remaining) for the rows that actually changed — nothing else needs writing.
    updated: list[tuple[int, pendulum.Duration]] = dataclasses.field(default_factory=list)
    # How much of the budget was actually charged. Less than the budget exactly when the credits ran out
    # partway through the window, which is what lets the caller date that moment as `checkpoint + spent`.
    spent: pendulum.Duration = dataclasses.field(default_factory=pendulum.duration)
    # The budget outran the credits: every one of them is now zero and there was still time to charge.
    exhausted: bool = False


def drain_credits(credits: list[CreditToDrain], budget: pendulum.Duration) -> CreditDrainResult:
    """Spend `budget` worth of uncovered time across `credits`, oldest first, and report what changed.

    Pure: no clock, no database. The caller decides what `budget` is (the uncovered span since the
    account's drain checkpoint, zero while a subscription covers it) and supplies the live credits in
    consumption order; everything the caller must then write back is in the result.

    Exactly one credit can be paying for any given moment, so the budget is spent down one credit at a
    time, oldest first, and spills into the next only once the current one is empty.

    Budget left over after the last credit is discarded rather than remembered: those were moments the
    account simply had no entitlement, and there is nobody to charge for them."""
    result = CreditDrainResult()
    zero = pendulum.duration()
    if budget <= zero:
        return result

    left = budget
    for credit in credits:
        if left <= zero:
            break
        charge = min(credit.remaining, left)
        if charge <= zero:
            continue
        result.updated.append((credit.payment_id, credit.remaining - charge))
        left -= charge

    result.spent = budget - left
    result.exhausted = left > zero and len(credits) > 0
    return result


def get_unredeemed_payments_list(conn: psycopg.Connection) -> list[PaymentRow]:
    result: list[PaymentRow] = []
    with db.transaction(conn):
        rows = db.query(
            conn,
            f'SELECT {PAYMENTS_COLUMNS} FROM {PAYMENTS_FROM}'
            ' WHERE p.redeemed_at IS NULL AND p.revoked_at IS NULL ORDER BY p.id',
            row_factory=db.dict_row,
        )
        for row in rows:
            item = payment_row_from_dict(row)
            result.append(item)
    return result


def get_payments_list(conn: psycopg.Connection) -> list[PaymentRow]:
    result: list[PaymentRow] = []
    with db.transaction(conn):
        rows = db.query(conn, f'SELECT {PAYMENTS_COLUMNS} FROM {PAYMENTS_FROM} ORDER BY p.id', row_factory=db.dict_row)
        for row in rows:
            item = payment_row_from_dict(row)
            result.append(item)
    return result


def get_user_and_payments(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> GetUserAndPayments:
    payments_it = db.query(
        tx.conn,
        f'''
        SELECT   {PAYMENTS_COLUMNS}
        FROM     {PAYMENTS_FROM}
        WHERE    p.user_id = (SELECT id FROM users WHERE master_pkey = %s)
        ORDER BY p.purchased_at DESC, p.id DESC
    ''',
        bytes(master_pkey),
        row_factory=db.dict_row,
    )

    result = GetUserAndPayments(payments_it=payments_it)
    result.user = get_user(tx.conn, master_pkey)

    result.payments_count = db.query_scalar(
        tx.conn,
        '''
        SELECT COUNT(*)
        FROM   payments
        WHERE  user_id = (SELECT id FROM users WHERE master_pkey = %s)
    ''',
        bytes(master_pkey),
    )
    return result


def get_user_payments_page(
    tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey, limit: int, before_id: int | None
) -> list[PaymentRow]:
    '''One keyset page of a user's (redeemed) payments, newest-first (id DESC — the registration order).
    `before_id` is the exclusive upper bound: return rows with id < before_id; None starts at the newest.
    A user_id is only ever set on a redeemed payment, so this returns only redeemed rows.'''
    sql = (
        f'SELECT {PAYMENTS_COLUMNS} FROM {PAYMENTS_FROM} '
        'WHERE p.user_id = (SELECT id FROM users WHERE master_pkey = %(mk)s)'
    )
    params: dict[str, typing.Any] = {'mk': bytes(master_pkey), 'lim': limit}
    if before_id is not None:
        sql += ' AND p.id < %(before)s'
        params['before'] = before_id
    sql += ' ORDER BY p.id DESC LIMIT %(lim)s'
    return [payment_row_from_dict(r) for r in db.query(tx.conn, sql, row_factory=db.dict_row, **params)]


def get_account_latest_payment(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> PaymentRow | None:
    '''The account's latest payment that still stands: newest by the STORE's purchase instant, preferring one
    that has not been revoked. `None` only when the account has no payments at all.

    Ordered on `purchased_at`, never on `p.id`. The id is assigned when we first WITNESS a payment, so it
    orders by delivery: a notification we accept late — the Apple catch-up drains failures up to 30 days
    on, and a backlog after an outage does the same — lands a row for an old cycle above a newer purchase.
    An account that moved between stores then reports the store it left. `purchased_at` is what the store
    itself says about when the payment happened, which is the question being asked; the id only breaks ties.

    Revoked rows sort last rather than being filtered out, which is one `ORDER BY` doing two jobs. Skipping
    them is the point: buy on a second store by mistake, reverse it, and the account goes back to reporting
    the subscription it actually still has, as soon as the revocation lands. Keeping them as the last resort
    is equally deliberate — an account whose every payment was refunded still gets an item, because `null`
    means "never had a payment" to a client and at least one of them renders an absent item as a default
    provider, which is the same wrong-store answer by another road.

    This is the LATEST payment, which is not necessarily the one whose coverage reaches furthest: a voucher
    stacks its length on top of a subscription, so an account holding both has an entitlement that outlives
    the payment named here. `users.expiry_at` (the sibling `expiry_ts`) is the account-level answer and comes
    from `_lookup_user_expiry`; do not expect the two to agree.'''
    row = db.query_one(
        tx.conn,
        f'''
        SELECT   {PAYMENTS_COLUMNS}
        FROM     {PAYMENTS_FROM}
        WHERE    p.user_id = (SELECT id FROM users WHERE master_pkey = %s)
        ORDER BY (p.revoked_at IS NULL) DESC, p.purchased_at DESC, p.id DESC
        LIMIT    1
        ''',
        bytes(master_pkey),
        row_factory=db.dict_row,
    )
    return payment_row_from_dict(row) if row is not None else None


def get_user_payments_count(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> int:
    return db.query_scalar(
        tx.conn,
        'SELECT COUNT(*) FROM payments WHERE user_id = (SELECT id FROM users WHERE master_pkey = %s)',
        bytes(master_pkey),
    )


def user_row_from_dict(row: dict[str, typing.Any]) -> UserRow:
    return UserRow(
        found=True,
        id=row['id'],
        master_pkey=bytes(row['master_pkey']),
        current_generation_id=row['current_generation_id'],
        token=bytes(row['token']),
        expiry_at=row['expiry_at'],
        grace_period=row['grace_period'],
        auto_renewing=bool(row['auto_renewing']),
        proof_expiry_offset=row['proof_expiry_offset'],
        proofs_issued_total=row['proofs_issued_total'],
        proofs_issued_window=row['proofs_issued_window'],
        proofs_issued_past_expiry_window=row['proofs_issued_past_expiry_window'],
        proofs_window_start=row['proofs_window_start'],
    )


def get_users_list(conn: psycopg.Connection) -> list[UserRow]:
    result: list[UserRow] = []
    with db.transaction(conn):
        for row in db.query(conn, f"SELECT {USERS_COLUMNS} FROM {USERS_FROM}", row_factory=db.dict_row):
            result.append(user_row_from_dict(row))
    return result


def get_user(conn: psycopg.Connection, master_pkey: nacl.signing.VerifyKey) -> UserRow:
    # Single SELECT: runs on the given connection, so a mid-transaction caller passes `tx.conn` (joins the
    # open transaction) and a standalone caller autocommits.
    result: UserRow = UserRow()
    row = db.query_one(
        conn,
        f"SELECT {USERS_COLUMNS} FROM {USERS_FROM} WHERE u.master_pkey = %s",
        bytes(master_pkey),
        row_factory=db.dict_row,
    )
    if row:
        result = user_row_from_dict(row)
    return result


def get_revocations_list(
    conn: psycopg.Connection, revoked_after: pendulum.DateTime | None = None
) -> list[RevocationRow]:
    """Revoked generations. `revoked_after` restricts them to those recorded after that instant, which is
    how the served list applies its retention window; omitted, this is the whole unfiltered set.

    Single statement, so it runs directly on the given connection: a mid-transaction caller passes
    `tx.conn` and the read joins that open transaction, a standalone caller autocommits."""
    sql = "SELECT id, token, revoked_at FROM generations WHERE revoked_at IS NOT NULL"
    args: tuple[typing.Any, ...] = ()
    if revoked_after is not None:
        sql += " AND revoked_at > %s"
        args = (revoked_after,)
    result: list[RevocationRow] = []
    for row in db.query(conn, sql, *args):
        generation_id, token, revoked_at = row
        result.append(RevocationRow(generation_id=generation_id, token=bytes(token), revoked_at=revoked_at))
    return result


def is_generation_revoked(conn: psycopg.Connection, generation_id: int, now: pendulum.DateTime) -> bool:
    # A generation is revoked iff revoked_at is set (revocation is terminal). `now` is accepted for a
    # uniform signature; a set revoked_at is always in effect (there is no per-entry expiry now — the
    # served-list retention window is list-level and memory-only on the client). Single statement, so it
    # runs directly on the given connection: a mid-transaction caller passes `tx.conn` and the read joins
    # that open transaction (sees an uncommitted revoke); a standalone caller autocommits.
    return bool(
        db.query_scalar(
            conn, "SELECT EXISTS (SELECT 1 FROM generations WHERE id = %s AND revoked_at IS NOT NULL)", generation_id
        )
    )


# Typed accessors for the `globals` key/value store (one row per app-global; see schema/000). Each
# global's type is known at the call site, so we read/write the matching value slot directly.
def get_global_int(conn: psycopg.Connection, key: str) -> int:
    row = db.query_one(conn, "SELECT int_val FROM globals WHERE key = %s", key)
    assert row is not None, f'missing int global "{key}"'
    return row[0]


def set_global_int(conn: psycopg.Connection, key: str, value: int) -> None:
    db.query(conn, "UPDATE globals SET int_val = %s WHERE key = %s", value, key)


def get_global_bytes(conn: psycopg.Connection, key: str) -> bytes:
    row = db.query_one(conn, "SELECT bytes_val FROM globals WHERE key = %s", key)
    assert row is not None, f'missing bytes global "{key}"'
    return bytes(row[0])


def get_global_datetime(conn: psycopg.Connection, key: str) -> pendulum.DateTime:
    row = db.query_one(conn, "SELECT ts_val FROM globals WHERE key = %s", key)
    assert row is not None, f'missing timestamp global "{key}"'
    return row[0]


def set_global_datetime(conn: psycopg.Connection, key: str, value: pendulum.DateTime) -> None:
    db.query(conn, "UPDATE globals SET ts_val = %s WHERE key = %s", value, key)


def get_revocation_ticket(conn: psycopg.Connection) -> int:
    return get_global_int(conn, 'revocation_ticket')


def bump_revocation_ticket(conn: psycopg.Connection, amount: int) -> int:
    """Advance the monotonic revocation ticket by `amount`, returning the new value. Manual DR tool: the
    ticket is a plain counter, so restoring the database from an older backup rolls it backward — and a
    client holding a higher cached ticket then reads the list as "unchanged" and silently stops seeing
    revocations. After such a restore, bump the ticket past its pre-restore value to force every client to
    re-fetch. See docs/deploy.md ("After ANY restore")."""
    row = db.query_one(
        conn, "UPDATE globals SET int_val = int_val + %s WHERE key = 'revocation_ticket' RETURNING int_val", amount
    )
    assert row is not None, 'missing revocation_ticket global'
    return row[0]


def migrate_schema(conn: psycopg.Connection) -> None:
    """Bootstrap/migrate the schema on `conn` if needed. Raises RuntimeError on failure."""
    try:
        migrations.apply_migrations(conn)
    except Exception as e:
        raise RuntimeError('Failed to bootstrap DB tables') from e


def bootstrap_db(database_url: str) -> psycopg_pool.ConnectionPool:
    """Open a pool for `database_url` and migrate the schema, returning the pool. Raises on failure.

    Single-process convenience (tests, CLI) where a pool is safe to open eagerly. The uWSGI master
    must NOT use this: it runs pre-fork, and a pool's worker threads inherited across fork() corrupt
    the children (see db.connect_one). The master migrates on a throwaway connection and lets each
    worker build its own pool post-fork."""
    db.set_dsn(database_url)
    try:
        pool = db.pool()
    except Exception as e:
        raise RuntimeError(f'Failed to open/connect to DB at {database_url}: {e}') from e

    with db.connection() as conn:
        migrate_schema(conn)

    return pool


def verify_db(conn: psycopg.Connection, err: base.ErrorSink) -> bool:
    unredeemed_payments: list[PaymentRow] = get_unredeemed_payments_list(conn)
    for index, it in enumerate(unredeemed_payments):
        base.verify_payment_provider(it.payment_provider, err)
        if len(it.google_payment_token) != BLAKE2B_DIGEST_SIZE:
            err.msg_list.append(
                f'Unredeeemed payment #{index} token is not 32 bytes, was {len(it.google_payment_token)}'
            )
        if it.plan == base.ProPlan.Nil:
            err.msg_list.append(
                f'Unredeemed payment #{index} had an invalid plan, received ({base.reflect_enum(it.plan)})'
            )

    payments: list[PaymentRow] = get_payments_list(conn)
    for index, it in enumerate(payments):
        # NOTE: Check mandatory fields
        if it.payment_provider == base.PaymentProvider.Nil:
            err.msg_list.append(
                f'Payment #{index} payment provider is set to {it.payment_provider.name} '
                f'but it should not be. '
                f'It should have been set by the platform before added to the DB'
            )

        # NOTE: Check mandatory fields or invariants given a particular TX status. Presence/absence
        # is now modelled by NULL (redeemed_at / revoked_at), and expiry_at is NOT NULL, so the old
        # "ts was 0" sentinel checks are gone — the schema enforces them.
        if it.redeemed_at is None and it.revoked_at is None:
            # Unclaimed: nothing identity-related should be set yet.
            if it.master_pkey is not None:
                err.msg_list.append(
                    f'Payment #{index} has a master pkey set but this pkey should not be set '
                    f'until it is redeemed (e.g. the user registers it)'
                )

        if it.revoked_at is None and it.redeemed_at is not None:
            # A term cannot end before it began. Compared against the PURCHASE instant, not the redemption
            # one: binding a payment whose term has already run out is legitimate and routine -- a
            # notification we accept late, or a backlog drained after an outage, arrives for a cycle that
            # has since ended, and the entitlement fold handles that on its own. Both instants here are the
            # store's own, so this checks the store against itself. A live credit has no expiry yet, so
            # there is nothing to compare.
            if it.expiry_at is not None and it.expiry_at < it.purchased_at:
                purchased_date = it.purchased_at.strftime('%Y-%m-%d')
                expiry_date = it.expiry_at.strftime('%Y-%m-%d')
                err.msg_list.append(
                    f'Payment #{index} expired ({expiry_date}) before it was purchased ({purchased_date})'
                )

        # NOTE: Verify the plan, it should always be set once it enters the DB..
        if it.plan == base.ProPlan.Nil:
            err.msg_list.append(f'Payment #{index} had an invalid plan, received ({base.reflect_enum(it.plan)})')
        base.verify_payment_provider(it.payment_provider, err)

        # NOTE: Check that the token is set correctly
        if it.payment_provider == base.PaymentProvider.GooglePlayStore:
            pass
        elif len(it.google_payment_token) != 0:
            err.msg_list.append(
                f'Payment #{index} specified a google payment token: '
                f'{base.maybe_obfuscate(it.google_payment_token)} for a non-google platform'
            )

    # NOTE: Verify the users
    users: list[UserRow] = get_users_list(conn)
    for index, user in enumerate(users):
        if user.master_pkey == ZERO_BYTES32:
            err.msg_list.append(f'User #{index} has a master public key set to the zero key')

    result = len(err.msg_list) == 0
    return result


def new_proof_expiry_offset() -> int:
    '''Draw a fresh per-account proof-expiry offset: uniform seconds spanning exactly one expiry grid
    period (a day, in production).

    Two properties are load-bearing, both for the same reason — an observer reads the offset off any proof
    and is trying to work backwards from it (see `_build_proof_clamped_expiry_time` for what the offset
    buys, `_offset_redrawn_if_expiry_extends` for when it is re-drawn, and
    `schema/003_proof_expiry_offset.sql` for why it is stored rather than derived):
    UNPREDICTABLE, so it must come from the CSPRNG and never from the clock or the account key; and
    UNIFORM over the full period, since a skew re-clusters the expiry times the offset exists to scatter.
    '''
    # Reducing a 64-bit draw modulo the period leaves a bias of ~1 part in 10^15 — far below any skew that
    # could cluster anything, so it is accepted rather than rejection-sampled away.
    return int.from_bytes(nacl.utils.random(8), 'big') % base.PROOF_EXPIRY_SHAPE.offset_range


def _offset_redrawn_if_expiry_extends(expiry: pendulum.DateTime | None) -> str:
    '''The SQL value for `users.proof_expiry_offset`: a fresh draw when the account's true expiry EXTENDS,
    the stored one otherwise. Both callers set expiry_at from the payment list, so an extension is the
    honest trigger for a new subscription cycle — a redeem, a renewal, a stacked purchase.

    Precision matters in three directions. Never re-drawing would leave a stable per-account fingerprint
    against a fixed anniversary instant. Re-drawing on a no-op refresh (a flag-only touch, a re-reconcile
    that claims nothing) would hand an observer repeated samples of one true expiry, whose minimum converges
    straight back onto it. And re-drawing on a SHRINK would let a reduction in entitlement hand out MORE
    coverage: the served expiry is the true one rounded up onto `EPOCH + offset + k*grid`, so an independent
    new offset lands anywhere in the following period and can overshoot what the longer expiry served. Keep
    the offset and the grid is unchanged, so rounding up a smaller value can only give a smaller result.

    Keeping it on a shrink costs no privacy: the offset is not secret — the served expiry IS a grid point,
    so its time-of-day is the offset (test_proof_expiry_lands_on_the_account_grid asserts exactly that). What
    the offset hides is the true expiry within one period, and that only degrades under repeated independent
    draws against a MATERIALLY UNCHANGED expiry, which is the case this still excludes. (Strictly, an
    extension smaller than one period — a grace-duration edit moving `expiry + grace` by minutes — also
    re-draws against a near-identical value, but that happens a handful of times in a subscription's life,
    nowhere near enough for the minimum to converge.)

    ONE EXCEPTION, applied by the caller rather than here: minting a generation forces a re-draw regardless.
    A broadcast revocation is a shrink, and it is also the moment the revocation_tag rolls — the one point at
    which the design unlinks an account's proofs — so an offset carried across it would be a ~16-bit
    fingerprint defeating exactly that (docs/limitations.md).
    '''
    # A shrink to "no expiry at all" is still a shrink, so the degenerate case is just: keep it.
    if expiry is None:
        return 'proof_expiry_offset'
    return (
        'CASE WHEN expiry_at IS NULL OR %(expiry)s > expiry_at'
        ' THEN %(proof_random_offset)s ELSE proof_expiry_offset END'
    )


@db.transactional
def _update_user_expiry_grace_and_renew_flag_from_payment_list(
    tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey
):
    """Update fields for the user that depend on their list of payments, like
    their latest known expiry time"""
    master_pkey_bytes: bytes = bytes(master_pkey)
    lookup: LookupUserExpiry = _lookup_user_expiry(tx, nacl.signing.VerifyKey(master_pkey_bytes))

    # No payment left to compute from — every one the account had is revoked or expired. `users.expiry_at`
    # is NOT NULL, so the absence has to be written as an instant rather than as NULL, and the instant that
    # says it is the recompute's own: coverage ends here, nothing beyond it is owed.
    #
    # Leaving the previous value instead would keep a refunded account entitled until its original term ran
    # out, since `get_pro_status` reads this column. Writing it forward is a SHRINK in the same sense the
    # offset helper below already means by it — it declines to redraw for exactly this case, which is how we
    # know a `None` expiry was expected here and only its write was not.
    expiry_at = lookup.best_expiry if lookup.best_expiry is not None else base.utc_now()

    # NOTE: We have the latest expiry value, now update the user
    db.query(
        tx.conn,
        f'''
        UPDATE users
        SET    expiry_at = %(expiry)s, grace_period = %(grace)s,
               auto_renewing = %(renewing)s,
               proof_expiry_offset = {_offset_redrawn_if_expiry_extends(lookup.best_expiry)}
        WHERE  master_pkey = %(pkey)s
    ''',
        expiry=expiry_at,
        grace=lookup.best_grace,
        renewing=lookup.best_auto_renewing,
        proof_random_offset=new_proof_expiry_offset(),
        pkey=master_pkey_bytes,
    )


@db.transactional
def revoke_payments_by_id_internal(tx: db.SQLTransaction, rows: typing.Any, revoke_at: pendulum.DateTime) -> bool:
    result = False
    master_pkey_dict: dict[bytes, pendulum.DateTime] = {}
    for row in rows:
        result = True
        id, master_pkey_raw, expiry_at = row
        master_pkey_bytes: bytes | None = bytes(master_pkey_raw) if master_pkey_raw is not None else None

        # NOTE: A payment will not have a master pkey associated with it if the user hasn't
        # redeemed it yet so the key may not be set. If it's not set we still mark the payment as
        # 'revoked', this means that it can't be activated and so a master pkey cannot be set on it
        # after the fact as well.
        if master_pkey_bytes:
            master_pkey_dict[master_pkey_bytes] = expiry_at

        # NOTE: Mark the payment revoked (set revoked_at) unless it already is.
        db.query(
            tx.conn,
            '''
        UPDATE payments
        SET    revoked_at = %(revoked_ts)s, auto_renewing = FALSE
        WHERE  id = %(id)s AND revoked_at IS NULL
        ''',
            revoked_ts=revoke_at,
            id=id,
        )

    # Every revoke UPDATE above has landed, so each affected account can now be recomputed and judged from
    # what it actually holds. Deliberately not per-payment: a refund is only one of several ways an
    # entitlement can fall, and they all reduce to the same question about outstanding proofs.
    for it in master_pkey_dict:
        refresh_entitlement_and_revoke_overreaching_proofs(tx, nacl.signing.VerifyKey(it), at=revoke_at)

    return result


@db.transactional
def refresh_entitlement_and_revoke_overreaching_proofs(
    tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey, at: pendulum.DateTime
) -> bool:
    """Recompute what an account is entitled to, and revoke its outstanding proofs if they now claim more
    than it has. Returns whether a revocation was broadcast.

    WHY the entitlement fell is deliberately not an input. A refund, a store-side revoke that back-dates the
    term, a downgrade, a supersession by an upgraded subscription, a shortened term — they differ only in
    what moved the payment rows, and by the time this runs the rows already say what they say. The single
    question left is whether anything we have already signed now overstates the account, and that has one
    answer regardless of cause.

    Ordering is the point: every write lands first, then the account is recomputed, then the decision is
    taken from the recomputed state. Judging mid-write is what made the old inline version depend on rows
    that had not been inserted yet, and on which row an unordered SELECT happened to return last.
    """
    # Before anything moves. `users.expiry_at` is only written by the recompute below, so this is still the
    # pre-change value even though the payment rows have already been updated.
    #
    # COVERAGE, not the stored expiry. Every question below is "did what we are willing to serve fall", and
    # the stored value is the paid term with neither the store's grace nor our allowance on it. Comparing
    # raw values understates both sides: an Apple subscriber refunded during a 16-day grace has a raw prior
    # expiry of today-ish, which clears the day-boundary early-out below and returns without broadcasting —
    # while the proofs already signed certify the full grace-inclusive horizon.
    prior_expiry = account_coverage_end(get_user(tx.conn, master_pkey))

    # Bind any payment the mule registered that the owner has not claimed yet, BEFORE judging.
    # `_lookup_user_expiry` is user-scoped and `user_id` is set only at redemption, so an unclaimed-but-live
    # payment is invisible to that judgement: we would revoke every outstanding proof for an account whose
    # coverage never actually lapsed. Claim-all and idempotent — the same bind the owner's next request
    # performs, just early. Stamped with OUR clock, never `at`: a store's instant can be days old.
    reconcile_pending_payments(tx, master_pkey, redeemed_at=base.utc_now())
    _update_user_expiry_grace_and_renew_flag_from_payment_list(tx, master_pkey)

    # The honest question is the DELTA, so ask it first and exactly: if the account ends up covering at
    # least what it covered before, nothing already signed can overstate it, whatever moved underneath.
    # Both gates below test absolutes, which is nearly always the same thing and occasionally is not —
    # refunding a payment that was NOT the account's entitlement driver leaves `surviving` unchanged and far
    # out, clears the day boundary, and yet falls short of the 30-day cap, so without this it would revoke
    # every proof of an account whose entitlement never moved.
    surviving = _lookup_user_expiry(tx, master_pkey)
    surviving_now = (
        subscription_coverage_end(surviving.best_expiry, surviving.best_grace, surviving.best_auto_renewing)
        if surviving.best_expiry is not None
        else None
    )
    if surviving_now is not None and surviving_now >= prior_expiry:
        return False

    # An account that was ending within a grid period anyway is not worth an entry in the revocation list
    # every client fetches. A proof built against it can outlive this by the renewal lead plus two grid
    # periods: accepted, because the entitlement was ending regardless and the overreach is bounded.
    #
    # Denominated in the PROOF GRID, not in calendar days. It used to ask whether `prior_expiry` fell before
    # the next UTC midnight, which is a boundary that no longer governs anything this decision cares about —
    # proof expiries land on the account's own random grid, and nothing in the revocation machinery is
    # day-aligned (retention is denominated in proof lifetime, `effective_ts` is a stamp plus a delay, and
    # the served list is window-filtered rather than day-bucketed).
    #
    # That framing also made an ORDINARY LAPSE broadcast. A lapse drops coverage by exactly the allowance —
    # the renewal flag goes false, so `expiry + allowance` becomes `expiry` — which slips past the delta
    # gate above; this check then compared two instants within an allowance of each other, so it really
    # asked "did a midnight fall between them". For a term ending in the last hour before midnight it did,
    # and a subscription that quietly ended landed in a retained list. That rate is the allowance as a
    # fraction of a day: one lapse in twenty-four at the default hour, one in four if the setting is raised
    # to six hours ahead of maintenance — worst exactly when the knob is being used.
    #
    # The bound is not a loosening: the old rule already admitted a `prior_expiry` up to a full day past
    # `at` whenever `at` fell just after midnight. This accepts the same worst case uniformly instead of
    # letting the wall clock decide which accounts get it. Testing environments compress the grid, so the
    # comparison follows them without needing a provider-aware special case.
    if prior_expiry <= at + base.PROOF_EXPIRY_SHAPE.grid:
        return False

    # The furthest any outstanding proof can reach: a proof reaches at most `max_proof_lifetime` past its
    # request instant, and a request is only accepted within the clock tolerance, so nothing issued up to
    # now goes beyond this. If what survives covers that, every proof we have signed is still honest and
    # there is nothing to announce.
    if surviving_now is not None and surviving_now >= at + base.DEFAULT_TIMESTAMP_TOLERANCE + (
        base.PROOF_EXPIRY_SHAPE.max_proof_lifetime
    ):
        return False

    log.info(
        f'Revoking the outstanding proofs of {base.maybe_obfuscate_bytes(bytes(master_pkey))}: coverage fell from '
        f'{base.readable(prior_expiry)} to '
        f'{base.readable(surviving_now) if surviving_now is not None else "nothing"}'
    )
    revoke_master_pkey_proofs_and_allocate_new_gen_id(tx, master_pkey, created_at=at)
    return True


@db.transactional
def add_apple_revocation(
    tx: db.SQLTransaction, apple_original_tx_id: str, revoke_at: pendulum.DateTime, err: base.ErrorSink
) -> bool:
    """Revoke all the payments that aren't revoked that share the same original TX ID. Returns true
    if there were any rows that had the ID"""
    # TODO: Can be cleaned up more, a lot of repeated code between apple and google here, but it
    # works fine. Also, this code is very platform specific, potentially the grabbing of IDs should
    # happen in the platform layers and then the backend only deals with IDs. Potentially separating
    # such platform specific implementation concerns to the requisite platforms.

    # NOTE: Select the newest apple transaction that has been redeemed or not. apple only gives us
    # the original TX ID token in the scenarios that we call this function.
    #
    # From there we need to find the previous plan using this ID which is shared across all payments
    # by the user which we can do by finding the newest most payment that is still valid to be used.

    # NOTE: We also grab payments that are already revoked. This is because Google sends the revoked
    # notification after it may have already expired or have been revoked. If we skip those, this
    # function will return false and the caller will erroneously assume it has failed when infact
    # what we're trying to communicate to the caller is that, the payment token they were trying to
    # modified, is indeed in a revoked/expired state (e.g. its idempotent to call this function) and
    # that entitlement has been revoked where necessary.
    rows_result = db.query(
        tx.conn,
        f'''
    SELECT p.id, u.master_pkey, p.expiry_at
    FROM   {PAYMENTS_FROM}
    WHERE  ad.original_tx_id = %(orig_tx)s;
    ''',
        orig_tx=apple_original_tx_id,
    )

    log.info(
        f'Revoking Apple payment (orig. TX ID={base.maybe_obfuscate(apple_original_tx_id)}, '
        f'revoke={base.readable(revoke_at)})'
    )
    rows = rows_result.fetchall()
    result: bool = revoke_payments_by_id_internal(tx, rows, revoke_at)
    if not result:
        err.msg_list.append(
            f'Failed to revoke Apple orig. TX ID {base.maybe_obfuscate(apple_original_tx_id)} '
            f'at {base.readable(revoke_at)}, '
            f'no matching payments were found'
        )

    return result


@db.transactional
def reinstate_apple_payment(
    tx: db.SQLTransaction,
    apple_original_tx_id: str,
    apple_tx_id: str,
    auto_renewing: bool,
    reinstated_at: pendulum.DateTime,
) -> bool:
    """Reverse a prior Apple REFUND for a single transaction (a REFUND_REVERSED notification) — the mirror of
    add_apple_revocation. Un-revoke the payment identified by (original_tx_id, tx_id), restore the affected
    user's entitlement snapshot, and — only when their current generation is revoked AND the restored window
    is still live — move them onto a fresh generation (the old, already-broadcast token stays on the
    revocation list; it can't be un-broadcast). Un-revoking only clears revoked_at (revoke never touched
    expiry_at), so the ORIGINAL paid window is restored, never extended.

    A reversal lands days-to-weeks after the refund, so the window has often already lapsed by the time it
    arrives — then there is nothing live to serve and no generation work to do (a later renewal settles the
    generation).

    Returns whether a matching payment was found. Idempotent: a redelivery whose payment is already active is
    a no-op. An unknown transaction is logged CRITICAL and returns False but never raises/errs — a reversal
    always follows a refund we processed, so an unknown one is anomalous, yet it must not wedge the Apple
    notification pipeline / the missed-notification catch-up.
    """
    rows = db.query(
        tx.conn,
        f'''
        SELECT p.id, u.master_pkey
        FROM   {PAYMENTS_FROM}
        WHERE  ad.original_tx_id = %(orig_tx)s AND ad.tx_id = %(tx_id)s
    ''',
        orig_tx=apple_original_tx_id,
        tx_id=apple_tx_id,
    ).fetchall()

    if not rows:
        log.critical(
            f'Apple REFUND_REVERSED for an unknown transaction (orig. TX ID='
            f'{base.maybe_obfuscate(apple_original_tx_id)}, tx={base.maybe_obfuscate(apple_tx_id)}); '
            f'nothing to reinstate'
        )
        return False

    log.info(
        f'Reinstating Apple payment (orig. TX ID={base.maybe_obfuscate(apple_original_tx_id)}, '
        f'tx={base.maybe_obfuscate(apple_tx_id)}, reinstated={base.readable(reinstated_at)})'
    )

    master_pkeys: set[bytes] = set()
    for payment_id, master_pkey_raw in rows:
        # Clear the refund's revocation (idempotent) and restore auto-renew from the notification.
        db.query(
            tx.conn,
            '''
            UPDATE payments SET revoked_at = NULL, auto_renewing = %(auto_renewing)s WHERE id = %(id)s
        ''',
            auto_renewing=auto_renewing,
            id=payment_id,
        )
        if master_pkey_raw is not None:
            master_pkeys.add(bytes(master_pkey_raw))

    for master_pkey_bytes in master_pkeys:
        master_pkey = nacl.signing.VerifyKey(master_pkey_bytes)
        lookup = _lookup_user_expiry(tx, master_pkey)
        restored_coverage_end = (
            subscription_coverage_end(
                lookup.expiry_from_redeemed, lookup.grace_from_redeemed, lookup.auto_renewing_from_redeemed
            )
            if lookup.expiry_from_redeemed is not None
            else None
        )
        if restored_coverage_end is not None and restored_coverage_end > reinstated_at:
            # Live restored window: ensure the user is on a usable (non-revoked) generation — mints a fresh
            # one iff the refund had revoked the current one — and refresh their entitlement snapshot.
            _ensure_active_generation(tx, master_pkey, issued_at=reinstated_at)
        else:
            # The paid window has already lapsed: just restore the expiry snapshot; there are no live proofs
            # to serve, so no generation work (a later renewal will settle the generation).
            _update_user_expiry_grace_and_renew_flag_from_payment_list(tx, master_pkey)

    return True


@db.transactional
def add_google_revocation(
    tx: db.SQLTransaction, google_payment_token: str, revoke_at: pendulum.DateTime, err: base.ErrorSink
) -> bool:
    """Revoke all the payments that aren't revoked that share the same original TX ID. Returns true
    if there were any rows that had the ID"""

    # NOTE: Select the newest google transaction that has been redeemed or not. Google only gives us
    # the purchase token in the scenarios that we call this function.

    # NOTE: We also grab payments that are already revoked. This is because Google sends the revoked
    # notification after it may have already expired or have been revoked. If we skip those, this
    # function will return false and the caller will erroneously assume it has failed when infact
    # what we're trying to communicate to the caller is that, the payment token they were trying to
    # modified, is indeed in a revoked/expired state (e.g. its idempotent to call this function) and
    # that entitlement has been revoked where necessary.
    rows_result = db.query(
        tx.conn,
        f'''
    SELECT p.id, u.master_pkey, p.expiry_at
    FROM   {PAYMENTS_FROM}
    WHERE  gd.payment_token = %(token)s
    ''',
        token=google_payment_token,
    )

    log.info(
        f'Revoking Google payment (token={base.maybe_obfuscate(google_payment_token)}, '
        f'revoke={base.readable(revoke_at)})'
    )
    rows = rows_result.fetchall()
    result: bool = revoke_payments_by_id_internal(tx, rows, revoke_at)
    if not result:
        err.msg_list.append(
            f'Failed to revoke Google payment {base.maybe_obfuscate(google_payment_token)} '
            f'at {base.readable(revoke_at)}, '
            f'no matching payments were found'
        )

    return result


@db.transactional
def reconcile_pending_payments(
    tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey, redeemed_at: pendulum.DateTime
) -> int:
    """Redeem every unredeemed, unrevoked Google/Apple payment bound to `master_pkey`, link the claimed
    payments to the user, refresh entitlement, and return how many were newly claimed.

    The stores attest the account identifier AS a function of the master key — Google's
    obfuscatedAccountId is the pubkey verbatim, Apple's appAccountToken is uuid_from_master_pk(pubkey) —
    so holding the key IS the claim; there's no separate client-supplied token to match. This is the
    reconcile step every master-key-authenticated endpoint runs up front, so a payment the mule has
    already registered gets bound to its owner on the owner's next request, whichever endpoint that is.

    Claim-all: a key legitimately accumulates several unredeemed payments (e.g. a device offline across a
    couple of renewals). A no-match is not an error and touches nothing — in particular NO user row is
    created for a key with no payments, so a signed-but-payment-less status probe can't spawn users."""
    from providers import app_store

    def claim(detail_table: str, account_column: str, account_value: bytes | str) -> list[int]:
        # detail_table/account_column are module-internal literals (never request data), so interpolating
        # them is safe; the account value is always a bound parameter.
        rows = db.query(
            tx.conn,
            f'''
            UPDATE payments
            SET    redeemed_at = %(redeemed_at)s
            WHERE  id IN (SELECT payment_id FROM {detail_table} WHERE {account_column} = %(account)s)
              AND  redeemed_at IS NULL AND revoked_at IS NULL
            RETURNING id
            ''',
            redeemed_at=redeemed_at,
            account=account_value,
        )
        return [row[0] for row in rows.fetchall()]

    claimed = claim('google_play_payment_details', 'obfuscated_account_id', bytes(master_pkey))
    claimed += claim(
        'app_store_payment_details', 'app_account_token', app_store.uuid_from_master_pk(bytes(master_pkey))
    )
    if not claimed:
        return 0

    # master_pkey lives only in `users`: ensure the identity row (+ its generation) exists, link the
    # just-claimed payments to it, then refresh entitlement (reuses the current generation — a redeem
    # never rolls it, so the client's revocation_tag is untouched).
    user_id = get_or_create_user_and_generation(tx, master_pkey, issued_at=redeemed_at)[0]
    db.query(tx.conn, 'UPDATE payments SET user_id = %(user_id)s WHERE id = ANY(%(ids)s)', user_id=user_id, ids=claimed)
    _ensure_active_generation(tx, master_pkey, issued_at=redeemed_at)
    log.info(
        f'Redeemed {len(claimed)} payment(s) for {base.maybe_obfuscate_bytes(bytes(master_pkey))} '
        f'at {base.readable(redeemed_at)}'
    )
    return len(claimed)


def _redeem_payment_for_user(
    tx: db.SQLTransaction,
    master_pkey: nacl.signing.VerifyKey,
    payment_tx: base.PaymentProviderTransaction,
    redeemed_at: pendulum.DateTime,
) -> None:
    """Redeem ONE specific payment and link it to master_pkey's (already-existing) user, matched by the
    payment's OWN store identifier — Google (payment_token, order_id) / Apple tx_id — NOT by the
    master-key-derived account-id.

    Used by the renewal auto-redeem, where the owner was resolved from the store's subscription-continuity
    linkage (payment_token / original_tx_id → a prior, securely-bound payment). That linkage is the
    authority, so we deliberately never touch the appAccountToken UUID: the mule stays out of UUID matching
    entirely, so a (vanishingly unlikely) 122-bit appAccountToken collision can never make a renewal bind a
    stranger's payment. The account-id match stays confined to the client path, where the caller is the
    owner and "the new payer is the next to claim their own UUID" holds."""
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        detail_where = 'google_play_payment_details WHERE payment_token = %(token)s AND order_id = %(order_id)s'
        params: dict[str, typing.Any] = {
            'token': payment_tx.google_payment_token,
            'order_id': payment_tx.google_order_id,
        }
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        detail_where = 'app_store_payment_details WHERE tx_id = %(tx_id)s'
        params = {'tx_id': payment_tx.apple_tx_id}
    else:
        return

    row_result = db.query(
        tx.conn,
        f'''
        UPDATE payments
        SET    redeemed_at = %(redeemed_at)s,
               user_id     = (SELECT id FROM users WHERE master_pkey = %(master_pkey)s)
        WHERE  id IN (SELECT payment_id FROM {detail_where})
          AND  redeemed_at IS NULL AND revoked_at IS NULL
        RETURNING id
        ''',
        redeemed_at=redeemed_at,
        master_pkey=bytes(master_pkey),
        **params,
    )
    if row_result.fetchall():
        # Only refresh entitlement if we actually redeemed something (it may already be redeemed).
        _ensure_active_generation(tx, master_pkey, issued_at=redeemed_at)


def redeem_minted_payment(
    tx: db.SQLTransaction,
    master_pkey: nacl.signing.VerifyKey,
    payment_tx: base.PaymentProviderTransaction,
    redeemed_at: pendulum.DateTime,
) -> None:
    """Redeem ONE just-minted payment and bind it to master_pkey's user (creating the user + generation
    if needed), matched by the payment's OWN store identifier. This is the shared redeem for the minting
    path — the CLI `voucher` command and the `/dev/add_payment` route (see minting.py). Distinct from the
    two client-facing redeems: unlike reconcile_pending_payments it claims exactly the one minted payment
    rather than everything sharing the account-id, and unlike _redeem_payment_for_user it creates the user
    and also handles a directly granted payment, which has no store account-id to reconcile against."""
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        detail_where = 'google_play_payment_details WHERE payment_token = %(token)s AND order_id = %(order_id)s'
        params: dict[str, typing.Any] = {
            'token': payment_tx.google_payment_token,
            'order_id': payment_tx.google_order_id,
        }
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        detail_where = 'app_store_payment_details WHERE tx_id = %(tx_id)s'
        params = {'tx_id': payment_tx.apple_tx_id}
    elif payment_tx.provider == base.PaymentProvider.SessionFoundation:
        detail_where = 'stf_payment_details WHERE order_id = %(order_id)s'
        params = {'order_id': payment_tx.stf_order_id}
    else:
        raise base.ServerError(f'Cannot redeem a minted payment for provider: {payment_tx.provider}')

    user_id = get_or_create_user_and_generation(tx, master_pkey, issued_at=redeemed_at)[0]
    row_result = db.query(
        tx.conn,
        f'''
        UPDATE payments
        SET    redeemed_at = %(redeemed_at)s, user_id = %(user_id)s
        WHERE  id IN (SELECT payment_id FROM {detail_where})
          AND  redeemed_at IS NULL AND revoked_at IS NULL
        RETURNING id
        ''',
        redeemed_at=redeemed_at,
        user_id=user_id,
        **params,
    )
    assert len(row_result.fetchall()) == 1, 'a freshly-minted payment must redeem exactly once'
    _ensure_active_generation(tx, master_pkey, issued_at=redeemed_at)
    log.info(
        f'Redeemed minted payment ({payment_provider_tx_log_label_safe(payment_tx)}) to '
        f'{base.maybe_obfuscate_bytes(bytes(master_pkey))}'
    )


def verify_payment_provider_tx(payment_tx: base.PaymentProviderTransaction, err: base.ErrorSink):
    base.verify_payment_provider(payment_tx.provider, err)
    match payment_tx.provider:
        case base.PaymentProvider.GooglePlayStore:
            if len(payment_tx.google_order_id) == 0:
                err.msg_list.append('Google order id was not set')
            if len(payment_tx.google_payment_token) == 0:
                err.msg_list.append('Google payment token was not set')
        case base.PaymentProvider.iOSAppStore:
            if len(payment_tx.apple_tx_id) == 0:
                err.msg_list.append('Apple TX ID was not set')
            if len(payment_tx.apple_original_tx_id) == 0:
                err.msg_list.append('Apple original TX ID was not set')
        case base.PaymentProvider.SessionFoundation:
            if len(payment_tx.stf_order_id) == 0:
                err.msg_list.append('Session Foundation order ID was not set')
        case base.PaymentProvider.Nil:
            err.msg_list.append('Payment provider was set invalidly to nil')


@db.transactional
def _lookup_user_expiry(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> LookupUserExpiry:
    # NOTE: We grab the expired ones as well because if they have grace that payment's deadline
    # is later than the expiry period which may actually be the latest known expiry period
    #
    # By definition we can't lookup unredeemed payments because they don't have a master public key
    # registered for it yet (e.g. the user has not associated a master public key with the payment
    # yet by redeeming it).
    # All of a user's linked payments are redeemed-or-later (user_id is set only at redemption), so
    # filtering on user_id selects exactly those — unredeemed payments have no user_id.
    # redeemed/expired/revoked are then derived from the timestamps below.
    result_set = db.query(
        tx.conn,
        '''
        SELECT    p.expiry_at, p.grace_period, p.auto_renewing, p.redeemed_at,
                  p.payment_provider, ad.original_tx_id, gd.payment_token, rd.order_id, p.revoked_at,
                  p.credit_remaining, u.credits_checkpoint_at
        FROM      payments p
                  JOIN users u ON u.id = p.user_id
                  LEFT JOIN app_store_payment_details ad      ON ad.payment_id = p.id
                  LEFT JOIN google_play_payment_details gd     ON gd.payment_id = p.id
                  LEFT JOIN stf_payment_details rd ON rd.payment_id = p.id
        WHERE     u.master_pkey = %(master_pkey)s
        ORDER BY  p.id DESC
    ''',
        master_pkey=bytes(master_pkey),
    )

    # How far this account's credits have been drained; the same value on every row, carried along rather
    # than fetched separately. The credit total below is added to THIS instant rather than to `now`, so the
    # answer is a fixed instant: each drain pass advances the checkpoint by the span it charged and reduces
    # the total by the same amount, and any recompute between passes — a payment registered, a redeem, a
    # revocation — lands on the same value instead of walking forward. An account with no payments has no
    # rows here, and therefore no credits either, so the absent checkpoint cannot matter.
    credits_checkpoint_at: pendulum.DateTime | None = None
    # Live credits are summed, not maxed: each grants a length that stacks on top of coverage. Their own
    # `expiry_at` is a grant-time receipt value, so it is kept OUT of the max below — counting it there
    # as well would credit the same length twice. A SPENT credit (remaining zero) does go through the max
    # like a subscription: its window is necessarily in the past by then, so it can only ever win when
    # nothing else covers the account, which is exactly when it is the truthful answer.
    credit_total = pendulum.duration()

    used_google_tokens: set[str] = set()
    used_apple_orig_tx_ids: set[int] = set()
    used_stf_order_ids: set[str] = set()

    # The coverage the winners so far reach. Kept local rather than on the result: it is the comparison key,
    # not an answer — what the caller gets is the winner's raw expiry, and re-deriving coverage from that is
    # the two helpers' job.
    best_coverage: pendulum.DateTime | None = None
    best_coverage_from_redeemed: pendulum.DateTime | None = None

    # NOTE: Determine the user's latest expiry by enumerating all the payments and calculating
    # the expiry time (inclusive of the grace period if applicable)
    result = LookupUserExpiry()
    rows = typing.cast(list[tuple[typing.Any, ...]], result_set.fetchall())
    for row in rows:
        # Order matches the SELECT above; unpacking fails loudly if the column count ever drifts.
        (
            expiry_at,
            grace_period,
            auto_renewing,
            redeemed_at,
            payment_provider,
            apple_original_tx_id,
            google_payment_token,
            stf_order_id,
            revoked_at,
            credit_remaining,
            credits_checkpoint_at,
        ) = row

        # A live credit contributes its remaining length to the total and nothing to the max. A revoked
        # one contributes neither: the revoke path zeroes it, and until it does, a clawed-back credit must
        # not still be extending the account.
        if credit_remaining is not None and credit_remaining > pendulum.duration():
            if revoked_at is None:
                credit_total += credit_remaining
            continue

        # One row per billing cycle, but a subscription's cycles must not each contribute to the max — only
        # its most recent one is the entitlement. So collapse by whatever identifies the SUBSCRIPTION on
        # each provider: Google's `payment_token`, Apple's `original_transaction_id`, and for a directly
        # granted payment the order id, which has no cycles. Rows arrive newest-first (the SELECT orders by
        # id DESC), so the first of each group seen is the one that counts.
        #
        # Google's per-cycle order ids happen to encode the subscription in a prefix (`GPA.x`, `GPA.x..0`,
        # `GPA.x..1`), and this once grouped by parsing that. The token says the same thing without
        # depending on the format, is already joined here, and is not confused by a subscription whose
        # order-id base changes mid-life — which the prefix match would have split into two competing
        # subscriptions.
        seen_before = False
        if payment_provider == base.PaymentProvider.GooglePlayStore.value:
            if google_payment_token in used_google_tokens:
                seen_before = True
            else:
                used_google_tokens.add(google_payment_token)
        elif payment_provider == base.PaymentProvider.iOSAppStore.value:
            if apple_original_tx_id in used_apple_orig_tx_ids:
                seen_before = True
            else:
                used_apple_orig_tx_ids.add(apple_original_tx_id)
        elif payment_provider == base.PaymentProvider.SessionFoundation.value:
            if stf_order_id in used_stf_order_ids:
                seen_before = True
            else:
                used_stf_order_ids.add(stf_order_id)
        else:
            log.warning(
                f"Unrecognised payment provider in {row} for {base.maybe_obfuscate_bytes(master_pkey)}: "
                f"{payment_provider}"
            )
            continue

        if seen_before:
            continue

        # NOTE: If we're revoked, clamp the expiry to the revoke time (entitlement stops effective
        # there). `status` is derived, not stored — we work from the orthogonal facts (revoked ⟺
        # revoked_at set), never a flattened status. Whether a payment has *expired* is a separate,
        # now-relative concern handled downstream (get_pro_status / proof-expiry clamping) — it must
        # not gate what expiry the user is *entitled* to, so no wall-clock enters here.
        #
        # A clamp, never an assignment: a revocation stops entitlement, so it can only ever pull the end
        # EARLIER. A payment refunded after it had already lapsed keeps its own expiry — assigning would
        # instead hand the account coverage from its lapse up to the refund, and this value becomes
        # users.expiry_at, i.e. the wire's expiry_ts and the ceiling a proof is clamped against. Apple
        # reaches that case whenever it processes a refund for a subscription that has already ended.
        assert expiry_at is not None, 'a row reaching the max has an expiry: live credits are summed above'
        if revoked_at is not None:
            assert not auto_renewing
            expiry_at = min(expiry_at, revoked_at)

        # Compared on COVERAGE, stored RAW. The two differ, and each is right for its job: with a mix of
        # renewing and cancelled payments the one that covers the account furthest is not necessarily the
        # one with the latest paid-through date, so the winner has to be picked grace-inclusive — while what
        # gets stored is the true end of the paid term, because that is what a user is shown and what every
        # consumer re-derives coverage from through the two helpers.
        coverage_end = subscription_coverage_end(expiry_at, grace_period, bool(auto_renewing))

        # NOTE: A payment contributes to the "redeemed" entitlement iff it has been redeemed and not
        # revoked. (Expiry is deliberately excluded — see above.)
        is_redeemed = redeemed_at is not None and revoked_at is None
        if is_redeemed and (best_coverage_from_redeemed is None or coverage_end > best_coverage_from_redeemed):
            best_coverage_from_redeemed = coverage_end
            result.expiry_from_redeemed = expiry_at
            result.grace_from_redeemed = grace_period
            result.auto_renewing_from_redeemed = bool(auto_renewing)

        if best_coverage is None or coverage_end > best_coverage:
            best_coverage = coverage_end
            result.best_expiry = expiry_at
            result.best_grace = grace_period
            result.best_auto_renewing = bool(auto_renewing)

    # Credits extend whatever the subscriptions above cover, from the later of that coverage and the drain
    # checkpoint (a credit cannot be paying for a moment a subscription already paid for, nor for one
    # already charged against it). `best_grace`/`best_auto_renewing` stay attributed to the subscription
    # that won the max: a subscriber holding a voucher is still auto-renewing, whatever sets their expiry.
    if credit_total > pendulum.duration():
        if credits_checkpoint_at is None:
            # The mint sets the checkpoint, and the drain clears it only once every credit is spent, so a
            # live credit with no checkpoint is a broken invariant. Anchor on the coverage we do know
            # about rather than silently answering with 1970, and make the noise visible.
            log.warning(
                f'Live credit with no drain checkpoint for {base.maybe_obfuscate_bytes(master_pkey)}: '
                f'anchoring its remaining length on known coverage instead'
            )
        anchor = credits_checkpoint_at if credits_checkpoint_at is not None else base.EPOCH
        result.best_expiry = max(result.best_expiry, anchor) if result.best_expiry else anchor
        result.best_expiry += credit_total
        redeemed = result.expiry_from_redeemed
        result.expiry_from_redeemed = (max(redeemed, anchor) if redeemed else anchor) + credit_total
    return result


@db.transactional
def update_payment_renewal_info(
    tx: db.SQLTransaction,
    payment_tx: base.PaymentProviderTransaction,
    grace_period: pendulum.Duration | None,
    auto_renewing: bool | None,
    err: base.ErrorSink,
) -> bool:
    """
    Update a payment's grace period and/or auto renewing flag. Pass in `None` for the arguments
    you want to opt out of updating.
    """

    result = False
    verify_payment_provider_tx(payment_tx, err)
    if len(err.msg_list) > 0:
        return result

    if grace_period is None and auto_renewing is None:
        result = True
        return result

    # NOTE: Generate the fields to write to matching payment in the DB
    sql_set_fields: str = ''
    kwparams: dict[str, typing.Any] = {}
    if auto_renewing is not None:
        if len(sql_set_fields):
            sql_set_fields += ', '
        sql_set_fields += 'auto_renewing = %(auto_renewing)s'
        kwparams['auto_renewing'] = auto_renewing

    if grace_period is not None:
        if len(sql_set_fields):
            sql_set_fields += ', '
        sql_set_fields += 'grace_period = %(grace_period)s'
        kwparams['grace_period'] = grace_period

    # The providers differ ONLY in how a payment is identified, so that is all the match produces: a
    # `detail_table WHERE ...` fragment that both statements below share. Per-provider copies of the
    # statements themselves would need the read and the write kept in step three times over.
    payment_selector: str = ''
    match payment_tx.provider:
        case base.PaymentProvider.Nil:
            pass

        case base.PaymentProvider.GooglePlayStore:
            payment_selector = 'google_play_payment_details WHERE payment_token = %(token)s AND order_id = %(order_id)s'
            kwparams['token'] = payment_tx.google_payment_token
            kwparams['order_id'] = payment_tx.google_order_id

        case base.PaymentProvider.iOSAppStore:
            payment_selector = (
                'app_store_payment_details WHERE original_tx_id = %(orig_tx_id)s AND tx_id = %(tx_id)s'
                ' AND web_line_order_tx_id = %(line_order_tx_id)s'
            )
            kwparams['orig_tx_id'] = payment_tx.apple_original_tx_id
            kwparams['tx_id'] = payment_tx.apple_tx_id
            kwparams['line_order_tx_id'] = payment_tx.apple_web_line_order_tx_id

        case base.PaymentProvider.SessionFoundation:
            payment_selector = 'stf_payment_details WHERE order_id = %(stf_order_id)s'
            kwparams['stf_order_id'] = payment_tx.stf_order_id

    assert payment_selector, 'Nil is the only provider with no selector, and verify_payment_provider_tx rejects it'

    # What the row says now, so the log below can tell a change from a restatement. Two unrelated store
    # events legitimately write the same value — a cancellation, then the EXPIRED that follows it weeks
    # later, both clearing `auto_renewing` — and reporting the second as though a subscriber had just
    # cancelled invents an event. No lock, unlike the Google converge: nothing here depends on the read
    # being the row the UPDATE then touches, so a concurrent write can only make one log line stale, and
    # the write itself is unaffected either way.
    before = db.query_one(
        tx.conn,
        f'SELECT auto_renewing, grace_period FROM payments WHERE id IN (SELECT payment_id FROM {payment_selector})',
        **kwparams,
    )

    result_set = db.query(
        tx.conn,
        f'''
        UPDATE    payments
        SET       {sql_set_fields}
        WHERE     id IN (SELECT payment_id FROM {payment_selector})
        RETURNING (SELECT master_pkey FROM users WHERE users.id = payments.user_id)
    ''',
        **kwparams,
    )

    # NOTE: A `RETURNING` clause seems to break rowcount (returns 0 even on row modification), so we
    # use fetchone instead. The RETURNING expression resolves the payment's owner master_pkey via the
    # users FK (NULL if the payment isn't redeemed yet).
    row = result_set.fetchone()
    result = row is not None

    # Phrased as what the store just told us about the subscription rather than as "renewal info updated":
    # these arrive when a subscriber cancels, resubscribes, or is granted a grace period, and that is what
    # someone reads the line to find out. Reported after the write, so the line records what happened rather
    # than what was attempted — the no-matching-payment case is reported through `err` below instead.
    if result and before is not None:
        old_auto_renewing, old_grace = before
        changes: list[str] = []
        if auto_renewing is not None and auto_renewing != old_auto_renewing:
            changes.append('will renew' if auto_renewing else 'cancelled; will not renew')
        if grace_period is not None and grace_period != old_grace:
            changes.append(f'granted a grace period of {grace_period.in_words()}')

        label = payment_provider_tx_log_label_safe(payment_tx)
        if changes:
            log.info(f'Payment ({label}): {"; ".join(changes)}')
        elif log.getEffectiveLevel() <= logging.DEBUG:
            log.debug(f'Payment ({label}): the store restated what we already had')

    # NOTE: Update the user's expiry to the latest known expiry
    if row and row[0]:
        master_pkey_bytes: bytes = bytes(row[0])
        _update_user_expiry_grace_and_renew_flag_from_payment_list(tx, nacl.signing.VerifyKey(master_pkey_bytes))

    if not result:
        payment_id = ''
        if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
            payment_id = payment_tx.google_order_id
        elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
            payment_id = payment_tx.apple_tx_id
        else:
            payment_id = payment_tx.stf_order_id
        err.msg_list.append(
            f'Updating payment TX failed, no matching payment found for '
            f'{payment_tx.provider.name} {base.maybe_obfuscate(payment_id)}'
        )
    return result


@db.transactional
def _insert_payment_row(
    tx: db.SQLTransaction,
    payment: dict[str, typing.Any],
    detail_table: str,
    detail: dict[str, typing.Any],
    dedup_keys: list[str],
) -> bool:
    """INSERT a payment atomically IFF no row in `detail_table` already matches on `dedup_keys` (a subset of
    `detail`'s columns, which must be covered by a UNIQUE constraint). Returns whether a row was inserted.

    A single CTE writes the provider-agnostic `payment` columns into `payments` — gated on the dedup key
    being absent — then the provider-specific `detail` columns keyed by the new id, so a duplicate inserts
    *neither* row (no orphaned `payments` entry). The `NOT EXISTS` guard is only the fast path: two writers
    racing on the same key both pass it, but the loser then trips `detail_table`'s UNIQUE constraint and
    raises — the constraint, not the guard, is what actually guarantees no duplicate.

    Each dict is self-aligning — the column name lives with its value, so there is no pair of parallel
    lists to drift out of index-lock; placeholders are generated from the same keys.
    """

    def columns_and_placeholders(cols: typing.Iterable[str]) -> tuple[str, str]:
        cols = list(cols)
        return ', '.join(cols), ', '.join(f'%({column})s' for column in cols)

    p_columns, p_placeholders = columns_and_placeholders(payment)
    d_columns, d_placeholders = columns_and_placeholders(detail)
    dedup_where = ' AND '.join(f'{key} = %({key})s' for key in dedup_keys)

    inserted = db.query_one(
        tx.conn,
        f'''
        WITH inserted AS (
            INSERT INTO payments ({p_columns})
            SELECT {p_placeholders}
            WHERE NOT EXISTS (SELECT 1 FROM {detail_table} WHERE {dedup_where})
            RETURNING id
        )
        INSERT INTO {detail_table} (payment_id, {d_columns})
        SELECT inserted.id, {d_placeholders} FROM inserted
        RETURNING payment_id
    ''',
        {**payment, **detail},
    )
    return inserted is not None


@db.transactional
def add_unredeemed_payment(
    tx: db.SQLTransaction,
    payment_tx: base.PaymentProviderTransaction,
    plan: base.ProPlan,
    expiry_at: pendulum.DateTime | None,
    purchased_at: pendulum.DateTime,
    platform_refund_expiry_at: pendulum.DateTime,
    platform_obfuscated_account_id: bytes | str,
    err: base.ErrorSink,
    needs_ack: bool = False,
    credit_remaining: pendulum.Duration | None = None,
    auto_renewing: bool = True,
):
    """Record a payment nobody has claimed yet.

    `credit_remaining` marks the row as a one-shot CREDIT with that much length left to give (see
    schema/004): a store subscription leaves it None, since its `expiry_at` already states an absolute
    paid-through instant.

    `auto_renewing` comes from the caller because only the caller knows. It is not derivable from the
    provider (a store sells both renewing subscriptions and one-time products) nor from whether the payment
    is a credit (a one-time store product is neither renewing nor a credit). The default suits the
    auto-renewing subscriptions that are all any provider registers today; anything else must say so."""

    # Says what is being recorded, not what state it will end in: this function may auto-redeem the payment
    # a few dozen lines below, so calling it "unredeemed" here described something that was true for about a
    # millisecond. The outcome is logged at the auto-redeem instead. `purchased` is the STORE's purchase
    # instant -- it was previously labelled `unredeemed`, which named a different concept entirely.
    if log.getEffectiveLevel() <= logging.INFO:
        payment_tx_label = payment_provider_tx_log_label_safe(payment_tx)
        log.info(
            f'Registering payment (payment={payment_tx_label}, plan={plan.name}, '
            f'expiry={base.readable(expiry_at) if expiry_at else "on exhaustion"}, '
            f'purchased={base.readable(purchased_at)}, '
            f'refund={base.readable(platform_refund_expiry_at)})'
        )

    verify_payment_provider_tx(payment_tx, err)
    if len(err.msg_list) > 0:
        return

    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        assert isinstance(platform_obfuscated_account_id, bytes)
        assert len(platform_obfuscated_account_id) == 32

        # Insert IFF this (token, order_id) isn't already recorded — Google reuses payment_token across
        # billing cycles, so order_id is what distinguishes them. Dedup + atomicity come from the
        # UNIQUE(payment_token, order_id) constraint inside _insert_payment_row's CTE.
        _insert_payment_row(
            tx,
            payment={
                'plan': plan.value,
                'payment_provider': payment_tx.provider.value,
                'expiry_at': expiry_at,
                'platform_refund_expiry_at': platform_refund_expiry_at,
                'purchased_at': purchased_at,
                'auto_renewing': auto_renewing,
                'credit_remaining': credit_remaining,
            },
            detail_table='google_play_payment_details',
            detail={
                'payment_token': payment_tx.google_payment_token,
                'order_id': payment_tx.google_order_id,
                'obfuscated_account_id': platform_obfuscated_account_id,
                # Outstanding Google purchase-ack obligation. The mule's sweep acks and clears it; a
                # fresh, not-yet-acknowledged purchase sets it TRUE (renewals arrive acknowledged).
                'needs_ack': needs_ack,
            },
            dedup_keys=['payment_token', 'order_id'],
        )

    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        assert isinstance(platform_obfuscated_account_id, str)
        # Insert IFF this apple payment isn't already recorded. apple_tx_id is always unique;
        # apple_web_line_order_tx_id is unique per billing cycle of the subscription; apple_original_tx_id is
        # reused across all subscriptions of the same type. Dedup + atomicity come from the
        # UNIQUE(original_tx_id, tx_id, web_line_order_tx_id) constraint inside _insert_payment_row's CTE.
        _insert_payment_row(
            tx,
            payment={
                'plan': plan.value,
                'payment_provider': payment_tx.provider.value,
                'expiry_at': expiry_at,
                'platform_refund_expiry_at': platform_refund_expiry_at,
                'purchased_at': purchased_at,
                'auto_renewing': auto_renewing,
                'credit_remaining': credit_remaining,
            },
            detail_table='app_store_payment_details',
            detail={
                'original_tx_id': payment_tx.apple_original_tx_id,
                'tx_id': payment_tx.apple_tx_id,
                'web_line_order_tx_id': payment_tx.apple_web_line_order_tx_id,
                'app_account_token': platform_obfuscated_account_id,
            },
            dedup_keys=['original_tx_id', 'tx_id', 'web_line_order_tx_id'],
        )
    elif payment_tx.provider == base.PaymentProvider.SessionFoundation:
        # Insert IFF this stf order id isn't already recorded. Dedup + atomicity come from the
        # UNIQUE(order_id) constraint inside _insert_payment_row's CTE.
        _insert_payment_row(
            tx,
            payment={
                'plan': plan.value,
                'payment_provider': payment_tx.provider.value,
                'expiry_at': expiry_at,
                'platform_refund_expiry_at': platform_refund_expiry_at,
                'purchased_at': purchased_at,
                'auto_renewing': auto_renewing,
                'credit_remaining': credit_remaining,
            },
            detail_table='stf_payment_details',
            detail={'order_id': payment_tx.stf_order_id},
            dedup_keys=['order_id'],
        )

    # NOTE: Find the latest master pkey associated with the common payment identifier (google payment
    # token or apple original tx id). Then find the user if it exists, if the user is still entitled
    # to Session Pro or is in grace, or in account hold, then, we've noticed a new payment for their
    # account.
    #
    # For UX we will automatically redeem the payment in this window and assign it to that public
    # key so that they automatically continue their Pro entitlement across the billing cycle without
    # needing their originating device to be on to "claim" the payment (because only the originating
    # device and the backend knows the confidential payment data it needs to provide to redeem).
    #
    # If the user is no outside of the account hold windows or cancelled their subscription then,
    # the next time they purchase a pro membership the Session account that the purchase was made
    # under will be the one that claims the initial payment. The auto-redeeming will be disabled
    # because the user is not in the auto-redeeming window.
    #
    # So the backend tries automatically redeem the payment on behalf of the user (if it seems
    # reasonable to do so according to that heuristic) for UX.
    master_pkey_set: db.Result | None = None
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        master_pkey_set = db.query(
            tx.conn,
            ('''
            SELECT   u.master_pkey
            FROM     payments p JOIN users u ON u.id = p.user_id
                     JOIN google_play_payment_details gd ON gd.payment_id = p.id
            WHERE    gd.payment_token = %s
            ORDER BY p.id DESC
            LIMIT    1
        '''),
            payment_tx.google_payment_token,
        )
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        master_pkey_set = db.query(
            tx.conn,
            ('''
            SELECT   u.master_pkey
            FROM     payments p JOIN users u ON u.id = p.user_id
                     JOIN app_store_payment_details ad ON ad.payment_id = p.id
            WHERE    ad.original_tx_id = %s
            ORDER BY p.id DESC
            LIMIT    1
        '''),
            payment_tx.apple_original_tx_id,
        )
    elif payment_tx.provider == base.PaymentProvider.SessionFoundation:
        # TODO: There is currently no auto-redeeming for directly granted payments. These are currently
        # granted to a user directly by creating a voucher payment attributed under their master pro
        # public key. It would be possible to incorporate some UI in the clients to allow redeeming
        # via an order ID. The issuer would then give the user the order ID that they have to redeem
        # in their client.
        pass

    if master_pkey_set:
        master_pkey_record = typing.cast(tuple[bytes] | None, master_pkey_set.fetchone())
        if master_pkey_record and master_pkey_record[0]:
            master_pkey = nacl.signing.VerifyKey(bytes(master_pkey_record[0]))
            user: UserRow = get_user(tx.conn, master_pkey)
            if user.found:
                # TODO: Handle the situation when a user cancels
                if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
                    # NOTE: Account hold as described by google
                    #
                    #   > [...] we’re increasing the default account hold duration on December 1, 2025.
                    #   > Starting on this date, by default account hold durations will be automatically
                    #   > calculated. Initially, the calculation will be 60 days minus any grace period
                    #   > duration, but we may change these calculations in the future to further
                    #   > improve recovery performance
                    #
                    # Source: https://support.google.com/googleplay/android-developer/answer/16631229
                    # Corroborated on the lifecycle page, which states the same calculation:
                    # https://developer.android.com/google/play/billing/lifecycle/subscriptions
                    # A flat 60 days, and it is EXACT rather than generous: the grace cancels out. The
                    # window in which a recovery can still arrive is the paid term plus grace plus hold, and
                    # Play sets hold to `60 days - grace`, so the sum is 60 days whatever the grace is set
                    # to. Subtracting grace here — as this once did — took it off a window it was never
                    # part of, and did so from a column that then held our own latency allowance rather
                    # than any store's grace, so the number removed was not even the one the formula names.
                    auto_redeem_deadline_at = user.expiry_at
                    if user.auto_renewing:
                        auto_redeem_deadline_at += 60 * base.DAY
                else:
                    assert payment_tx.provider == base.PaymentProvider.iOSAppStore
                    # Apple merges grace and account hold into one billing-retry period, so the window is
                    # the paid term plus whatever grace the store declared for this subscription. That is
                    # zero when no grace applies, which makes the test an equality on the boundary -- a
                    # contiguous renewal's purchase instant IS the previous cycle's expiry, so it passes
                    # with no margin. It is not zero once a grace period is configured in App Store
                    # Connect, which is the case this window was really written for.
                    auto_redeem_deadline_at = user.expiry_at
                    if user.auto_renewing:
                        auto_redeem_deadline_at += user.grace_period

                # The store's purchase instant against the deadline: inside it, this is a continuation of a
                # subscription we already know the owner of, so bind it for them rather than making the
                # payment wait for their next request.
                if purchased_at > auto_redeem_deadline_at:
                    # Outside the window: the subscription lapsed far enough that this is a fresh start
                    # rather than a continuation, so the payment waits for its owner to claim it. Logged
                    # because from the outside this is indistinguishable from an auto-redeem that failed.
                    log.info(
                        f'Payment left for its owner to claim '
                        f'(payment={payment_provider_tx_log_label_safe(payment_tx)}): purchased '
                        f'{base.readable(purchased_at)} is past the auto-redeem deadline '
                        f'{base.readable(auto_redeem_deadline_at)}'
                    )
                else:
                    # Bind THIS renewal to the owner we just resolved from the store's subscription
                    # continuity, matched by the renewal's own identifier — NOT the master-key-derived
                    # account-id. We already hold the full master key, so there's no need to route through
                    # the appAccountToken UUID, and deliberately not doing so keeps a mule-side renewal from
                    # ever claiming a stranger's payment on a (vanishingly unlikely) 122-bit UUID collision.
                    #
                    # A failed auto-redeem is swallowed: the user can still claim the payment later, and
                    # propagating the failure to the platform layers (google/apple) would stall them
                    # unnecessarily. The savepoint keeps a failed redeem from poisoning the outer
                    # transaction; we log it for internal visibility.
                    try:
                        with tx.conn.transaction():
                            # OUR clock, not `purchased_at`: this is when we bound the payment, and the
                            # store's instant can be days old by the time we see it (a catch-up drain, a
                            # backlog after an outage). `purchased_at` above is the store's own fact and
                            # belongs in the deadline test; it is not a redemption time.
                            _redeem_payment_for_user(tx, master_pkey, payment_tx, redeemed_at=base.utc_now())
                        log.info(
                            f'Auto-redeemed payment (payment={payment_provider_tx_log_label_safe(payment_tx)}) '
                            f'to the account that owns the previous cycle of this subscription'
                        )
                    except base.ApiError as e:
                        log.error(
                            f'Failed to auto-redeem a payment we witnessed from. '
                            f'(auto_redeem_deadline={base.readable(auto_redeem_deadline_at)}) {e}'
                        )


def mint_generation(tx: db.SQLTransaction, user_id: int, issued_at: pendulum.DateTime) -> tuple[int, bytes]:
    '''Insert a fresh generation (new random 32-byte token) for an existing user; returns
    (generation_id, token). Retries on a token-unique collision — astronomically unlikely for 32 CSPRNG
    bytes, but cheap insurance against a degraded RNG; each attempt is a savepoint so a collision can't
    poison the outer transaction.'''
    for _attempt in range(3):
        token = nacl.utils.random(BLAKE2B_DIGEST_SIZE)
        try:
            with tx.conn.transaction():
                row = db.query_one(
                    tx.conn,
                    "INSERT INTO generations (user_id, token, issued_at) VALUES (%s, %s, %s) RETURNING id",
                    user_id,
                    token,
                    issued_at,
                )
            assert row is not None
            return (row[0], token)
        except psycopg.errors.UniqueViolation:
            continue
    raise RuntimeError('mint_generation: exhausted token-collision retries (CSPRNG failure?)')


def get_or_create_user_and_generation(
    tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey, issued_at: pendulum.DateTime
) -> tuple[int, int, bytes, bool]:
    '''Ensure a user row AND its first generation exist for master_pkey. Race-free via ON CONFLICT on the
    master_pkey unique index. Returns (user_id, current_generation_id, token, was_created). Must run inside
    a transaction (the circular users<->generations FK is deferred to COMMIT).

    The caller must link at least one payment to the returned user in that SAME transaction, so a user is
    never committed without one. Nothing sweeps up a user that has no payments, so one committed without
    would be permanent.'''
    master_pkey_bytes = bytes(master_pkey)

    # Common path: the user already exists — a plain read, no id/generation allocation burned.
    existing = get_user(tx.conn, master_pkey)
    if existing.found:
        return (existing.id, existing.current_generation_id, existing.token, False)

    # New user: pre-allocate both ids so the circular NOT NULL FKs are satisfied at insert time (the
    # deferred users->generations FK is validated at COMMIT). Insert the user first (ON CONFLICT arbitrates
    # a concurrent create), then the generation it points at. The expiry here is a placeholder overwritten
    # by _allocate… below.
    seq_row = db.query_one(
        tx.conn,
        "SELECT nextval(pg_get_serial_sequence('users','id')), nextval(pg_get_serial_sequence('generations','id'))",
    )
    assert seq_row is not None
    user_id, gen_id = seq_row[0], seq_row[1]
    token = nacl.utils.random(BLAKE2B_DIGEST_SIZE)
    won = db.query_one(
        tx.conn,
        '''
        INSERT INTO users (id, master_pkey, current_generation_id, expiry_at, proof_expiry_offset)
        VALUES            (%(id)s, %(master_pkey)s, %(gen_id)s, to_timestamp(0), %(proof_expiry_offset)s)
        ON CONFLICT (master_pkey) DO NOTHING
        RETURNING id
    ''',
        id=user_id,
        master_pkey=master_pkey_bytes,
        gen_id=gen_id,
        # A seed value only: the placeholder expiry above is immediately overwritten by
        # _ensure_active_generation, and that write re-draws the offset along with it.
        proof_expiry_offset=new_proof_expiry_offset(),
    )
    if won is None:
        # Lost a concurrent create — re-read the winner (our pre-allocated ids simply go unused).
        winner = get_user(tx.conn, master_pkey)
        return (winner.id, winner.current_generation_id, winner.token, False)
    db.query(
        tx.conn,
        "INSERT INTO generations (id, user_id, token, issued_at) VALUES (%s, %s, %s, %s)",
        gen_id,
        user_id,
        token,
        issued_at,
    )
    return (user_id, gen_id, token, True)


def _ensure_active_generation(
    tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey, issued_at: pendulum.DateTime
) -> AllocatedGenID:
    # Refresh the user's top-level entitlement fields from their current best payment, and settle which
    # generation they're on. A generation is an EPOCH, not a per-payment value: REUSE the user's
    # current generation across payments — stacking, renewals, auto-redeem, natural-lapse reactivation — so
    # the revocation_tag stays stable (no per-payment revocation-list churn, no subscription-cadence leak).
    # Mint a FRESH generation only when the current one is REVOKED (reusing it would mint proofs born
    # already-revoked). The revoke path depends on exactly this: it sets revoked_at first, then calls here,
    # so it rolls onto a fresh generation. The user row must already exist (redeem creates it via
    # get_or_create_user_and_generation; revoke's user exists).
    # Start the drain clock for a credit that has just become this user's, BEFORE reading the entitlement
    # below: the fold anchors a credit's remaining length on this checkpoint, so setting it afterwards would
    # store an expiry dated from the epoch. Every path that claims a payment comes through here, so this is
    # the one place it cannot be forgotten — and forgetting it would leave a live credit that never drains,
    # i.e. a voucher that never expires. Only when currently NULL: resetting an existing checkpoint would
    # forgive whatever uncovered time has accrued against the account's other credits.
    db.query(
        tx.conn,
        '''
        UPDATE users
        SET    credits_checkpoint_at = %(at)s
        WHERE  master_pkey = %(master_pkey)s AND credits_checkpoint_at IS NULL
          AND  EXISTS (SELECT 1 FROM payments
                       WHERE user_id = users.id AND revoked_at IS NULL
                         AND credit_remaining > '0'::interval)
    ''',
        at=issued_at,
        master_pkey=bytes(master_pkey),
    )

    result = AllocatedGenID()
    lookup: LookupUserExpiry = _lookup_user_expiry(tx, master_pkey)
    result.expiry_at = lookup.expiry_from_redeemed
    if lookup.expiry_from_redeemed is None:
        return result  # no usable payment → nothing to allocate

    result.found = True
    user = get_user(tx.conn, master_pkey)
    assert user.found, "user must exist before allocating a generation"

    minted = is_generation_revoked(tx.conn, user.current_generation_id, issued_at)
    if minted:
        result.generation_id, result.token = mint_generation(tx, user.id, issued_at)
    else:
        result.generation_id, result.token = user.current_generation_id, user.token

    # A minted generation ALWAYS re-draws the offset, whatever the expiry did. The revocation that rolls the
    # tag is a shrink, so the extension-only rule alone would carry the offset across the one moment the
    # design deliberately unlinks an account's proofs — and the offset is ~16 bits, readable off every proof
    # (docs/limitations.md, "adds no cross-roll linkage"). Nothing is lost: monotonicity across a roll would
    # be protecting proofs that were just revoked, so there is no served expiry left to undercut.
    offset_value = '%(proof_random_offset)s' if minted else _offset_redrawn_if_expiry_extends(lookup.best_expiry)

    # A minted generation revokes every proof this account is holding, so all of its devices must re-fetch
    # at once — and those re-fetches are the SAME installs the window has already counted. Restarting it
    # with the tag stops an account being charged for an invalidation WE performed, which is what would
    # otherwise make a refund-then-resubscribe, or any billing arc that revokes, look like a fleet.
    #
    # Only on a mint. A renewal or a stacked payment reuses the generation, so the tag is unchanged and
    # existing proofs stay valid: no re-fetch is forced, and there is nothing to forgive. Resetting on every
    # payment would hand the same monthly amnesty to an account being shared, which does renew.
    window_reset = (
        ',\n               proofs_issued_window = 0'
        ',\n               proofs_issued_past_expiry_window = 0'
        ',\n               proofs_window_start = NULL'
        if minted
        else ''
    )

    db.query(
        tx.conn,
        f'''
        UPDATE users
        SET    current_generation_id        = %(gen_id)s,
               expiry_at                   = %(expiry)s,
               grace_period                 = %(grace)s,
               auto_renewing                = %(auto_renewing)s,
               proof_expiry_offset          = {offset_value}{window_reset}
        WHERE  id = %(user_id)s
    ''',
        gen_id=result.generation_id,
        user_id=user.id,
        expiry=lookup.best_expiry,
        grace=lookup.best_grace,
        auto_renewing=lookup.best_auto_renewing,
        proof_random_offset=new_proof_expiry_offset(),
    )
    result.grace_period = lookup.best_grace

    return result


@db.transactional
def drain_due_credits(tx: db.SQLTransaction, now: pendulum.DateTime, stale_after: pendulum.Duration) -> int:
    """Charge elapsed uncovered time against the credits of every account whose drain checkpoint is older
    than `stale_after`, and return how many accounts were visited.

    A credit is spent only while nothing else covers the account, so the charge is the span since that
    account's checkpoint — never an assumed interval — which makes a pass that runs late charge exactly
    what it should and a pass that runs twice charge nothing the second time. Coverage is sampled once,
    now: a subscription that lapsed part-way through the span is charged for the whole of it, and one that
    started part-way through is charged for none, each bounded by one interval and only at a genuine
    coverage transition (a renewal is not one — `expiry_at` moves before the old term lapses).

    SKIP LOCKED so a second runner, or an overlapping pass, cannot charge the same account twice."""
    due = db.query(
        tx.conn,
        '''
        SELECT   id, master_pkey, credits_checkpoint_at
        FROM     users
        WHERE    credits_checkpoint_at IS NOT NULL AND credits_checkpoint_at < %(cutoff)s
        ORDER BY credits_checkpoint_at
        FOR UPDATE SKIP LOCKED
    ''',
        cutoff=now - stale_after,
    )

    visited = 0
    for user_id, master_pkey_raw, checkpoint in typing.cast(list[tuple[typing.Any, ...]], due.fetchall()):
        visited += 1
        master_pkey = nacl.signing.VerifyKey(bytes(master_pkey_raw))

        # Is a SUBSCRIPTION covering this account right now? Deliberately computed from the subscription
        # rows and NOT from users.expiry_at: that already includes the credits' own remaining length, so a
        # credit would report the account as covered, protect itself from being charged, and never expire.
        coverage_rows = db.query(
            tx.conn,
            '''
            SELECT expiry_at, grace_period, auto_renewing
            FROM   payments
            WHERE  user_id = %(user_id)s AND revoked_at IS NULL AND credit_remaining IS NULL
        ''',
            user_id=user_id,
        )
        covered_now = any(
            subscription_coverage_end(expiry_at, grace_period, auto_renewing) > now
            for expiry_at, grace_period, auto_renewing in typing.cast(
                list[tuple[typing.Any, ...]], coverage_rows.fetchall()
            )
        )

        # Clamped at zero: a checkpoint ahead of `now` (a clock stepping back, a future-dated pass) must
        # never hand length BACK to a credit.
        budget = pendulum.duration() if covered_now else max(now - checkpoint, pendulum.duration())

        live_rows = db.query(
            tx.conn,
            '''
            SELECT   id, credit_remaining
            FROM     payments
            WHERE    user_id = %(user_id)s AND revoked_at IS NULL AND credit_remaining > '0'::interval
            ORDER BY purchased_at, id
        ''',
            user_id=user_id,
        )
        live = [
            CreditToDrain(payment_id=row[0], remaining=row[1])
            for row in typing.cast(list[tuple[typing.Any, ...]], live_rows.fetchall())
        ]
        remaining_before = {credit.payment_id: credit.remaining for credit in live}
        drained = drain_credits(live, budget)

        # Walk the charges in consumption order so an emptied credit can be dated: its length ran out at the
        # checkpoint plus everything charged up to and including it. `expiry_at` is a receipt value for a
        # credit (unlike a subscription, where the store owns it), and this is the one thing that writes it
        # after the mint — so that a spent credit states when it really ran out rather than what it was
        # worth on the day it was granted.
        spent_so_far = pendulum.duration()
        for payment_id, new_remaining in drained.updated:
            spent_so_far += remaining_before[payment_id] - new_remaining
            emptied_at = checkpoint + spent_so_far if new_remaining == pendulum.duration() else None
            if emptied_at is not None:
                log.info(
                    f'Credit {payment_id} of {base.maybe_obfuscate_bytes(bytes(master_pkey))} ran out at '
                    f'{base.readable(emptied_at)}'
                )
            elif log.getEffectiveLevel() <= logging.DEBUG:
                log.debug(
                    f'Charged {(remaining_before[payment_id] - new_remaining).in_words()} against credit '
                    f'{payment_id} of {base.maybe_obfuscate_bytes(bytes(master_pkey))}; '
                    f'{new_remaining.in_words()} left'
                )
            db.query(
                tx.conn,
                '''
                UPDATE payments
                SET    credit_remaining = %(remaining)s,
                       expiry_at       = COALESCE(%(emptied_at)s, expiry_at)
                WHERE  id = %(payment_id)s
            ''',
                remaining=new_remaining,
                emptied_at=emptied_at,
                payment_id=payment_id,
            )

        # If the credits ran out partway through this span, the checkpoint is the instant they ran out, not
        # `now`: the account's expiry is derived as checkpoint + what remains, so with nothing remaining and
        # a checkpoint of `now` it would walk forward by an interval on every pass and hand out free time.
        checkpoint_next = checkpoint + drained.spent if drained.exhausted else now
        db.query(
            tx.conn,
            'UPDATE users SET credits_checkpoint_at = %(at)s WHERE id = %(user_id)s',
            at=checkpoint_next,
            user_id=user_id,
        )
        _update_user_expiry_grace_and_renew_flag_from_payment_list(tx, master_pkey)

        # Stop visiting an account with nothing left to charge — but only AFTER the refresh above, which
        # needs the checkpoint to date the entitlement the credits just finished providing.
        db.query(
            tx.conn,
            '''
            UPDATE users SET credits_checkpoint_at = NULL
            WHERE  id = %(user_id)s
              AND  NOT EXISTS (SELECT 1 FROM payments
                               WHERE user_id = %(user_id)s AND revoked_at IS NULL
                                 AND credit_remaining > '0'::interval)
        ''',
            user_id=user_id,
        )

    return visited


def make_generate_pro_proof_message(
    master_pkey: nacl.signing.VerifyKey, rotating_pkey: nacl.signing.VerifyKey, request_at: pendulum.DateTime
) -> bytes:
    '''The message the user signs to authorise a new rotating_pkey for master_pkey's Session Pro
    subscription.'''
    return signed_message(GENERATE_PROOF_DOMAIN, master_pkey, rotating_pkey, request_at)


def build_proof_message(
    revocation_tag: bytes, rotating_pkey: nacl.signing.VerifyKey, expiry_at: pendulum.DateTime
) -> bytes:
    '''The message the backend signs to certify a proof.'''
    return signed_message(BUILD_PROOF_DOMAIN, revocation_tag, rotating_pkey, expiry_at)


def _build_proof_clamped_expiry_time(
    request_at: pendulum.DateTime, proposed_expiry_at: pendulum.DateTime, proof_expiry_offset: int
) -> pendulum.DateTime:
    '''How far ahead a proof issued at `request_at` certifies, given the account's true (grace-inclusive)
    entitlement end and its stored per-account offset:

        round_up_onto_grid( min(request_at + clamp, true) + renewal_lead )

    where the grid is this account's own, `{ UTC midnight + proof_expiry_offset + k * one day }`.

    Clamp, pad, then round up. Two arms come out of the `min`: while the subscription still has more than
    the clamp left the expiry SLIDES with the request (a rolling ~30 d proof lifetime, so a lost or leaked
    proof self-expires); as the subscription end comes into range the expiry PINS near it.

    The round-up onto the grid is what makes both arms safe to publish. Landing on a grid point means the
    expiry is constant for a whole period and then steps by exactly one: two of a user's devices asking at
    different moments in the same period get identical proofs, and the value carries only which period the
    request fell in, never the instant.

    * The offset (uniform over one period, re-drawn each cycle) is what stops the pinned expiry from BEING
      the account's exact true expiry, which would otherwise publish the precise purchase/renewal instant
      as a stable time-of-day fingerprint and, via midnight-vs-not, the plan cadence — all readable by any
      conversation partner. It equally stops clients herding into one minute at renewal time, which is what
      any deterministic expiry (a plain day boundary, or the plan anniversary) does. An observer can read
      the offset straight off the wire (`expiry_ts` modulo the period) but gains nothing by it: `true` is
      still only pinned to within one period, and the offset is a random per-cycle value, less identifying
      than the `revocation_tag` already in the proof. Note the rounding only ever goes UP — pulling an
      expiry DOWN onto a boundary would advertise an end up to a period BEFORE the entitlement really
      ends, and the renewal payment may well not have arrived by then.
    * `renewal_lead` (1 h 1 min) keeps a renewing client's attempt on the correct side of `true`. A client
      starts renewing one hour before its proof expires, so the attempt lands no earlier than
      `min(...) + 60 s` — at least a minute past `true` in the pinned arm, since rounding up only pushes it
      later — and `true` is grace-inclusive, i.e. the last instant an upstream store might still notify us
      of the renewal. The 60 s absorbs a client clock running up to a minute fast so it still cannot fire
      early. This is a LOCKED PAIR with the client's one-hour lead: a client that renews earlier needs a
      matching change here, or its attempts start landing before the renewal can have resolved.

    The cost is over-provisioning: an account is honoured for up to one period past `true + renewal_lead`.
    That is deliberate (it also buffers a late store notification), and re-drawing the offset on every
    extension keeps the luck from settling on the same accounts. `shape.max_proof_lifetime` bounds the
    resulting proof lifetime.
    '''
    shape = base.PROOF_EXPIRY_SHAPE
    # The stored column's own range (a day — the schema CHECK), NOT the current shape's: a database written
    # before the shape changed still holds day-wide offsets, which the grid helper reduces modulo the period.
    assert 0 <= proof_expiry_offset < base.PROOF_EXPIRY_SHAPE.offset_range
    clamped_expiry_at = min(request_at + shape.clamp, proposed_expiry_at)
    return base.round_datetime_up_onto_offset_grid(
        clamped_expiry_at + shape.renewal_lead, period=shape.grid, offset_seconds=proof_expiry_offset
    )


def build_proof(
    revocation_tag: bytes,
    rotating_pkey: nacl.signing.VerifyKey,
    expiry_at: pendulum.DateTime,
    signing_key: nacl.signing.SigningKey,
) -> ProSubscriptionProof:
    # The revocation_tag is the generation's stored random token, embedded verbatim (no hashing).
    assert len(revocation_tag) == BLAKE2B_DIGEST_SIZE
    result: ProSubscriptionProof = ProSubscriptionProof()
    result.revocation_tag = revocation_tag
    result.rotating_pkey = rotating_pkey
    result.expiry_at = expiry_at

    message: bytes = build_proof_message(
        revocation_tag=result.revocation_tag, rotating_pkey=result.rotating_pkey, expiry_at=result.expiry_at
    )
    result.sig = signing_key.sign(message).signature
    return result


def internal_verify_add_payment_and_get_proof_common_arguments(
    signing_key: nacl.signing.SigningKey,
    master_pkey: nacl.signing.VerifyKey,
    rotating_pkey: nacl.signing.VerifyKey,
    message: bytes,
    master_sig: bytes,
    rotating_sig: bytes,
) -> None:
    # Verify the signatures first (authenticate that the message was not tampered with) — if these fail,
    # the rest of the payload is indeterminate, so raising bad_signature short-circuits everything else.
    # `message` is the signed message (variable length; built by make_*_message), signed directly — no
    # pre-hash — so there's no fixed-size assert here.
    try:
        master_pkey.verify(smessage=message, signature=master_sig)
    except Exception as e:
        raise base.FailError(
            f'Failed to verify signature from master key {base.maybe_obfuscate_bytes(master_pkey)}: {e}',
            code=base.ErrorCode.bad_signature,
        )

    try:
        rotating_pkey.verify(smessage=message, signature=rotating_sig)
    except Exception as e:
        raise base.FailError(
            f'Failed to verify signature from rotating key {base.maybe_obfuscate_bytes(rotating_pkey)}: {e}',
            code=base.ErrorCode.bad_signature,
        )

    # Dev/config sanity checks (the signing key never leaves the backend).
    assert bytes(signing_key) != ZERO_BYTES32 and bytes(signing_key.verify_key) != ZERO_BYTES32

    # Sanity check the signing key — a backend misconfiguration, not the client's fault.
    if signing_key.verify_key == master_pkey or signing_key.verify_key == rotating_pkey:
        raise base.ServerError('Internal key error during adding payment: please notify the devs')

    # Sanity check the user's keys and signatures (client-supplied → their fault).
    if master_pkey == rotating_pkey:
        raise base.FailError(
            f'Master and rotating key cannot be the same was: {base.maybe_obfuscate_bytes(master_pkey)}'
        )

    if bytes(master_pkey) == ZERO_BYTES32:
        raise base.FailError('Master key cannot be the zero key')

    if bytes(rotating_pkey) == ZERO_BYTES32:
        raise base.FailError('Rotating key cannot be the zero key')

    if master_sig == rotating_sig:
        raise base.FailError('Master and rotating signature cannot be the same')


@db.transactional
def revoke_master_pkey_proofs_and_allocate_new_gen_id(
    tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey, created_at: pendulum.DateTime
) -> AllocatedGenID:
    # Revoke the user's current generation (terminal): sets revoked_at, which blocks every proof issued
    # under that generation and (via the trigger) bumps the revocation ticket. The `revoked_at IS NULL`
    # guard makes a double-revoke a no-op rather than tripping the terminal-immutability trigger.
    #
    # `revoked_at` is stamped with OUR clock, read here, and is deliberately NOT `created_at` and NOT a
    # parameter. The served list turns this stamp into `effective_ts = revoked_at +
    # REVOCATION_EFFECTIVE_DELAY`, so it must mean "when we recorded the revocation", never "when the store
    # says the refund happened": a notification we process late (a backlog drained after an outage carries
    # refunds dated hours or days back) would otherwise be broadcast already-effective, and peers would
    # start rejecting the sender's proof before the sender could possibly have polled and learnt of it —
    # precisely the compose-then-truncate gap the delay exists to close. Reading the clock at the single
    # write site, rather than taking it from the caller, is what makes that unrepresentable: every caller
    # here holds a provider timestamp, and one passed in by mistake looks exactly like a correct argument.
    # `created_at` is the entitlement-side revoke instant (and the new generation's issued_at below);
    # `payments.revoked_at` likewise keeps the store's own date — the user really was entitled until then.
    db.query(
        tx.conn,
        '''
        UPDATE generations
        SET    revoked_at = %(recorded_at)s
        WHERE  id = (SELECT current_generation_id FROM users WHERE master_pkey = %(master_pkey)s)
          AND  revoked_at IS NULL
    ''',
        master_pkey=bytes(master_pkey),
        recorded_at=base.utc_now(),
    )

    # If the user still has usable payments, roll them onto a fresh generation for subsequent proofs.
    # Clients see the old generation revoked (via the revocation list) and re-query for a new proof.
    result = _ensure_active_generation(tx, master_pkey, issued_at=created_at)
    return result


def _record_proof_issued(tx: db.SQLTransaction, user_id: int, issued_at: pendulum.DateTime, past_expiry: bool) -> int:
    """Count one proof against `user_id` and return how many of this window's are subject to the limit.

    `past_expiry` says the account was past its paid-through instant when it asked — covered by store
    grace, our allowance, or the proof over-provision. Those are counted separately and are NOT what the
    return value reports, because in that regime the proof expiry is pinned: every re-fetch hands back the
    identical value, so a client whose renewal target has fallen inside the window re-asks indefinitely
    having been given nothing to act on. It is a paying subscriber with a late renewal, and no threshold
    can separate its traffic from a fleet's — see `schema/009_proof_issue_counters.sql`.

    One statement, deliberately: the read-modify-write happens under the row lock the UPDATE takes, so two
    proof requests racing for one account each count once. Reading the row first and writing back a
    computed value would let concurrent requests — exactly what a shared seed produces — lose increments
    against each other, which is the case the counters exist to measure.

    The window restarts from `issued_at` rather than from `window_start + PROOF_ISSUE_WINDOW`: a rate is
    being measured, so an account that goes quiet for a month starts a fresh window on its next proof
    instead of being credited for the windows it sat out."""
    row = db.query_one(
        tx.conn,
        '''
        UPDATE users
        SET    proofs_issued_total  = proofs_issued_total + 1,
               proofs_issued_window = CASE WHEN proofs_window_start IS NULL
                                             OR %(now)s >= proofs_window_start + %(window)s
                                           THEN 1 ELSE proofs_issued_window + 1 END,
               proofs_issued_past_expiry_window =
                                      CASE WHEN proofs_window_start IS NULL
                                             OR %(now)s >= proofs_window_start + %(window)s
                                           THEN %(past_expiry)s::int
                                           ELSE proofs_issued_past_expiry_window + %(past_expiry)s::int END,
               proofs_window_start  = CASE WHEN proofs_window_start IS NULL
                                             OR %(now)s >= proofs_window_start + %(window)s
                                           THEN %(now)s ELSE proofs_window_start END
        WHERE  id = %(user_id)s
        RETURNING proofs_issued_window - proofs_issued_past_expiry_window
        ''',
        now=issued_at,
        window=base.PROOF_ISSUE_WINDOW,
        past_expiry=past_expiry,
        user_id=user_id,
    )
    assert row is not None, f'proof issued for user {user_id} that does not exist'
    return row[0]


@db.transactional
def build_current_entitlement_proof(
    tx: db.SQLTransaction,
    master_pkey: nacl.signing.VerifyKey,
    rotating_pkey: nacl.signing.VerifyKey,
    request_at: pendulum.DateTime,
    signing_key: nacl.signing.SigningKey,
) -> ProSubscriptionProof:
    '''Sign a proof for the user's CURRENT entitlement using their existing generation token (NO roll).
    Called by generate_pro_proof. Raises a FailError with the matching slug when
    there is nothing to sign: `not_subscribed` (no user row), `revoked` (current generation revoked),
    `expired` (entitlement lapsed past the clamped proof window).'''
    get_user = get_user_and_payments(tx, master_pkey)
    if get_user.user.master_pkey != bytes(master_pkey):
        raise base.FailError(
            f'User {bytes(master_pkey).hex()} does not have an active payment registered for it',
            code=base.ErrorCode.not_subscribed,
        )

    if is_generation_revoked(tx.conn, get_user.user.current_generation_id, request_at):
        raise base.FailError(f'User {bytes(master_pkey).hex()} payment has been revoked', code=base.ErrorCode.revoked)

    # Coverage, not the stored expiry: what we are willing to certify runs to the end of the window we are
    # willing to serve. Clamping against the raw term would stop a renewing subscriber's proofs at their
    # paid-through date, which is precisely the interval the allowance exists to cover — and it would break
    # the locked pair `_build_proof_clamped_expiry_time` documents, where our lead matches the client's.
    proof_expiry_at = _build_proof_clamped_expiry_time(
        request_at=request_at,
        proposed_expiry_at=account_coverage_end(get_user.user),
        proof_expiry_offset=get_user.user.proof_expiry_offset,
    )
    # The expiry we are willing to certify is the honest cut-off, so a lapsed account keeps getting proofs
    # (all with this same, stable expiry — the offset only moves when the true expiry does) until the
    # over-provision above genuinely runs out, up to ~25 h past its true expiry. That is the same
    # over-provision every live account gets, granted no further, and it keeps us consistent with the
    # `account_expiry_ts` we already handed the client.
    if request_at > proof_expiry_at:
        raise base.FailError(
            f'User {bytes(master_pkey).hex()} entitlement expired at '
            f'{base.readable(account_coverage_end(get_user.user))} '
            f'({base.readable(get_user.user.expiry_at)} + {get_user.user.grace_period} store grace '
            f'+ {base.RENEWAL_LATENCY_ALLOWANCE} allowance)',
            code=base.ErrorCode.subscription_expired,
            # Advisory, same as the success path, and the same THREE values rather than the expiry alone:
            # a client persists these into synced config and reads them back later — offline, at cold
            # start, on another device — long after this error code is gone, so a response that refreshes
            # one member of the trio has to refresh the others or leave durable state describing two
            # different instants.
            #
            # This path needs that most, not least. The transition that produces the refusal is typically a
            # cancel, which collapses the grace and the renewal flag while leaving the expiry exactly where
            # it was (`update_payment_renewal_info` writes `grace_period=None, auto_renewing=False` and
            # never touches `expiry_at`) — so the expiry is the one value here that did NOT change, and a
            # client left holding its cached grace reads itself as covered for the remainder of a store
            # dunning window we have already stopped honouring.
            #
            # Only on this slug — not_subscribed has no expiry, and revoked is a distinct state (its expiry
            # may be future).
            data={
                'account_expiry_ts': base.unix_seconds_from_datetime(get_user.user.expiry_at),
                'account_grace_period_duration': base.seconds_from_duration(account_grace_span(get_user.user)),
                'account_auto_renewing': get_user.user.auto_renewing,
            },
        )

    # Counted only once every entitlement check above has passed, so the counters measure proofs ISSUED
    # rather than requests attempted: a lapsed or revoked account hammering the endpoint never advances
    # them, and a cap can never be consumed by requests that were going to be refused anyway.
    #
    # Incremented BEFORE signing, and the cap judged on the value the UPDATE returns, so the check and the
    # count are one atomic step — a fleet sharing one seed cannot slip past a cap by racing. Raising here
    # rolls the increment back with the rest of the transaction, which is what keeps a refused request from
    # advancing the count it was refused by.
    #
    # `past_expiry` splits the count rather than the cap: a request from an account past its paid term is
    # recorded, and visibly so, but is not what the limit is judged on. Every renewing account crosses that
    # line on every billing cycle — the last proof before the term end always expires after it, so the
    # client's next wake is always on the far side — and while it is there the proof expiry is pinned, so a
    # late renewal turns one wake into an unbounded retry loop that no cap could survive.
    issued_this_window = _record_proof_issued(
        tx, get_user.user.id, request_at, past_expiry=request_at > get_user.user.expiry_at
    )
    if base.MAX_PROOFS_PER_WINDOW and issued_this_window > base.MAX_PROOFS_PER_WINDOW:
        # WARNING, not INFO: with a cap configured at all this cannot happen to an account renewing on its
        # own timer, so a line here means either a seed in circulation or a cap set too low. Both want a
        # human.
        log.warning(
            f'Proof rate limit hit (master={base.maybe_obfuscate_bytes(master_pkey)}, '
            f'{issued_this_window} > {base.MAX_PROOFS_PER_WINDOW} per {base.PROOF_ISSUE_WINDOW.in_words()})'
        )
        raise base.FailError(
            f'User {bytes(master_pkey).hex()} has been issued too many proofs this window',
            code=base.ErrorCode.rate_limited,
        )

    proof = build_proof(
        revocation_tag=get_user.user.token,
        rotating_pkey=rotating_pkey,
        expiry_at=proof_expiry_at,
        signing_key=signing_key,
    )
    # Advisory (unsigned) account entitlement end, from this same snapshot — the client's true
    # subscription horizon, distinct from the clamped proof expiry above.
    #
    # The TRUE end of the paid term, and deliberately NOT `max(…, proof.expiry_at)`. That max existed to
    # keep `expiry_at <= account_expiry_at` self-consistent, and buying it meant handing the owner a date
    # carrying the proof's random grid offset — up to a day out from the one they would put in a UI. The two
    # answer different questions: the proof's expiry is how long peers honour the credential, deliberately
    # over-provisioned; this is when the subscription actually ends. Confirmed with both client teams before
    # breaking it — libsession schedules renewal one hour before PROOF expiry, so nothing keys on this.
    proof.account_expiry_at = get_user.user.expiry_at
    # The span we serve past that expiry, derived from the SAME snapshot so the pair a client persists
    # cannot describe two different instants.
    proof.account_grace_period = account_grace_span(get_user.user)
    # The renewal flag from that same snapshot, so a client persisting the expiry above out of this
    # response persists the flag that qualifies it at the same time, instead of leaving whatever a
    # previous get_pro_status left behind.
    proof.account_auto_renewing = get_user.user.auto_renewing
    return proof


def generate_pro_proof(
    conn: psycopg.Connection,
    signing_key: nacl.signing.SigningKey,
    master_pkey: nacl.signing.VerifyKey,
    rotating_pkey: nacl.signing.VerifyKey,
    request_at: pendulum.DateTime,
    master_sig: bytes,
    rotating_sig: bytes,
) -> ProSubscriptionProof:
    # DEBUG, not INFO: a client re-requests its proof routinely, so this is request traffic rather than
    # something happening to a payment. The redeem it may trigger below reports itself at INFO.
    log.debug(f'Get pro proof (master={base.maybe_obfuscate_bytes(master_pkey)}, ts={base.readable(request_at)})')

    # Authenticate the request (raises FailError(bad_signature) / invalid_request on failure).
    message: bytes = make_generate_pro_proof_message(
        master_pkey=master_pkey, rotating_pkey=rotating_pkey, request_at=request_at
    )
    # Every outcome below is reported, so a proof request always ends in exactly one INFO line. Without the
    # refusal half, a client being turned away is indistinguishable from a client that never asked — and the
    # two have completely different causes.
    try:
        internal_verify_add_payment_and_get_proof_common_arguments(
            signing_key=signing_key,
            master_pkey=master_pkey,
            rotating_pkey=rotating_pkey,
            message=message,
            master_sig=master_sig,
            rotating_sig=rotating_sig,
        )

        with db.transaction(conn) as tx:
            # Reconcile first: claim any payment the mule has already registered for this key but that
            # hasn't been redeemed yet, so a client's post-purchase proof request binds it right here — no
            # separate redeem call. A no-op when there's nothing new. Then build the proof from the current
            # entitlement (build_current_entitlement_proof raises the truthful "no Pro" slug if there's
            # still nothing, which the client treats as "not yet — retry").
            reconcile_pending_payments(tx, master_pkey, redeemed_at=request_at)
            proof = build_current_entitlement_proof(tx, master_pkey, rotating_pkey, request_at, signing_key)
    except base.FailError as e:
        # The CODE, never `str(e)`: those messages carry the master key unobfuscated, and this is the one
        # place a refusal reaches a log file. Re-raised untouched — the wire envelope is the caller's.
        log.info(f'Refused Pro proof (master={base.maybe_obfuscate_bytes(master_pkey)}, reason={e.code.value})')
        raise

    # Logged after the commit, and at INFO: signing a proof is the one action this endpoint exists to
    # perform, and this line is the only record of what was certified for whom and until when. The DEBUG
    # line above is the request that asked.
    log.info(
        f'Issued Pro proof (master={base.maybe_obfuscate_bytes(master_pkey)}, '
        f'rotating={base.maybe_obfuscate_bytes(rotating_pkey)}, '
        f'expiry={base.readable(proof.expiry_at)}, account expiry={base.readable(proof.account_expiry_at)})'
    )
    return proof


# Housekeeping deletes, one table each. All are pure storage reclamation: nothing here affects a live
# result, because every consuming query already self-guards (payment expiry is derived on read, the served
# revocation list filters by its retention window, a notification id absent from the history is simply
# unseen). So each can run on any schedule, any number of times, in any process, and a redundant run
# deletes nothing — hence no checkpoint, no windowing, no cross-process "only one wins" guard. Each is a
# single statement on an autocommit connection, so none of them needs a transaction, and they are separate
# calls so that one failing does not roll back the others.
#
# Users and payments are never deleted. Payments are the history /get_payment_details serves, and
# payments.user_id is a RESTRICT reference, so a user cannot be deleted for as long as one of their
# payments exists — which is always (see get_or_create_user_and_generation).


def delete_expired_revocations(conn: psycopg.Connection, now: pendulum.DateTime) -> int:
    """Delete revoked generations that have aged out of the served revocation list, returning the number
    removed.

    The cutoff is exactly the complement of the window get_pro_revocations serves (`revoked_at > now -
    REVOCATION_RETAIN_FOR`), so a row is only ever deleted once it can no longer appear in any response —
    keep the two in step. Dropping it is then invisible: REVOCATION_RETAIN_FOR is at least the maximum
    proof lifetime, so no proof still carrying this generation's token can be valid, and the token was
    random, so a later generation cannot collide with it.

    The `NOT EXISTS` is what makes this safe rather than merely tidy: a generation is a user's entitlement
    epoch, and `users.current_generation_id` is a NOT NULL FK to it, so the row a user is sitting on must
    survive however old its revocation is. In practice a live user is never that row (a revoked generation
    is replaced by a fresh one on the next entitlement change), but a user whose entitlement has not been
    touched since being revoked still points at it."""
    return db.query(
        conn,
        '''
        DELETE FROM generations g
        WHERE  g.revoked_at IS NOT NULL AND g.revoked_at <= %(cutoff)s
        AND    NOT EXISTS (SELECT 1 FROM users u WHERE u.current_generation_id = g.id)
        ''',
        cutoff=now - base.REVOCATION_RETAIN_FOR,
    ).rowcount


def delete_expired_apple_notification_uuids(conn: psycopg.Connection, now: pendulum.DateTime) -> int:
    """Delete Apple notification-dedupe rows whose expiry has passed, returning the number removed."""
    return db.query(conn, '''DELETE FROM apple_notification_uuid_history WHERE %s >= expires_at''', now).rowcount


def delete_expired_google_notifications(conn: psycopg.Connection, now: pendulum.DateTime) -> int:
    """Delete handled Google notification-history rows whose expiry has passed, returning the number
    removed. An unhandled row is kept regardless of age: it is the record that the notification still
    owes processing."""
    return db.query(
        conn, '''DELETE FROM google_notification_history WHERE %s >= expires_at AND handled = TRUE''', now
    ).rowcount


@db.transactional
def get_payment(
    tx: db.SQLTransaction, payment_tx: base.PaymentProviderTransaction, err: base.ErrorSink
) -> PaymentRow | None:
    result = None
    verify_payment_provider_tx(payment_tx, err)
    if err.has():
        return result

    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        result_set = db.query(
            tx.conn,
            f'''
            SELECT {PAYMENTS_COLUMNS}
            FROM {PAYMENTS_FROM}
            WHERE gd.payment_token = %(token)s AND gd.order_id = %(order_id)s
            ''',
            token=payment_tx.google_payment_token,
            order_id=payment_tx.google_order_id,
            row_factory=db.dict_row,
        )

        record = result_set.fetchone()
        if record:
            result = payment_row_from_dict(record)

    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        result_set = db.query(
            tx.conn,
            f'''
            SELECT {PAYMENTS_COLUMNS}
            FROM {PAYMENTS_FROM}
            WHERE ad.original_tx_id = %(orig_tx_id)s AND ad.tx_id = %(tx_id)s
                AND ad.web_line_order_tx_id = %(line_order_tx_id)s
            ''',
            orig_tx_id=payment_tx.apple_original_tx_id,
            tx_id=payment_tx.apple_tx_id,
            line_order_tx_id=payment_tx.apple_web_line_order_tx_id,
            row_factory=db.dict_row,
        )

        record = result_set.fetchone()
        if record:
            result = payment_row_from_dict(record)
    elif payment_tx.provider == base.PaymentProvider.SessionFoundation:
        result_set = db.query(
            tx.conn,
            f'SELECT {PAYMENTS_COLUMNS} FROM {PAYMENTS_FROM} WHERE rd.order_id = %s',
            payment_tx.stf_order_id,
            row_factory=db.dict_row,
        )

        record = result_set.fetchone()
        if record:
            result = payment_row_from_dict(record)

    return result


@db.transactional
def apple_add_notification_uuid(tx: db.SQLTransaction, uuid: str, expires_at: pendulum.DateTime):
    # uuid is the PRIMARY KEY; DO NOTHING keeps this idempotent (and crash-free) if the caller's
    # prior existence check raced with a concurrent insert of the same notification.
    db.query(
        tx.conn,
        ('''
        INSERT INTO apple_notification_uuid_history (uuid, expires_at)
        VALUES      (%s, %s)
        ON CONFLICT (uuid) DO NOTHING
    '''),
        uuid,
        expires_at,
    )


@db.transactional
def apple_notification_uuid_is_in_db(tx: db.SQLTransaction, uuid: str) -> bool:
    row = db.query_one(
        tx.conn,
        ('''
        SELECT 1
        FROM   apple_notification_uuid_history
        WHERE  uuid = %s
    '''),
        uuid,
    )
    result = row is not None
    return result


def apple_set_notification_checkpoint_at(tx: db.SQLTransaction, checkpoint_at: pendulum.DateTime):
    set_global_datetime(tx.conn, 'apple_notification_checkpoint_at', checkpoint_at)


@db.transactional
def google_add_notification_id(tx: db.SQLTransaction, message_id: str, expires_at: pendulum.DateTime, payload: str):
    maybe_payload: str | None = None
    if len(payload):
        maybe_payload = payload

    db.query(
        tx.conn,
        # ON CONFLICT because Pub/Sub is at-least-once: the same message can be delivered twice, and under
        # the streaming subscriber those deliveries can be in flight together. A check-then-insert lets both
        # pass the check, and the loser would raise on the primary key — turning a duplicate delivery, which
        # is normal, into a nacked message and a redelivery. Recording it once is the whole requirement.
        ('''
            INSERT INTO google_notification_history (message_id, handled, payload, expires_at)
            VALUES      (%(message_id)s, FALSE, %(payload)s, %(expiry)s)
            ON CONFLICT (message_id) DO NOTHING
    '''),
        message_id=message_id,
        payload=maybe_payload,
        expiry=expires_at,
    )


def google_set_notification_handled(tx: db.SQLTransaction, message_id: str, delete: bool) -> bool:
    if delete:
        rows = db.query(tx.conn, ('''DELETE FROM google_notification_history WHERE message_id = %s'''), message_id)
    else:
        rows = db.query(
            tx.conn,
            ('''UPDATE google_notification_history SET handled = TRUE, payload = NULL WHERE message_id = %s'''),
            message_id,
        )
    result: bool = rows.rowcount >= 1
    return result


def google_get_unhandled_notification_iterator(
    tx: db.SQLTransaction,
) -> collections.abc.Iterator[GoogleUnhandledNotificationIterator]:
    result_set = db.query(
        tx.conn, ('SELECT message_id, payload, expires_at FROM google_notification_history WHERE NOT handled')
    )
    return typing.cast(collections.abc.Iterator[GoogleUnhandledNotificationIterator], result_set)


@db.transactional
def google_notification_message_id_is_in_db(tx: db.SQLTransaction, message_id: str) -> GoogleNotificationMessageIDInDB:
    row = typing.cast(
        tuple[int] | None,
        db.query_one(tx.conn, '''SELECT handled FROM google_notification_history WHERE message_id = %s''', message_id),
    )
    result = GoogleNotificationMessageIDInDB()
    if row is not None:
        result.present = True
        result.handled = row[0] > 0  # NOTE: Should always be 0 or 1 but we'll be extra careful
    return result


def google_payment_tokens_needing_ack(conn: psycopg.Connection) -> list[tuple[str, pendulum.DateTime]]:
    """Google purchase-tokens with an outstanding acknowledgement, each with its EARLIEST purchase instant.

    The mule's sweep acks each against Google and clears the flag via google_clear_needs_ack. It gets
    `purchased_at` because that is the clock Google's three-day auto-refund runs on, so it is what tells the
    sweep whether a failing ack is a blip or an emergency. The earliest cycle of the token is the
    conservative choice: a token acknowledged as a whole is at risk from its oldest unacknowledged purchase.
    """
    rows = db.query(
        conn,
        '''SELECT   gd.payment_token, MIN(p.purchased_at)
           FROM     google_play_payment_details gd
                    JOIN payments p ON p.id = gd.payment_id
           WHERE    gd.needs_ack
           GROUP BY gd.payment_token''',
    )
    return [(row[0], row[1]) for row in rows]


@db.transactional
def google_clear_needs_ack(tx: db.SQLTransaction, payment_token: str) -> None:
    """Clear the acknowledgement obligation for every row of `payment_token` (a token is acknowledged as
    a whole, so all its billing-cycle rows clear together)."""
    db.query(
        tx.conn, '''UPDATE google_play_payment_details SET needs_ack = FALSE WHERE payment_token = %s''', payment_token
    )


def _log_google_convergence(
    payment_tx: base.PaymentProviderTransaction,
    old_expiry: pendulum.DateTime | None,
    old_auto_renewing: bool,
    old_grace: pendulum.Duration | None,
    new_expiry: pendulum.DateTime,
    new_auto_renewing: bool,
    new_grace: pendulum.Duration | None,
) -> None:
    """Report what a converge did to one payment: INFO when the row moved, DEBUG when it did not.

    The split is the whole point. A converge runs on every notification and every reconcile pass, and the
    great majority write back what was already there — an operator watching INFO wants the renewal, the
    cancellation and the grace period, not the several hundred confirmations that nothing changed.

    Phrased as what happened to the subscription rather than as a column diff, because the columns do not
    say it on their own: an expiry moving later is a renewal, unless a grace period appeared at the same
    time, in which case the term did not move at all and the store extended it (see the caller's docstring).
    """
    changes: list[str] = []
    if new_expiry != old_expiry:
        if old_expiry is None:
            changes.append(f'term set to {base.readable(new_expiry)}')
        elif new_expiry > old_expiry:
            changes.append(f'renewed through {base.readable(new_expiry)}')
        else:
            changes.append(f'term shortened to {base.readable(new_expiry)} (was {base.readable(old_expiry)})')

    # "store grace runs to", never "covered until": what we actually serve is that instant plus the renewal
    # latency allowance, which is ours and applied on read. Calling the store's number the coverage would
    # misreport the horizon by an hour to anyone reading this line to explain a proof.
    if new_grace != old_grace:
        if new_grace is None:
            changes.append('grace period ended')
        elif old_grace is None:
            changes.append(f'entered the store grace period, which runs to {base.readable(new_expiry + new_grace)}')
        else:
            changes.append(f'store grace period revised, now running to {base.readable(new_expiry + new_grace)}')

    if new_auto_renewing != old_auto_renewing:
        changes.append('renewal re-enabled' if new_auto_renewing else 'cancelled; will not renew')

    # Labelled the same way as every other payment line, so one account's history greps out of the log as a
    # whole rather than in provider-specific dialects.
    if changes:
        log.info(f'Payment ({payment_provider_tx_log_label_safe(payment_tx)}): {"; ".join(changes)}')
    elif log.getEffectiveLevel() <= logging.DEBUG:
        log.debug(
            f'Payment ({payment_provider_tx_log_label_safe(payment_tx)}): unchanged by the store snapshot '
            f'(expiry={base.readable(new_expiry)}, grace={new_grace}, auto_renewing={new_auto_renewing})'
        )


@db.transactional
def google_converge_payment(
    tx: db.SQLTransaction,
    payment_tx: base.PaymentProviderTransaction,
    expiry_at: pendulum.DateTime,
    auto_renewing: bool,
    in_grace: bool,
    needs_ack: bool,
    at: pendulum.DateTime,
    err: base.ErrorSink,
) -> bool:
    """Bring an existing payment row into line with what Google's subscription resource now says, and report
    whether a row was there to converge.

    This is the write half of "the notification is a hint, the resource is the truth". The store owns these
    values, so they are taken as stated rather than merged: a term Google has shortened, extended or deferred
    is simply what it now says. That is only possible because `expiry_at` is revisable — it used to be
    written once at insert, so the only way a new expiry could reach the database was a new order id, and a
    change that moved an expiry without starting a billing cycle was invisible.

    Two things the snapshot does NOT get to overrule:

    * A REVOKED row is terminal and is left entirely alone. Google reports a refunded subscription as
      expired, but it does not report *that money came back* — that arrives as its own RTDN — so converging
      a revoked row on the resource would quietly undo a refund we already recorded, and could extend its
      expiry past the instant entitlement actually stopped.
    * A CLAIMED row's ownership. Convergence adjusts the terms of a payment, never who holds it.

    `grace_period` is DERIVED here rather than taken from the caller, and this is the one place the two
    stores are made to look alike. Play applies grace by EXTENDING `expiryTime`, so the resource never states
    the paid-through date once a renewal has failed — but we already know it, because the previous
    notification stored it and this row still holds it. So when the resource says IN_GRACE_PERIOD and the new
    expiry is LATER than the one on file, the stored expiry is kept as the paid term and the difference
    becomes the grace, exactly as Apple's `gracePeriodExpiresDate - expiresDate` does.

    Coverage is identical either way — `expiry + grace + allowance` — but the split is what lets a client say
    "your payment failed on the 3rd, you have Pro until the 6th" instead of showing a renewal date that
    silently jumped forward.

    Anchoring on the STORED value, not on a computed one, is what keeps this idempotent: `expiry_at` stops
    moving for the duration of the grace, so re-converging the same snapshot recomputes the same difference
    and writes the same row. That matters beyond tidiness — a spurious move re-draws the account's
    proof-expiry offset, which is the privacy mechanism.

    Two limits worth knowing. If our FIRST sighting of a token is already in grace there is nothing to anchor
    on, so the extended expiry is stored as-is and the grace reads as zero; the property is "exact whenever
    we saw the term before it was extended", not "always". And this gates on the resource's
    `subscription_state`, never on the notification type — reading the store's own account of itself, which
    is the opposite of the type dispatch this pipeline deleted.

    Outside grace the column is written to NULL rather than left alone, deliberately: a row the retired
    `IN_GRACE_PERIOD` branch stamped with the base plan's real grace would otherwise keep that day forever,
    and it is exactly those rows that convergence would then double-count.

    Idempotency is the load-bearing property, not an optimisation: re-running this against an unchanged
    snapshot must leave `users.expiry_at` untouched, because a move there re-draws the account's
    proof-expiry offset, and a convergence pass that "changed" nothing on every run would hand an observer
    repeated samples against one true expiry — the exact attack the offset exists to prevent. Writing the
    same values is genuinely a no-op here, so the recompute below sees no movement.
    """
    verify_payment_provider_tx(payment_tx, err)
    if err.has():
        return False

    assert payment_tx.provider == base.PaymentProvider.GooglePlayStore, 'Google-only: keyed on (token, order id)'

    # Read the row before writing it, under the same predicates the UPDATE uses, so the log below can report
    # what actually moved rather than restating what we asked for — a converge that changes nothing is the
    # common case and must be distinguishable from one that renews, cancels or opens a grace period.
    #
    # `FOR UPDATE` is what makes the assert below sound, and the reconcile lease does not cover it: the lease
    # serialises drain against drain on one token, never drain against the notification thread stamping a
    # REVOKED. A revoke landing between the read and the write leaves the UPDATE matching nothing, and a
    # log line would then crash the drain.
    #
    # `OF p` locks the payments row only, so the assert additionally rests on `google_play_payment_details`'
    # key columns never being rewritten (`needs_ack` is the sole column anything updates, and nothing deletes
    # a detail row). That is convention, not constraint: a writer that moved a token or order id between
    # these two statements would make the assert reachable.
    before = db.query_one(
        tx.conn,
        '''
        SELECT p.expiry_at, p.auto_renewing, p.grace_period
        FROM   payments p JOIN google_play_payment_details gd ON gd.payment_id = p.id
        WHERE  gd.payment_token = %(token)s AND gd.order_id = %(order_id)s
          AND  p.revoked_at IS NULL
        FOR    UPDATE OF p
    ''',
        token=payment_tx.google_payment_token,
        order_id=payment_tx.google_order_id,
    )
    if before is None:
        # Either no such payment or a revoked one; both are "nothing to converge".
        return False
    old_expiry, old_auto_renewing, old_grace = before

    rows = db.query(
        tx.conn,
        '''
        UPDATE payments p
        SET    expiry_at     = CASE WHEN %(in_grace)s AND p.expiry_at IS NOT NULL
                                          AND %(expiry_at)s > p.expiry_at
                                    THEN p.expiry_at
                                    ELSE %(expiry_at)s END,
               auto_renewing = %(auto_renewing)s,
               grace_period  = CASE WHEN %(in_grace)s AND p.expiry_at IS NOT NULL
                                         AND %(expiry_at)s > p.expiry_at
                                    THEN %(expiry_at)s - p.expiry_at
                                    ELSE NULL END
        FROM   google_play_payment_details gd
        WHERE  gd.payment_id = p.id
          AND  gd.payment_token = %(token)s AND gd.order_id = %(order_id)s
          AND  p.revoked_at IS NULL
        RETURNING (SELECT master_pkey FROM users WHERE users.id = p.user_id),
                  p.expiry_at, p.auto_renewing, p.grace_period
    ''',
        token=payment_tx.google_payment_token,
        order_id=payment_tx.google_order_id,
        expiry_at=expiry_at,
        auto_renewing=auto_renewing,
        in_grace=in_grace,
    )

    # RETURNING breaks rowcount (see update_payment_renewal_info), so the fetch is what tells us whether a
    # row matched. It reports the values as WRITTEN, so the grace split is described by the rule that
    # performed it rather than by a second copy of that rule here.
    row = rows.fetchone()
    assert row is not None, 'the SELECT ... FOR UPDATE above matched, so the UPDATE must too'
    owner_pkey, new_expiry, new_auto_renewing, new_grace = row
    _log_google_convergence(
        payment_tx,
        old_expiry=old_expiry,
        old_auto_renewing=old_auto_renewing,
        old_grace=old_grace,
        new_expiry=new_expiry,
        new_auto_renewing=new_auto_renewing,
        new_grace=new_grace,
    )

    db.query(
        tx.conn,
        '''
        UPDATE google_play_payment_details SET needs_ack = %(needs_ack)s
        WHERE  payment_token = %(token)s AND order_id = %(order_id)s
    ''',
        token=payment_tx.google_payment_token,
        order_id=payment_tx.google_order_id,
        needs_ack=needs_ack,
    )

    # Only a claimed payment has an account whose entitlement could have moved; an unclaimed one is folded
    # in when its owner's next request reconciles it.
    #
    # Through the SAME rule the revoke path uses, not a bare recompute. Converging is one of the ways an
    # entitlement FALLS — a term the store shortened, or a revoke we never received a notification for,
    # whose resource now reads back-dated — and a fall that nobody judges leaves every outstanding proof
    # certifying a horizon the account no longer has. Safe on the paths where nothing fell: the rule claims
    # pending payments before deciding, so an upgrade's replacement is bound first, the delta gate sees no
    # fall, and it returns without announcing anything.
    if owner_pkey is not None:
        refresh_entitlement_and_revoke_overreaching_proofs(tx, nacl.signing.VerifyKey(bytes(owner_pkey)), at=at)
    return True


@dataclasses.dataclass
class GoogleReconcileClaim:
    '''A purchase token leased for reconciliation.

    `revision` is the obligation this worker picked up. It must be handed back to `google_reconcile_done` or
    `google_reconcile_failed`, which use it to tell whether a notification arrived while the fetch was in
    flight — one that describes a state the fetch cannot have seen, and so must not be cleared by it.
    '''

    payment_token: str = ''
    attempts: int = 0
    revision: int = 0


@db.transactional
def google_owner_of_purchase_token(tx: db.SQLTransaction, payment_token: str) -> bytes | None:
    """The master pkey that owns any payment on `payment_token`, or None if none is claimed.

    For attributing a resubscription whose new purchase carries no identifiers of its own and whose EXPIRED
    subscription never carried one either — so `expiredExternalAccountIdentifiers` is absent and only
    `expiredPurchaseToken` is left. Redemption bound the old row to its owner whatever the store knew, so our
    own record answers a question the store cannot.

    Any row will do: every cycle on one token belongs to one subscription and therefore one account, so this
    takes the newest rather than asserting there is exactly one.
    """
    # query_one, not query_scalar: an unknown or unclaimed token legitimately returns nothing, and
    # query_scalar asserts a row is present.
    row = db.query_one(
        tx.conn,
        '''
        SELECT   u.master_pkey
        FROM     google_play_payment_details gd
                 JOIN payments p ON p.id = gd.payment_id
                 JOIN users u    ON u.id = p.user_id
        WHERE    gd.payment_token = %s
        ORDER BY p.id DESC
        LIMIT    1
    ''',
        payment_token,
    )
    return bytes(row[0]) if row is not None and row[0] is not None else None


def google_enqueue_reconcile(tx: db.SQLTransaction, payment_token: str, eligible_at: pendulum.DateTime) -> None:
    """Record that `payment_token` owes a reconcile against Google's current subscription resource.

    Idempotent by construction: the token is the primary key, so a burst of notifications for one
    subscription collapses into one piece of work. That is the whole point of keying on the token — the
    resource is fetched at reconcile time, so whatever the tenth notification would have told us is already
    in the snapshot the first fetch returns.

    A repeat enqueue pulls the work EARLIER (`LEAST`) and never later, so a fresh notification for a token
    already waiting out a backoff is acted on promptly rather than inheriting the wait. `attempts` is
    deliberately left alone: a new notification arriving says nothing about whether the reason the last
    attempt failed has gone away, and resetting it would let a permanently stuck token retry at full speed
    forever.
    """
    db.query(
        tx.conn,
        '''
        INSERT INTO google_reconcile_queue (payment_token, eligible_at)
        VALUES      (%(token)s, %(eligible_at)s)
        ON CONFLICT (payment_token) DO UPDATE
        SET         eligible_at   = LEAST(google_reconcile_queue.eligible_at, EXCLUDED.eligible_at),
                    revision = google_reconcile_queue.revision + 1
    ''',
        token=payment_token,
        eligible_at=eligible_at,
    )


@db.transactional
def google_claim_due_reconciles(
    tx: db.SQLTransaction, now: pendulum.DateTime, lease_until: pendulum.DateTime, limit: int
) -> list[GoogleReconcileClaim]:
    """Lease up to `limit` tokens that are due, and return them.

    A lease rather than the claim-and-process-in-one-transaction shape the credit drain uses, because
    reconciling makes a NETWORK CALL to Google: holding row locks across that would pin a transaction open
    for the length of an external request. So the claim pushes `eligible_at` out to `lease_until` and commits,
    and the work happens outside any transaction. A worker that dies mid-fetch simply lets the lease lapse
    and the token comes due again — no in-progress state to clean up, and no way to lose the work.

    `lease_until` therefore has to exceed the longest a reconcile can take (the API call carries its own
    socket timeout), or a slow fetch would be re-leased while it is still running. SKIP LOCKED keeps two
    runners from contending on the same rows.
    """
    rows = db.query(
        tx.conn,
        '''
        UPDATE google_reconcile_queue
        SET    leased_until = %(lease_until)s
        WHERE  payment_token IN (
                   SELECT   payment_token
                   FROM     google_reconcile_queue
                   WHERE    eligible_at <= %(now)s
                     AND    parked_at IS NULL
                     AND    (leased_until IS NULL OR leased_until <= %(now)s)
                   ORDER BY eligible_at
                   FOR UPDATE SKIP LOCKED
                   LIMIT    %(limit)s
               )
        RETURNING payment_token, attempts, revision
    ''',
        now=now,
        lease_until=lease_until,
        limit=limit,
    )
    return [GoogleReconcileClaim(payment_token=row[0], attempts=row[1], revision=row[2]) for row in rows.fetchall()]


@db.transactional
def google_reconcile_done(tx: db.SQLTransaction, claim: GoogleReconcileClaim) -> bool:
    """Drop a token from the queue if the obligation just discharged is still the current one, and report
    whether it went.

    Deleting rather than marking done is right because the row is an OBLIGATION, not a record: the
    notification history keeps what arrived, and this table only ever answers "what still owes work".

    Conditional on `revision` because a notification arriving mid-fetch describes a state the fetch cannot
    have seen. Deleting unconditionally would discard that newer obligation on the strength of an older
    snapshot, and the change would sit unapplied until some later event happened to touch the token. Note
    that comparing `eligible_at` would NOT catch this: enqueue only ever lowers it, and a token being worked on
    is already due, so the new notification would leave the value untouched.
    """
    rows = db.query(
        tx.conn,
        '''
        DELETE FROM google_reconcile_queue
        WHERE  payment_token = %(token)s AND revision = %(revision)s
        RETURNING payment_token
    ''',
        token=claim.payment_token,
        revision=claim.revision,
    )
    if rows.fetchone() is not None:
        return True

    # A newer obligation stands, so the row survives — but this worker is done with it, and leaving the
    # lease standing would make the fresh notification wait out however much of it remains for nothing.
    db.query(
        tx.conn,
        '''UPDATE google_reconcile_queue SET leased_until = NULL WHERE payment_token = %s''',
        claim.payment_token,
    )
    return False


@db.transactional
def google_reconcile_failed(
    tx: db.SQLTransaction, claim: GoogleReconcileClaim, retry_at: pendulum.DateTime, error: str, park: bool = False
) -> None:
    """Record a failed attempt, release the lease, and back the token off to `retry_at`.

    The failure itself is always recorded — it happened, whatever else has changed. The BACK-OFF is not:
    if a notification arrived while the fetch was in flight, its obligation is newer than this failure and
    keeps the due time it asked for. Otherwise a token whose reconcile is failing would have every fresh
    notification's urgency stomped by the backoff from an attempt that predates it, which contradicts
    enqueue's rule that new information only ever pulls work earlier.

    `park` stops the automatic retries for good (see `parked_at`, added by migration
    008_google_convergence). It is subject to the same
    newer-obligation rule as the backoff: a notification that arrived during this fetch describes a state
    this attempt cannot have seen, so it gets its chance rather than being parked on the strength of a
    failure that predates it.
    """
    db.query(
        tx.conn,
        '''
        UPDATE google_reconcile_queue
        SET    attempts     = attempts + 1,
               last_error   = %(error)s,
               leased_until = NULL,
               eligible_at  = CASE WHEN revision = %(revision)s THEN %(retry_at)s ELSE eligible_at END,
               parked_at    = CASE WHEN %(park)s AND revision = %(revision)s THEN %(retry_at)s ELSE parked_at END
        WHERE  payment_token = %(token)s
    ''',
        token=claim.payment_token,
        revision=claim.revision,
        retry_at=retry_at,
        error=error,
        park=park,
    )


def google_parked_reconciles(conn: psycopg.Connection) -> list[tuple[str, int, str | None, pendulum.DateTime]]:
    """Every token the drain has given up on, for an operator or a report. Never called by the drain."""
    return [
        (row[0], row[1], row[2], row[3])
        for row in db.query(
            conn,
            '''SELECT payment_token, attempts, last_error, parked_at FROM google_reconcile_queue
               WHERE parked_at IS NOT NULL ORDER BY parked_at''',
        )
    ]


def google_unpark_reconcile(tx: db.SQLTransaction, payment_token: str, eligible_at: pendulum.DateTime) -> bool:
    """Put a parked token back in the queue, due at `eligible_at`. Returns whether one was parked.

    `attempts` is deliberately NOT reset: the count is the history of how much trouble this token has been,
    and an operator un-parking it has not made the previous failures un-happen. It does mean the first retry
    after un-parking uses the ceiling backoff, which is the right pace for something already known to fail.
    """
    rows = db.query(
        tx.conn,
        '''UPDATE google_reconcile_queue SET parked_at = NULL, eligible_at = %(eligible_at)s
           WHERE payment_token = %(token)s AND parked_at IS NOT NULL''',
        token=payment_token,
        eligible_at=eligible_at,
    )
    return rows.rowcount > 0


def _get_date_group_expr_sql(column: str, period: ReportPeriod) -> str:
    """Group a `timestamptz` column into a UTC calendar-period label."""
    utc = f"({column} AT TIME ZONE 'UTC')"  # timestamptz → UTC wall-clock, so buckets are UTC-stable
    match period:
        case ReportPeriod.Daily:
            return f"TO_CHAR({utc}, 'YYYY-MM-DD')"
        case ReportPeriod.Weekly:
            return f"TO_CHAR({utc}, 'IYYY-IW')"
        case ReportPeriod.Monthly:
            return f"TO_CHAR({utc}, 'YYYY-MM')"


def _get_period_end_ts_sql(period_str: str, period: ReportPeriod) -> str:
    """The last instant of the given period as a `timestamptz` (UTC), for range comparisons."""
    if period == ReportPeriod.Weekly:
        year, week = period_str.split("-")
        # ISO week Monday 00:00 UTC, + 1 week - epsilon = that week's final instant.
        start = f"(TO_TIMESTAMP('{year} {week} 1', 'IYYY IW ID') AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'"
        return f"({start} + INTERVAL '1 week' - INTERVAL '1 microsecond')"
    elif period == ReportPeriod.Monthly:
        return (
            f"((DATE_TRUNC('month', '{period_str}-01'::timestamp) AT TIME ZONE 'UTC')"
            " + INTERVAL '1 month' - INTERVAL '1 microsecond')"
        )
    else:
        return f"(('{period_str}'::timestamp AT TIME ZONE 'UTC') + INTERVAL '1 day' - INTERVAL '1 microsecond')"


def _format_period_label(period_str: str, period: ReportPeriod) -> str:
    """Format period string for display."""
    if period == ReportPeriod.Weekly:
        year, week = period_str.split("-")
        date = pendulum.DateTime.fromisocalendar(year=int(year), week=int(week), day=1)
        return date.strftime('%F') + f' (W{week})'
    return period_str


def generate_report_rows(conn: psycopg.Connection, period: ReportPeriod, limit: int | None) -> list[ReportRow]:
    def fetch_counts(
        tx_conn: psycopg.Connection, period: ReportPeriod, date_column: str, where_clause: str
    ) -> dict[str, int]:
        group_by_expr = _get_date_group_expr_sql(date_column, period)

        result_set = db.query(
            tx_conn,
            f"""
            SELECT {group_by_expr} AS period, COUNT(*) AS count
            FROM payments
            WHERE {where_clause}
            GROUP BY period
            ORDER BY period DESC
        """,
        )

        result: dict[str, int] = {}
        for row in result_set:
            period_label = _format_period_label(row[0], period)
            result[period_label] = row[1]
        return result

    def fetch_active_users(tx_conn: psycopg.Connection, period: ReportPeriod) -> dict[str, int]:
        date_expr = _get_date_group_expr_sql("purchased_at", period)

        result_set = db.query(
            tx_conn,
            f"""
            SELECT DISTINCT {date_expr} AS period
            FROM payments
        """,
        )
        periods_list = [row[0] for row in result_set]
        result: dict[str, int] = {}

        for it in periods_list:
            assert isinstance(it, str)
            end_ts = _get_period_end_ts_sql(it, period)

            count = db.query_scalar(
                tx_conn,
                f"""
                SELECT COUNT(DISTINCT user_id) AS active
                FROM payments
                WHERE {end_ts} >= purchased_at
                  AND {end_ts} <= expiry_at
                  AND revoked_at IS NULL
            """,
            )
            period_label = _format_period_label(it, period)
            result[period_label] = count

        return result

    result: list[ReportRow] = []
    with db.transaction(conn) as tx:
        unredeemed: dict[str, int] = fetch_counts(
            tx_conn=tx.conn,
            period=period,
            date_column="purchased_at",
            where_clause="redeemed_at IS NULL AND revoked_at IS NULL",
        )

        plan_1m: dict[str, int] = fetch_counts(
            tx_conn=tx.conn,
            period=period,
            date_column="purchased_at",
            where_clause=f"plan = '{base.ProPlan.OneMonth.value}'",
        )

        plan_3m: dict[str, int] = fetch_counts(
            tx_conn=tx.conn,
            period=period,
            date_column="purchased_at",
            where_clause=f"plan = '{base.ProPlan.ThreeMonth.value}'",
        )

        plan_12m: dict[str, int] = fetch_counts(
            tx_conn=tx.conn,
            period=period,
            date_column="purchased_at",
            where_clause=f"plan = '{base.ProPlan.TwelveMonth.value}'",
        )

        google: dict[str, int] = fetch_counts(
            tx_conn=tx.conn,
            period=period,
            date_column="purchased_at",
            where_clause=f"payment_provider = '{base.PaymentProvider.GooglePlayStore.value}'",
        )

        apple: dict[str, int] = fetch_counts(
            tx_conn=tx.conn,
            period=period,
            date_column="purchased_at",
            where_clause=f"payment_provider = '{base.PaymentProvider.iOSAppStore.value}'",
        )

        stf: dict[str, int] = fetch_counts(
            tx_conn=tx.conn,
            period=period,
            date_column="purchased_at",
            where_clause=f"payment_provider = '{base.PaymentProvider.SessionFoundation.value}'",
        )

        new_subs: dict[str, int] = fetch_counts(
            tx_conn=tx.conn, period=period, date_column="purchased_at", where_clause="purchased_at IS NOT NULL"
        )

        revocations: dict[str, int] = fetch_counts(
            tx_conn=tx.conn, period=period, date_column="revoked_at", where_clause="revoked_at IS NOT NULL"
        )

        cancelled: dict[str, int] = fetch_counts(
            tx_conn=tx.conn,
            period=period,
            date_column="expiry_at",
            where_clause="NOT auto_renewing AND revoked_at IS NULL",
        )

        active_users: dict[str, int] = fetch_active_users(tx.conn, period)

        all_periods: set[str] = set()
        for key_list in [new_subs.keys(), revocations.keys(), cancelled.keys(), active_users.keys()]:
            for it in key_list:
                all_periods.add(it)

        sorted_periods: list[str] = sorted(all_periods, reverse=True)[:limit]
        for it in sorted_periods:
            result.append(
                ReportRow(
                    period=it,
                    active_users=active_users.get(it, 0),
                    unredeemed=unredeemed.get(it, 0),
                    new_subs=new_subs.get(it, 0),
                    google=google.get(it, 0),
                    apple=apple.get(it, 0),
                    stf=stf.get(it, 0),
                    plan_1m=plan_1m.get(it, 0),
                    plan_3m=plan_3m.get(it, 0),
                    plan_12m=plan_12m.get(it, 0),
                    revoked=revocations.get(it, 0),
                    cancelled=cancelled.get(it, 0),
                )
            )

    return result


def generate_report_str(period: ReportPeriod, data: list[ReportRow], type: ReportType) -> str:
    @dataclasses.dataclass(frozen=True)
    class Section:
        name: str
        width: int
        align_left: bool = False

    sections: list[Section] = [
        Section("Period", 16, align_left=True),
        Section("Active Users", 14),
        Section("Unredeemed", 12),
        Section("New Subs", 10),
        Section("Google", 8),
        Section("Apple", 7),
        Section("Foundation", 12),
        Section("Plan 1m", 10),
        Section("Plan 3m", 10),
        Section("Plan 12m", 10),
        Section("Revoked", 10),
        Section("Cancelling", 12),
    ]

    result: str = ''
    match type:
        case ReportType.Human:
            header_parts: list[str] = []
            for sec in sections:
                if sec.align_left:
                    header_parts.append(f"{sec.name:<{sec.width}}")
                else:
                    header_parts.append(f"{sec.name:>{sec.width}}")
            header = " ".join(header_parts)

            result = f"{period.name.upper()} REPORT\n"
            result += "-" * len(header) + "\n"
            result += header + "\n"
            result += "-" * len(header) + "\n"

            for i, row in enumerate(data):
                if i > 0:
                    result += "\n"

                human_parts: list[str] = []
                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.period:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.active_users:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.unredeemed:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.new_subs:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.google:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.apple:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.stf:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.plan_1m:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.plan_3m:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.plan_12m:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.revoked:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.cancelled:{align}{padding}}")

                assert len(human_parts) == len(sections)
                result += " ".join(human_parts)

        case ReportType.CSV:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([sec.name for sec in sections])
            for row in data:
                csv_parts: list[str | int] = [
                    row.period,
                    row.active_users,
                    row.unredeemed,
                    row.new_subs,
                    row.google,
                    row.apple,
                    row.stf,
                    row.plan_1m,
                    row.plan_3m,
                    row.plan_12m,
                    row.revoked,
                    row.cancelled,
                ]
                assert len(csv_parts) == len(sections)
                writer.writerow(csv_parts)
            result = output.getvalue().strip()
    return result
