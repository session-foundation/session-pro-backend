# Session Pro — wire & proof format (authoritative spec)

> **Status: authoritative, pre-launch, mutable.** This is the single source of truth for the Session
> Pro proof, signed-request, and revocation-list formats, implemented by **both** the backend (signer)
> and libsession-util + clients (verifier / request-builder).
>
> The format is **not frozen** until Pro launches (no client can validate a real proof yet — the
> backend signing pubkey isn't finalized). Until then, fix it here and both sides implement to it. It
> freezes at launch.
>
> **Out of scope: the `/dev/*` routes.** `dev_routes.py` serves unauthenticated test-only endpoints
> that mint payments with no payment provider involved. They are not part of this spec, no client
> implements them, and they only exist on an instance explicitly started with `dev_endpoints` (which
> in turn requires `provider_dry_run`). Nothing here applies to them.

## 1. Primitives & conventions

- **Signatures:** Ed25519 over the **message directly** — NOT over a hash of it. Ed25519 already hashes
  internally and these messages are tiny, so there is no pre-hash (no BLAKE2b). Each signed message is
  built by the same rule (§1.1).
- **§1.1 Signed-message construction.** A signed message is: a **16-byte domain prefix** (ASCII,
  `_`-right-padded to 16) followed by the fields
  in the stated order, each encoded by type:
  - **public key / raw bytes** (`master_pkey`, `rotating_pkey`, `revocation_tag`): appended **verbatim**
    (fixed width — 32 bytes — so self-delimiting).
  - **integer** (`ts`, `count`, `expiry`, …): its **canonical decimal ASCII** — no grouping, no leading
    zeros, `-` for negatives (Python `str(int).encode()`, C++ `std::to_chars` base 10; both are
    locale-independent and MUST be used, not locale-aware formatters). This is why `count = -1` and
    unbounded values need no special handling.
  - **string** (`before` — the pagination cursor): its **UTF-8** bytes verbatim.
  - **Framing:** a single `\0` (NUL) byte is inserted **between two adjacent variable-length fields** (i.e.
    between two int/str fields). Fixed-width fields (keys/tag) need no separator. A `\0` cannot occur in a
    decimal integer; the trailing variable-length field (e.g. the opaque cursor `before`) is **always
    last**, so it is never followed by a separator and the parse stays unambiguous even if it contained one.
- **Time quantities:** **UNIX-epoch seconds** everywhere (never milliseconds), for both timestamps and
  durations. Almost every value is a JSON **integer**: every expiry, every duration, and anything the
  backend computes or rounds lands on a whole second (the proof's `expiry_ts` is rounded onto a
  whole-second grid — §2.3 — and a store-supplied expiry surfaced as an integer field is floored to the
  second). The **only** exception is a short, explicitly-enumerated set of **upstream provider event
  instants** — currently `purchased_ts` (provider purchase time) and `revoked_ts` (provider revocation
  time) — emitted as JSON **floats** so the provider's sub-second precision survives; the fractional part
  is just the sub-second remainder, still seconds. (A binary64 float resolves current-era timestamps to
  ~238 ns, so this preserves milliseconds exactly.) A value that enters a **signed message is always a
  whole-second integer** (encoded as canonical decimal ASCII per §1.1), never a float — the signed
  timestamps (`ts`, proof `expiry_ts`) are whole-second by nature; the float
  `purchased_ts`/`revoked_ts` are read-response fields, never signed. The DB stores every instant at full
  `timestamptz` (µs) precision regardless of wire type, so an integer wire field is a *display* choice,
  not data loss — a field can widen to a float later with no storage change.
- **Field-name markers (no unit suffix, ever).** Seconds is the universal unit, so **no** field carries a
  `_ms`/`_s` marker. Timestamps take a short **`_ts`** suffix (the redundant `_unix` is dropped — the
  value is just seconds-since-epoch): `expiry_ts`, `effective_ts`, `revoked_ts`, and a request nonce is
  bare `ts`. Durations are named `…_duration` (e.g. `grace_period_duration`). The `_ts`/`_duration`
  marker stays because the field names are often past participles (`revoked`) that would
  otherwise read as booleans; only the *unit* suffix is dropped, never the type marker. A value needing
  finer resolution than a whole second is a JSON **float** (see Time quantities), never a `_ms`-suffixed
  integer — so the unit suffix never reappears.
- **Byte strings on the JSON wire:** lowercase hex, no `0x` prefix. Fixed lengths: pubkeys 32 B (64 hex),
  signatures 64 B (128 hex), `revocation_tag` 32 B (64 hex).
- **JSON numbers:** only for values whose *realistically-occurring* value stays `< 2^53`. Anything that
  can exceed that (opaque IDs, tokens, provider transaction ids) is a **string**. `ticket` is typed
  `int64` for headroom + signedness + restore-safety, but its *value* is a monotonic counter that stays
  far below 2^53 (it ticks only when a revocation is **added** — never on expiry/prune-removal, see §4), so it rides as a **number** — the int64 is
  a storage/type choice, not a value range. All `_ts` / `_duration` values likewise stay numbers
  (seconds ~1.7e9 « 2^53).
- **Enums are transmitted as stable string `code`s, never integers** (backed by lookup tables;
  the DB keeps a surrogate int `id`, but the wire *and the signed messages* use the `code`, so no magic
  number ever crosses the wire and new values are additive `INSERT`s):
  - `payment_provider`: `"google_play"`, `"app_store"`, `"stf"` (the Session Foundation, for a payment
    granted out of band rather than bought from a store)
  - `status`: the per-**item** *payment* status — `"redeemed"`, `"expired"`, `"revoked"` — where
    **`"revoked"`** is the terminal revoked state (refund/chargeback/protocol kill). There is no
    `"refunded"` status.
    (The account-level *Pro* status is a **separate** field, `user_status` — values `"never"`/`"active"`/
    `"expired"` — not this per-item `status`; see §5.2.)
  - `plan`: a compact **billing-period code** with a **backend-owned, closed grammar**: a fixed
    `<N><unit>` pattern over a fixed unit set, or the literal `"lifetime"`. The backend emits only conforming
    values, so a client MAY treat a non-conforming value as a protocol error (fail-closed) and need not keep
    a raw-string pass-through.
    - **`<N><unit>`** — `N` a positive integer, no leading zeros (`[1-9][0-9]*`); `unit` one of
      `s`/`d`/`w`/`m`/`y` (second/day/week/month/year). Single-unit (`"1y6m"` is invalid). Parses to
      `(count ≥ 1, unit)`. **The unit is preserved, never converted:** `"12m"` and `"1y"` are the same
      duration but distinct values — the unit is the product's intended presentation. `s` is mainly for
      testing; no production plan uses it.
    - **`"lifetime"`** — perpetual, non-recurring; parses to `(count = 0, unit = lifetime)`. `count` is
      defined only for periodic units; for `lifetime` it is not meaningful (invariant:
      `count == 0 ⟺ lifetime`). Consumers switch on `unit` and never render `lifetime` as `"{count} {unit}"`.

    **Display/accounting only** (never computed with); recurrence is the separate `auto_renewing` field. A
    parser reads it **once** to `(count, unit)` — unit enum `second`/`day`/`week`/`month`/`year`/`lifetime`;
    clients own localized display. Backend groups by the raw code.
  - A `nil`/unset value is never valid on the wire — every stored row has a real code.
- **No version byte in any signed message, and no `version` field anywhere on this wire** — requests,
  responses and the proof alike. A format version is carried by the **domain prefix** (§1.1) and by the
  **endpoint**: a new request or response shape earns a new endpoint, so the caller has already selected
  the format by the time it gets an answer, and an integer echoed back tells it nothing it did not
  already know. A version a peer must act on belongs where that peer can read it — for the proof, the
  protobuf envelope clients attach it to (below).

## 2. The Pro proof (signed by the backend)

The proof certifies that a rotating key is Pro-entitled until an expiry. It is **self-contained and
verified offline**; it carries **no user identity**.

**Wire (JSON):**
```
{ "revocation_tag": "<64 hex>",            // opaque 32-byte value; see §2.1
  "rotating_pkey":  "<64 hex>",            // Ed25519 public key the proof entitles
  "expiry_ts": <int>,                      // seconds; PROOF validity (clamped, rolling ~30d) — NOT the
                                           //   sub end; see §2.3 before reading anything into its value
  "sig": "<128 hex>",                      // Ed25519 over the message below (§1.1)
  "account_expiry_ts": <int>,              // advisory, UNSIGNED; see §2.2
  "account_grace_period_duration": <int>,  // advisory, UNSIGNED; see §2.2
  "account_auto_renewing": <bool> }        // advisory, UNSIGNED; see §2.2
```
**There is no `version` field in this response.** The format version is bound into the signature by the
**domain prefix** — v0 signs under `ProProof_v0_____` — so a proof of one version cannot verify as
another, and the map from version to prefix is arbitrary and per-version (a future version may pick any
prefix, or reshape the proof entirely).

A future proof version is served from a **new endpoint**, per §1. `generate_pro_proof` keeps the shape
above: fields are added to it, never removed or retyped, and it never begins answering in another format.
A client may therefore parse this response strictly and treat an unexpected shape as an error rather than
as a version it has to detect.

The client fetching this response already knows the version: it chose the endpoint that produced it. The
party that does *not* know is an **offline peer verifier**, which never made this request — and it reads
the version from the **protobuf envelope** the fetching client attaches the proof to, not from here. A
verifier that meets a version it does not recognise **refuses to interpret the proof** rather than
reporting it invalid: it cannot check a format it does not know, and treating an unrecognised version as a
failed signature would make a client-upgrade rollout look like a wave of forgeries. That distinction is a
property of the envelope layer; this response is not where it lives.

**Signed message** — `sig = Ed25519(backend_key, M)` over the message **directly** (no pre-hash; §1.1);
the verifier picks the 16-byte domain prefix for the version it is holding (v0 → `ProProof_v0_____`), then:
```
M =  "ProProof_v0_____"        # 16-byte domain prefix; the "_v0" is where the version is bound
  ‖  revocation_tag            # 32 bytes, raw
  ‖  rotating_pkey             # 32 bytes, raw
  ‖  dec(expiry_ts)            # canonical decimal ASCII seconds (trailing field → no separator)
```
Verifiers reconstruct `M` from the proof fields and check `sig` against the backend's public key, then
check `expiry_ts` against their clock and `revocation_tag` against the revocation list (§4).

### 2.1 `revocation_tag`
A per-**generation** opaque **random 32-byte value** (a generation = one epoch of a user's aggregate
entitlement). Clients treat it as an **opaque blob compared for equality** against revocation-list
entries — nothing derives or interprets it: it is not a hash of anything the client can or should
compute, just an opaque stored random value.

### 2.2 The account fields (advisory, unsigned)
Three fields describing the **account** rather than the proof: `account_expiry_ts`,
`account_grace_period_duration` and `account_auto_renewing`. None is part of the signed message; all three
come from one snapshot, taken at the same instant as the proof beside them.

#### `account_expiry_ts`
The account's **true entitlement end** in integer seconds — the same value `get_pro_status` reports as
`expiry_ts`. This is the end of the term that was *paid for*: it carries neither the store's grace period
nor the backend's renewal-latency allowance, both of which describe how long service continues past that
point rather than what the subscription ran to. It is **not** part of the signed message `M` and carries no
signature of
its own: a verifier reconstructs `M` from `revocation_tag`/`rotating_pkey`/`expiry_ts` only and
MUST NOT feed `account_expiry_ts` into that check. It is **distinct from the proof's `expiry_ts`**, which
is the clamped, rolling (~30 d) proof-validity window; `account_expiry_ts` is the subscription horizon
and may be far later. It rides on the proof response so a proof fetch also refreshes the client's cached
expiry; treat it as display state, not an entitlement authority (the signed proof + revocation list are
authoritative).

**`expiry_ts ≤ account_expiry_ts` does NOT hold**, and a client must not assume it. The two answer
different questions and are allowed to cross: in the final stretch of a subscription the proof's expiry
overtakes the account's true end (§2.3), and a proof issued during a store grace period or the backend's
renewal-latency allowance runs past it by construction. `account_expiry_ts` is exact in every case — it is
the one value here with no over-provision and no random offset on it, which is what makes it the right
thing to show a user and the wrong thing to make a serving decision on.

#### `account_grace_period_duration` and `account_auto_renewing`
How much longer the account is served **past** `account_expiry_ts`, and whether the subscription behind it
renews itself. They are the **same two quantities** `get_pro_status` reports as its account-level
`grace_period_duration` and `auto_renewing` (§5.2): the store's dunning window plus the backend's
renewal-latency allowance, and `0` when the subscription is not auto-renewing, since neither span applies
to a term that is simply ending. Service stops at `account_expiry_ts + account_grace_period_duration`, and
that is the same instant `get_pro_status` flips `user_status` from `active` to `expired`.

`account_grace_period_duration` is **not** the payment-item field of that name, which is what one store
declared about one transaction and carries no allowance (§5.2).

#### The three travel together
Every response that carries any of the three carries **all** of them, so a client can persist them from
whichever it received and never hold two values describing different instants. That is both the proof
response above and the `subscription_expired` failure (§5.1), where `account_expiry_ts` is in the past —
and where the other two are the fields that can have changed, since a cancellation collapses coverage to
the paid term without moving the expiry.

### 2.3 `expiry_ts` (proof validity)
The proof's own validity window, and **nothing else**. It is the earlier of the subscription end and a
rolling ~30 d cap, plus a **deliberate over-provision of up to ~25 h**, rounded up onto a **random,
per-account grid** (one grid point every 24 h, at an offset the backend re-draws each billing cycle).
Consequences for a verifier or a client:

- **Never day-aligned, and never treated as one.** A verifier checks `expiry_ts` against its clock, full
  stop; it must not round, truncate to a day, or reconstruct any boundary from it.
- **Do not read the value as information.** Its time-of-day is a random per-account draw, and two accounts
  on identical plans have unrelated `expiry_ts` values. It is not the subscription end (that's
  `account_expiry_ts`), not the renewal instant, and not a plan-tier indicator.
- **Clients renew one hour before `expiry_ts`.** That lead is fixed by agreement with the backend, which
  sizes the over-provision around it: **renewing earlier than 1 h requires a coordinated backend change**,
  or a renewal request can land before the store has had its last chance to report the renewal and be
  answered `subscription_expired` on a subscription that is in fact renewing.
- **Expect the value to be stable, then step.** Two of a user's devices asking within the same grid period
  receive the same `expiry_ts`; while the cap is in force it steps by exactly 24 h per period rather than
  sliding with the request, and once the subscription end comes into range it stops moving at all.

## 3. Signed requests (signed by the user's master key)

Each request is authorised by an Ed25519 signature from the account **master key** over the message built
per §1.1 (16-byte domain prefix + typed fields, no pre-hash). Field order is exact. `ts` is the caller's
clock (backend accepts it within a tolerance window, currently ±70 s). **No message carries a `version`**
field or prefix (§1) — the domain prefix + the endpoint already domain-separate each message; a
new request shape gets a new endpoint. Below, `dec(x)` = the canonical decimal-ASCII integer of §1.1, raw
32-byte fields are self-delimiting, and `\0` separates adjacent variable-length fields.

**Redemption is implicit — there is no client-submitted "add payment" request.** The store notifies the
backend of a purchase out-of-band; the backend records it against the buyer's account id (the master key,
for Google; a UUID derived from it, for Apple — §1). Any of the three master-signed requests below binds
the account's still-unbound payments before it answers, so the client never submits or names a payment to
redeem it. After a purchase the client just calls `generate_pro_proof` (or `get_pro_status`); until the
store notification has reached the backend the answer reflects no new entitlement, and the client retries.

**3.1 generate_pro_proof** — domain `ProGenerateProof`
```
master_pkey(32) ‖ rotating_pkey(32) ‖ dec(ts)
```

**3.2 get_pro_status** — domain `ProGetProStatus_`  (the hot path: account status + the single latest payment)
```
master_pkey(32) ‖ dec(ts)
```

**3.3 get_payment_details** — domain `ProGetPayDetails`  (paginated payment history; rarely hit)
```
master_pkey(32) ‖ dec(ts) ‖ \0 ‖ dec(limit) ‖ \0 ‖ before
```
`before` is the opaque pagination cursor (§5.3) — the empty string requests the newest page.

## 4. Revocation list

Poll endpoint; response is JSON and **not signed** (fetched over TLS/onion). The client sends its
last-seen `ticket`; the backend returns the full list only if the ticket advanced.

**Request:** `{ "ticket": <int64> }`  (no `version` field — §1)
**Response:**
```
{ "ticket":     <int64>,   // int64 type; VALUE stays « 2^53, so a JSON number (see §1)
  "retry_in":   <int>,     // recommended poll interval / throttle (seconds)
  "retain_for": <int>,     // seconds a client should keep each entry after seeing it (≥ the max
                           //   proof-validity window, ~30d). Sent, not hardcoded, so it can vary.
  "items": [ { "revocation_tag": "<64 hex>",
               "effective_ts":   <int> },   // start rejecting matching proofs at/after this; always
                                            //   comfortably more than retry_in ahead of when the
                                            //   backend recorded the revocation, so the revoked
                                            //   sender polls and sees its own tag first. Enforce it
                                            //   as given — never earlier.
             ... ] }        // empty if caller's ticket == current ticket
}
```
A proof is revoked iff its `revocation_tag` matches a listed entry **and** the client clock ≥ that
entry's `effective_ts`.

**Local aging is a memory-only cleanup timer — no per-entry expiry.** A client keeps each entry until
roughly `(when it saw the entry) + retain_for`, then drops it. Correctness does not depend on precision
here: holding a stale entry too long is harmless (its random `revocation_tag` never matches a live proof
— those have expired, and a new generation gets a fresh random tag), and `retain_for ≥` the proof-validity
window guarantees a client never drops an entry while a valid proof could still carry it. The backend
prunes its *own* served list on the same basis (`creation + retain_for`) to keep it small — **without**
bumping `ticket`, so a prune never triggers a client re-fetch.

## 5. Response envelope

Every endpoint returns HTTP 200 with a JSON object discriminated by **`status`** (the envelope `status` is
authoritative for the application outcome; HTTP status is not used for it):

- `"ok"` — success; the payload is in **`result`** (an object, shape per endpoint). No `error`/`error_code`.
- `"fail"` — the request was understood but rejected by the client's input or a state precondition (the
  HTTP-4xx family: bad args, not-found, conflict). The client's to fix or accept; retrying the *identical*
  request generally won't help (the one exception is `stale_request`).
- `"error"` — the backend faulted while handling it (HTTP-5xx family: unhandled exception, DB fault). The
  client did nothing wrong; the same request may succeed later.

**`status` is a closed, exhaustive set** — `"ok"` / `"fail"` / `"error"` and nothing else, ever. A client
SHOULD treat any other `status` value as a protocol error (fail-closed), NOT a gracefully-ignored unknown.
The envelope will never grow a fourth `status`; a new category or extra detail is always conveyed by a new
**`error_code`** slug (which *is* open/additive — see §5.1) or a new field. Two deliberate extensibility
contracts: `status` is rigid (clients may model it as a fixed enum), `error_code` is extensible.

Non-`ok` responses carry two fields:
- **`error_code`** — a stable lowercase-`snake_case` machine slug, **always present** on non-`ok`. This is
  the identifier a client keys its localized (Crowdin) message off; an unrecognized (newer) slug degrades
  gracefully — the client falls back to `status`-level handling and/or shows `error`.
- **`error`** — a single human English string. It is a **fallback + diagnostic, NOT the user-facing text**
  (the user-facing text comes from the `error_code`→translation map). A client shows it only when it does
  not recognize the slug, and logs it. (Was an array `errors`; it is now one string, and on a malformed
  request the server reports the *first* bad field, not an accumulated list.)

```
{ "status": "ok",    "result": { … } }
{ "status": "fail",  "error_code": "<slug>", "error": "<english>" }
{ "status": "error", "error_code": "<slug>", "error": "<english>" }
```

### 5.1 `error_code` vocabulary

| slug | status | when / client action |
| --- | --- | --- |
| `invalid_request` | fail | malformed JSON, missing/wrong-type field, bad hex, out-of-range value, unsupported/disabled provider. A correct client never sees this. |
| `bad_signature` | fail | a request signature failed to verify. A correct client never sees this. |
| `stale_request` | fail | request timestamp outside the replay-tolerance window. The client may re-fetch server time (`/status`) and retry. |
| `subscription_expired` | fail | the user's entitlement has lapsed → "renew" CTA. (Named to stay disjoint from `user_status: expired` — §5.2 — so no token belongs to two fields.) A `subscription_expired` fail on `generate_pro_proof` additionally carries the three top-level account fields — **`account_expiry_ts`** (now in the past), **`account_grace_period_duration`** and **`account_auto_renewing`** (§2.2) — so the client can refresh its cached state without a separate `get_pro_status`; other slugs do not. |
| `not_subscribed` | fail | no entitlement on record (never subscribed, or pruned after long inactivity) → "subscribe" CTA. |
| `revoked` | fail | the user's current entitlement was revoked. Treat as `subscription_expired` (renew) on clients today; the distinct slug is reserved for a future revoked-specific flow. |
| `rate_limited` | fail | too many proofs have been issued to this account in the current window (`generate_pro_proof` only). The entitlement is intact — this is a per-account issuance limit, not an expiry — so a client should keep its existing proof and retry later rather than treating the account as lapsed. Disabled by default; a correct client on one account will not normally see it. |
| `internal_error` | error | backend fault; not the client's doing. |

### 5.2 Result payloads

The read endpoints (`get_pro_status`, `get_payment_details`) return unsigned
JSON data. They carry the same conventions: timestamps are `_ts` seconds — **integer** everywhere except the
two upstream provider event instants `purchased_ts` and `revoked_ts`, which are **floats** to keep provider
sub-second precision (§1) — enums are their string `code`s (§1), byte strings are hex, and no key name leaks
an internal implementation detail (see §6). (Their per-field shapes track `server.py`; only the naming/units
rules here are normative for them.) Note a non-error outcome lives *in* `result`, not as a `fail`:
`get_pro_status` reports account state as `user_status` (`never`/`active`/`expired`; `user_` disambiguates it
from the envelope `status` and the per-item payment `status`).
`user_status` is a distinct axis from the `error_code` slugs (§5.1) and their vocabularies are deliberately
**disjoint** — the "lapsed" `error_code` is `subscription_expired`, not `expired`, so a value never belongs to
two fields; `user_status: never` is the state behind an `error_code: not_subscribed` rejection.

The two read endpoints return these `result` shapes:
- **`get_pro_status`** (cheap, hot path) — `{ user_status, auto_renewing, expiry_ts,
  grace_period_duration, latest_payment }`. `latest_payment` is a single payment item (shape
  below) or `null` when the account has no payments. No list, no pagination.

  **`latest_payment` is the account's newest payment that still stands** — newest by the store's own
  purchase instant (`purchased_ts`), preferring one that has not been revoked. Two consequences a client can
  rely on: on an account with payments on more than one store, `payment_provider` names the store the user
  most recently bought from, never one whose notifications merely arrived late; and when a purchase is
  refunded the item reverts to the payment that still stands, so a mistaken second-store purchase stops
  being reported once its revocation lands.

  It is the LATEST payment, not the longest-lasting one. A voucher stacks its length on top of a
  subscription, so an account holding both is covered past the end of the payment named here — the
  account-level `expiry_ts`/`grace_period_duration` beside it are the coverage answer, and the two are not
  expected to agree. Nor is the item necessarily `active`: it can read `expired` or `revoked` while
  `user_status` is `active`.

  `null` means the account has never had a payment, and nothing else. An account whose payments have all
  lapsed, or all been refunded, still gets an item.
- **`get_payment_details`** (paginated history) — `{ payments_total, items, next_cursor }`. `items` is one
  keyset page of payment items, newest-first, and carries **no** `user_status`; `payments_total` is the
  account's total payment count; `next_cursor` (§5.3) is the pagination token, or `null` at end-of-data.

Each **payment item** carries: `status` (payment `code`), `plan`, `payment_provider`, `auto_renewing`,
`purchased_ts` (float), `expiry_ts`, `grace_period_duration`, `platform_refund_expiry_ts`,
`revoked_ts` (float), and the opaque `payment_id` — a backend-owned identifier the client stores and
compares for equality but never parses.

#### `expiry_ts` and `grace_period_duration` — two levels, two meanings

`grace_period_duration` is **not** the same quantity on a payment item and on `get_pro_status`, and a client
must not treat them interchangeably:

- On a **payment item** it is what the *store declared* about that one transaction: a dunning window the
  store granted without folding it into its own expiry. `0` where the store declared none.
- On **`get_pro_status`** it is how much longer the *account* is served past `expiry_ts` — the store's grace
  plus the backend's renewal-latency allowance, and `0` when the subscription is not auto-renewing (nothing
  is in flight, so nothing is being waited for).
- On a **proof response** (and on a `subscription_expired` failure) the same account-level value rides under
  the `account_`-prefixed name `account_grace_period_duration` (§2.2), because the proof carries an
  `expiry_ts` of its own. Same quantity as the `get_pro_status` one, not a third meaning.

The account-level pair is self-consistent: `expiry_ts + grace_period_duration` is exactly the instant the
backend stops serving, and is the same instant `user_status` flips from `active` to `expired`. A client that
wants "am I still Pro?" should read `user_status`; a client that wants "until when?" can add the two.

**`expiry_ts` is the paid-through date on both stores, including during a grace period.** The two stores
report it differently — Apple leaves its expiry alone and declares grace separately, while Google Play
applies grace by *extending* its own expiry — but the backend normalises them, so a subscription in grace
reports the term the customer actually paid for, with the grace in `grace_period_duration` beside it.

That is what lets a client say something true while a payment is failing: *"your subscription expired 13
hours ago and your payment hasn't gone through — you keep Pro for another 2 days."* Both halves come from
this pair, and neither requires the client to know which store the subscription is on.

**One case where the Google value is approximate.** The backend recovers the paid term by remembering what
the term was before the store extended it. If the very first thing it ever hears about a subscription is a
grace-period notification — no earlier renewal to have recorded the term — there is nothing to anchor on,
and `expiry_ts` will report the extended date with a zero `grace_period_duration`. Rare, and the
stop-serving arithmetic above still holds; only the split between the two fields is lost.

### 5.3 Pagination cursor (`get_payment_details`)

`get_payment_details` uses **keyset** (seek) pagination, never numeric offsets. The client sends
`{ limit, before }` — `limit` caps the page (server-clamped), `before` is a cursor (empty string = newest
page). The response returns up to `limit` items newest-first plus `next_cursor`; the client re-requests with
`before = next_cursor` to walk older pages, stopping when `next_cursor` is `null` (or fewer than `limit`
items return). The cursor is **opaque** — an **encrypted** token, not a readable id: the client stores and
echoes it verbatim and MUST NOT parse it. (It seals the boundary row's internal id, a global identity
sequence whose raw value would leak system-wide payment volume/ordering — the same enumeration concern that
made `payment_id` opaque. A tampered or foreign cursor is rejected as `invalid_request`.)

## 6. Field-naming rule
Wire (JSON) field names describe **purpose to the consumer**, never server implementation, and carry
**no unit suffix** (the unit is the §1 default; add one only for a genuine deviation) — timestamps take
a `_ts` marker, durations `…_duration`.
