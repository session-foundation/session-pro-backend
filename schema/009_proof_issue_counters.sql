-- Per-account proof-issuance counters.
--
-- A Pro proof is a bearer credential verified offline against a rotating key that carries no account
-- identity, so possession is the whole test and nothing downstream can tell one subscriber's proof from a
-- copy of it. An account whose master seed has been extracted into a modified client can therefore feed
-- an unbounded number of installs, and until now the backend kept no record with which to notice: proofs
-- were signed and handed back without leaving a trace on the account.
--
-- These columns are that record. A legitimate account re-fetches on its own renewal timer (roughly an
-- hour before a ~30-day proof expiry) times its device count, plus retries, so its counts sit in the low
-- single digits per week; a seed being served to a fleet does not. The window count is what a cap is
-- judged against, and the lifetime total is what documents a violation after the fact.
--
-- Written idempotently per this directory's README.

ALTER TABLE users
    -- Every proof this account has ever been issued. Monotonic, never reset and never swept: a
    -- terms-of-service case is made from the account's whole history, and a counter that rolled would
    -- destroy the evidence it exists to hold.
    ADD COLUMN IF NOT EXISTS proofs_issued_total  BIGINT NOT NULL DEFAULT 0
        CHECK (proofs_issued_total >= 0),
    -- Proofs issued since `proofs_window_start` -- ALL of them, including the past-expiry ones counted
    -- again below. Reset by the issue path when that window has elapsed, rather than by a sweep, so the
    -- value is correct when read regardless of when maintenance last ran.
    ADD COLUMN IF NOT EXISTS proofs_issued_window BIGINT NOT NULL DEFAULT 0
        CHECK (proofs_issued_window >= 0),
    -- Of that window's proofs, how many were issued while the account was PAST its paid-through expiry --
    -- covered by store grace, our renewal-latency allowance, or the proof over-provision. A subset of the
    -- column above, not a separate bucket, so both counts mean what their names say and the limit is a
    -- subtraction at the point of use rather than a policy baked into a stored column.
    --
    -- Separated because the two have completely different natural rates. Before expiry a device fetches
    -- once per proof lifetime (~30 days) and no less often as the term runs down: inside the last 30 days
    -- one proof covers all remaining time plus the over-provision. Past expiry the proof expiry is PINNED
    -- -- every re-fetch returns the identical value -- so a client whose renewal target has fallen inside
    -- that window re-asks and re-asks, having been given nothing new to act on. Charging a limit for that
    -- would refuse a paying subscriber whose renewal is merely late.
    --
    -- Windowed rather than lifetime, because the question asked of it is "was this account retrying
    -- RECENTLY", and a monotonic total cannot distinguish last week from two years ago when all you have
    -- is the row in front of you.
    ADD COLUMN IF NOT EXISTS proofs_issued_past_expiry_window BIGINT NOT NULL DEFAULT 0
        CHECK (proofs_issued_past_expiry_window >= 0),
    -- When the current window opened, or NULL when no window is open -- before this account's first proof,
    -- and again after a generation roll clears the count. A zero or epoch sentinel would instead claim an
    -- empty window that really elapsed. Anchored on the issue that opened it, NOT on a fixed grid: nothing
    -- downstream compares one account's window to another's.
    ADD COLUMN IF NOT EXISTS proofs_window_start  TIMESTAMPTZ;
