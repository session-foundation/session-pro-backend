'''
The per-account proof-issuance counters, and the cap they can be judged against.

A proof is a bearer credential verified offline against a rotating key that names no account, so nothing
downstream can tell a subscriber's proof from a copy of it. These counters are the only place the backend
can see that one account is feeding many installs; the tests below pin what they count, what they refuse
to count, and that the window restarts rather than accumulating forever.
'''

import nacl.signing
import pendulum
import pytest

import backend
import base
import db

from tests.helpers import _CreditFixture, _prove_at, round_datetime_to_next_day


def _counters(conn, pkey) -> tuple[int, int, pendulum.DateTime | None]:
    user = backend.get_user(conn, pkey)
    return user.proofs_issued_total, user.proofs_issued_window, user.proofs_window_start


def _past_expiry(conn, pkey) -> int:
    return backend.get_user(conn, pkey).proofs_issued_past_expiry_window


def test_counters_start_unset_and_track_each_issue(pg_database):
    # An account that has never asked for a proof has no window: NULL rather than an epoch sentinel, which
    # would claim a window that had really elapsed. The first issue opens one, anchored on that issue.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()

    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        f.subscribe(expiry_at=T + 30 * base.DAY)

        assert _counters(conn, f.pkey) == (0, 0, None)

        _prove_at(conn, backend_key, f.master_key, rotating_key, T)
        assert _counters(conn, f.pkey) == (1, 1, T)

        # A second proof inside the window advances both counts and leaves the window where it opened.
        _prove_at(conn, backend_key, f.master_key, rotating_key, T + base.HOUR)
        assert _counters(conn, f.pkey) == (2, 2, T)
    pool.close()


def test_window_restarts_from_the_issue_that_opens_it(pg_database):
    # The window is a rate measurement, not a calendar: an account that goes quiet starts a fresh window on
    # its next proof rather than being credited for the windows it sat out. The lifetime total is the one
    # value that never resets -- it is what documents a violation after the fact.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()

    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        f.subscribe(expiry_at=T + 365 * base.DAY)

        _prove_at(conn, backend_key, f.master_key, rotating_key, T)
        _prove_at(conn, backend_key, f.master_key, rotating_key, T + base.HOUR)
        assert _counters(conn, f.pkey) == (2, 2, T)

        # Exactly one window later: the boundary is inclusive, so this opens a new window rather than
        # landing in the old one's last instant.
        rolled = T + base.PROOF_ISSUE_WINDOW
        _prove_at(conn, backend_key, f.master_key, rotating_key, rolled)
        assert _counters(conn, f.pkey) == (3, 1, rolled)

        # A long silence does not accumulate windows: the next proof anchors on itself.
        much_later = rolled + 30 * base.DAY
        _prove_at(conn, backend_key, f.master_key, rotating_key, much_later)
        assert _counters(conn, f.pkey) == (4, 1, much_later)
    pool.close()


def test_a_refused_proof_is_not_counted(pg_database):
    # The counters measure proofs ISSUED, not requests attempted. A lapsed account hammering the endpoint
    # must not advance them -- otherwise a cap could be consumed entirely by requests that were always
    # going to be refused, and the number an operator reads would not mean what its name says.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()

    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        term_end = T + base.HOUR
        f.subscribe(expiry_at=term_end, auto_renewing=False)

        _prove_at(conn, backend_key, f.master_key, rotating_key, T)
        assert _counters(conn, f.pkey)[:2] == (1, 1)

        lapsed_at = term_end + base.PROOF_EXPIRY_SHAPE.max_proof_lifetime
        for _ in range(3):
            with pytest.raises(base.FailError) as excinfo:
                _prove_at(conn, backend_key, f.master_key, rotating_key, lapsed_at)
            assert excinfo.value.code == base.ErrorCode.subscription_expired
        assert _counters(conn, f.pkey)[:2] == (1, 1), 'refusals must not advance the counters'
    pool.close()


def test_a_generation_roll_clears_the_window(pg_database):
    # A revocation mints a fresh generation, which invalidates every proof the account holds and forces all
    # of its devices to re-fetch at once. Those re-fetches are the SAME installs the window already counted,
    # so the window restarts with the tag -- an account is not charged for an invalidation we performed.
    # The lifetime total is untouched: nothing about the account's history stops being true.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()

    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        f.subscribe(expiry_at=T + 365 * base.DAY)

        for i in range(3):
            _prove_at(conn, backend_key, f.master_key, rotating_key, T + i * base.HOUR)
        assert _counters(conn, f.pkey) == (3, 3, T)
        before = backend.get_user(conn, f.pkey).token

        with db.transaction(conn) as tx:
            backend.revoke_master_pkey_proofs_and_allocate_new_gen_id(tx, f.pkey, created_at=T + 4 * base.HOUR)

        total, window, window_start = _counters(conn, f.pkey)
        assert backend.get_user(conn, f.pkey).token != before, 'the fixture must have rolled the tag'
        assert (total, window, window_start) == (3, 0, None)

        # The next proof opens a fresh window anchored on itself, exactly as a first-ever proof does.
        resumed = T + 5 * base.HOUR
        _prove_at(conn, backend_key, f.master_key, rotating_key, resumed)
        assert _counters(conn, f.pkey) == (4, 1, resumed)
    pool.close()


def test_a_renewal_does_not_clear_the_window(pg_database):
    # The other half, and the reason the reset hangs off the generation roll rather than off "a payment
    # arrived": a renewal REUSES the generation, so the tag is unchanged, existing proofs stay valid and no
    # re-fetch is forced. There is nothing to forgive -- and resetting here would hand the same monthly
    # amnesty to an account whose seed is being shared, which renews like any other.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()

    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        f.subscribe(expiry_at=T + 30 * base.DAY)

        for i in range(3):
            _prove_at(conn, backend_key, f.master_key, rotating_key, T + i * base.HOUR)
        assert _counters(conn, f.pkey) == (3, 3, T)
        before = backend.get_user(conn, f.pkey).token

        # A second cycle lands: the payment stacks onto the same account and the same generation.
        f.subscribe(expiry_at=T + 60 * base.DAY, purchased_at=T + 4 * base.HOUR)

        assert backend.get_user(conn, f.pkey).token == before, 'a renewal must not roll the tag'
        assert _counters(conn, f.pkey) == (3, 3, T)
    pool.close()


def test_past_expiry_proofs_are_counted_but_not_limited(pg_database):
    # The split the limit turns on. Past its paid term the account's proof expiry is PINNED -- every
    # re-fetch returns the identical value -- so a client whose renewal target has fallen inside that
    # window re-asks having been handed nothing to act on. That is a paying subscriber with a late renewal,
    # so the requests are recorded (and visibly so) but are not what a cap is judged against.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()

    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        term_end = T + 30 * base.DAY
        f.subscribe(expiry_at=term_end)

        # Before expiry: counted, and subject to the limit.
        first = _prove_at(conn, backend_key, f.master_key, rotating_key, term_end - base.HOUR)
        assert _counters(conn, f.pkey)[:2] == (1, 1)
        assert _past_expiry(conn, f.pkey) == 0

        # The client's renewal target lands PAST the term end -- always, for any account inside the clamp,
        # because the last proof before expiry is pinned just beyond it.
        loop_at = first.expiry_at - base.HOUR
        assert loop_at > term_end, 'the pinned expiry puts the next wake past the paid term'

        # Ten re-fetches from there. Each returns the same proof, and each is recorded as past-expiry.
        for i in range(10):
            again = _prove_at(conn, backend_key, f.master_key, rotating_key, loop_at + i * pendulum.duration(minutes=1))
            assert again.expiry_at == first.expiry_at, 'the expiry is pinned: re-asking gains the client nothing'

        total, window, _ = _counters(conn, f.pkey)
        assert (total, window) == (11, 11), 'every issue is counted'
        assert _past_expiry(conn, f.pkey) == 10, 'and ten of them are marked past-expiry'
    pool.close()


def test_a_late_renewal_loop_cannot_trip_the_cap(monkeypatch, pg_database):
    # The consequence, with a cap configured: the retry loop above must not refuse a subscriber whose
    # renewal is merely late. A cap low enough to catch a fleet is destroyed in minutes by this loop, so
    # the limit reads the before-expiry count and nothing else.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()

    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        term_end = T + 30 * base.DAY
        f.subscribe(expiry_at=term_end)
        # The one before-expiry proof is taken BEFORE the cap goes on, so the cap has room for it and this
        # test is measuring the loop rather than that first request.
        first = _prove_at(conn, backend_key, f.master_key, rotating_key, term_end - base.HOUR)
        loop_at = first.expiry_at - base.HOUR

        monkeypatch.setattr(base, 'MAX_PROOFS_PER_WINDOW', 3)
        # Far more requests than the cap, all past expiry: every one is served.
        for i in range(20):
            _prove_at(conn, backend_key, f.master_key, rotating_key, loop_at + i * pendulum.duration(minutes=1))

        assert _past_expiry(conn, f.pkey) == 20
        assert _counters(conn, f.pkey)[:2] == (21, 21)
    pool.close()


def test_cap_is_unlimited_by_default(pg_database):
    # 0 = unlimited, and it is the shipped default: the counters exist to be looked at before anyone picks
    # a number, and a cap guessed ahead of real traffic would refuse legitimate users.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    assert base.MAX_PROOFS_PER_WINDOW == 0
    backend_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()

    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        f.subscribe(expiry_at=T + 30 * base.DAY)
        for i in range(25):
            _prove_at(conn, backend_key, f.master_key, rotating_key, T + i * base.HOUR)
        assert _counters(conn, f.pkey)[:2] == (25, 25)
    pool.close()


def test_cap_refuses_past_the_limit_and_recovers_next_window(monkeypatch, pg_database):
    # With a cap configured, the (cap+1)'th proof in a window is refused with `rate_limited` and the count
    # does not advance past the cap -- the refusal rolls its own increment back, so a capped account cannot
    # be pushed further from the limit by continuing to ask.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    monkeypatch.setattr(base, 'MAX_PROOFS_PER_WINDOW', 3)
    backend_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()

    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        f.subscribe(expiry_at=T + 365 * base.DAY)

        for i in range(3):
            _prove_at(conn, backend_key, f.master_key, rotating_key, T + i * base.HOUR)
        assert _counters(conn, f.pkey)[:2] == (3, 3)

        for i in range(2):
            with pytest.raises(base.FailError) as excinfo:
                _prove_at(conn, backend_key, f.master_key, rotating_key, T + (3 + i) * base.HOUR)
            assert excinfo.value.code == base.ErrorCode.rate_limited
        assert _counters(conn, f.pkey)[:2] == (3, 3), 'a refused request rolls its own increment back'

        # The cap is per window, not terminal: the account is served again once the window rolls.
        rolled = T + base.PROOF_ISSUE_WINDOW
        _prove_at(conn, backend_key, f.master_key, rotating_key, rolled)
        assert _counters(conn, f.pkey)[:2] == (4, 1)
    pool.close()
