-- `google_notification_history.expires_at` -> `event_at`, holding Google's `eventTimeMillis` instead of
-- that instant plus our retention window.
--
-- The column was our retention policy fossilised into a row of store facts: the writer added eight days
-- before the INSERT and the prune compared against the sum, so a change to the window would leave every
-- existing row on the old one, and the instant Google actually reported was recoverable only by knowing
-- what the constant had been on the day each row was written. The prune now subtracts
-- `base.GOOGLE_NOTIFICATION_RETAIN_FOR` on read, which is what `delete_expired_revocations` already does
-- against `revoked_at`.
--
-- Backfilled by subtracting the window every existing row was written with. Denominated in hours, not
-- days: `interval '8 days'` added to a timestamptz is a calendar step, which a DST transition moves by an
-- hour, and the same rule applies here as to the pendulum Durations in the source.

-- A rename has no IF EXISTS form, so this is guarded on the old name still being present, per schema/README.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'google_notification_history' AND column_name = 'expires_at') THEN
        ALTER TABLE google_notification_history RENAME COLUMN expires_at TO event_at;
        UPDATE google_notification_history SET event_at = event_at - interval '192 hours';
    END IF;
END $$;
