'''
Main entry point for the Session Pro Backend. This runs the necessary setup code like initialising
the DB and responding startup arguments before handing over control-flow to Flask.

For database operations (user errors, revocations, reports, etc.), use the cli.py tool instead.
'''

import flask
import flask.logging
import nacl.signing
import logging
import sys

import base
import backend
import config
import db
import server

log = logging.getLogger('pro')
webhook_loggers: list[base.AsyncSessionWebhookLogHandler] = []


def entry_point() -> flask.Flask:
    # Enough logging to report a bad config; the real levels are not known until it is read.
    base.bootstrap_logging()

    # NOTE: Parse arguments from .INI if present and environment variables, then setup global variables
    try:
        parsed_args: config.ParsedArgs = config.parse_args()
    except config.ConfigError as e:
        log.error(f'Failed to startup, invalid configuration options:\n  {e}')
        sys.exit(1)

    base.configure_logging(parsed_args.log_level, parsed_args.log_levels)
    log_formatter = base.LogFormatter(base.LOG_FORMAT)  # webhook handlers format their own records
    base.UNSAFE_LOGGING = parsed_args.unsafe_logging
    db.set_dsn(parsed_args.db_url)
    base.RENEWAL_LATENCY_ALLOWANCE = parsed_args.renewal_latency_allowance
    base.PROVIDER_DRY_RUN = parsed_args.provider_dry_run
    # Only this process issues proofs, so the mules have no use for it.
    base.MAX_PROOFS_PER_WINDOW = parsed_args.max_proofs_per_window

    # NOTE: log_path is deliberately ignored here. Under uWSGI the vassal's `logto` already captures
    # this process's stdout/stderr into the log file and rotates it (log-maxsize/log-backupname); a
    # second app-managed RotatingFileHandler on the same path would double-write, and it isn't
    # rotation-safe across the multiple workers + mule anyway. log_path stays a config option only
    # for non-uWSGI/CLI use (see cli.py) — it does nothing in the Flask/uWSGI process.

    # NOTE: Equip the session webhook URL if it's configured
    for it in parsed_args.session_webhooks:
        if it.enabled:
            webhook_logger = base.AsyncSessionWebhookLogHandler(url=it.url, name=it.name)
            webhook_logger.setLevel(logging.WARNING)
            webhook_logger.setFormatter(log_formatter)
            webhook_loggers.append(webhook_logger)

            # Console handlers came from configure_logging; these are additional sinks, so they are
            # ADDED rather than replacing anything.
            log.addHandler(webhook_logger)
            backend.log.addHandler(webhook_logger)

    # NOTE: Import the Google provider only if enabled — a disabled provider loads nothing at all (this
    # is what keeps grpcio out of the process). Logging is wired here; its runtime work lives in the mule.
    if parsed_args.with_provider_google_play:
        from providers import google_play

        for handler in webhook_loggers:
            google_play.log.addHandler(handler)

    # NOTE: Load the backend Ed25519 signing key from disk. It is NEVER stored in the DB. The app does
    # not (and its user should not be able to) write this file — deployment creates it — so a
    # missing/unreadable key is a hard startup error rather than a silent regeneration that would
    # invalidate every proof already issued. Tests/dev supply an ephemeral key via the same path.
    if not parsed_args.backend_key_path:
        log.error('No backend signing key configured: set [base] backend_key_path (or SESH_PRO_BACKEND_KEY_PATH)')
        sys.exit(1)
    try:
        backend_key: nacl.signing.SigningKey = backend.load_backend_signing_key(parsed_args.backend_key_path)
    except Exception as e:
        log.error(f'Failed to load backend signing key from "{parsed_args.backend_key_path}": {e}')
        sys.exit(1)

    # NOTE: entry_point runs in the uWSGI master, BEFORE it forks the workers and mule. Everything it
    # does with the DB is one-shot startup work (schema migration, the startup-log read, Apple's
    # missed-notification catch-up), so it runs on a single throwaway connection, NEVER a pool: a
    # ConnectionPool opened here would spawn background worker threads, and forking a multi-threaded
    # process corrupts the children's thread state — a hard segfault when the pool is closed at reload
    # (Python 3.13). Each worker/mule builds its own pool lazily, post-fork (db.connection -> db.pool).
    try:
        conn = db.connect_one(parsed_args.db_url)
    except Exception as e:
        log.error(f'Failed to open/connect to DB at {parsed_args.db_url}: {e}', exc_info=True)
        sys.exit(1)

    with conn:
        try:
            backend.migrate_schema(conn)
        except Exception as e:
            log.error(f'{e}', exc_info=True)
            sys.exit(1)

        startup_log = '\n'
        startup_log += 'Session Pro Backend\n'
        startup_log += '  Features:\n'
        if len(parsed_args.ini_path) > 0:
            startup_log += f'    Config .INI file loaded: {parsed_args.ini_path}\n'
        startup_log += f'    DB loaded from: {parsed_args.db_url}\n'
        if len(parsed_args.log_path):
            startup_log += '    log_path is set but ignored under uWSGI (the vassal `logto` owns the log file)\n'
        if parsed_args.unsafe_logging:
            startup_log += '    Unsafe logging enabled (this must NOT be used in production)\n'
        if parsed_args.provider_dry_run:
            startup_log += '    provider_dry_run ENABLED: all payment-provider egress is stubbed (NO FOR PRODUCTION)\n'
        if parsed_args.dev_endpoints:
            startup_log += (
                '    dev_endpoints ENABLED: /dev/* routes are live and will mint Pro subscriptions for'
                ' ANY unauthenticated caller (NOT FOR PRODUCTION)\n'
            )
        if parsed_args.with_provider_app_store:
            # The environment named here is the App Store Server API's (which endpoint we call and which
            # root certs verify it), NOT a property of the notification route: Apple posts to the same
            # endpoint either way, and which environment a notification came from is a field inside it.
            env = 'sandbox' if parsed_args.apple_sandbox_env else 'production'
            startup_log += f'    Platform: Apple App Store notifications enabled ({env} API environment)\n'
        if parsed_args.with_provider_google_play:
            startup_log += '    Platform: Google Play notifications enabled\n'
        for it in parsed_args.session_webhooks:
            if it.enabled:
                startup_log += f'    Webhook Logger: Enabled (display name: {it.name})\n'

        log.info(startup_log)
        for handler in webhook_loggers:
            handler.emit_text(f'Starting up instance: {startup_log}')

        # NOTE: Add flask to our global logger
        result: flask.Flask = server.init(
            testing_mode=False,
            database_url=parsed_args.db_url,
            backend_key=backend_key,
            dev_endpoints=parsed_args.dev_endpoints,
        )
        # Flask lazily attaches its own default_handler to app.logger the first time it's accessed
        # (the addHandler below triggers that); remove it so app records aren't emitted twice — once
        # in Flask's format and once in ours.
        base.install_log_handler(result.logger, parsed_args.log_levels.get('flask', parsed_args.log_level))
        result.logger.removeHandler(flask.logging.default_handler)
        for handler in webhook_loggers:
            result.logger.addHandler(handler)

        # NOTE: Enable Apple iOS App Store notifications routes on the server if enabled. Apple will
        # contact the endpoint when a notification is generated.
        if parsed_args.with_provider_app_store:
            # Import the Apple provider only if enabled — zero footprint when disabled.
            from providers import app_store

            for handler in webhook_loggers:
                app_store.log.addHandler(handler)
            core: app_store.Core = app_store.init(
                key_id=parsed_args.apple_key_id,
                issuer_id=parsed_args.apple_issuer_id,
                bundle_id=parsed_args.apple_bundle_id,
                app_id=None if parsed_args.apple_sandbox_env else parsed_args.apple_app_id,
                key_bytes=parsed_args.apple_key,
                root_certs=parsed_args.apple_root_certs,
                sandbox_env=parsed_args.apple_sandbox_env,
            )
            app_store.equip_flask_routes(core, result)

        # NOTE: Singleton background work does NOT run here. The Google Pub/Sub subscriber runs in its own
        # mule (providers/google_play/mule.py), and the periodic prune plus the Apple notification catch-up
        # run in the maintenance mule (maintenance.py) — a plain loop, so neither needs a uWSGI signal and
        # neither competes with request handling. Only the Apple notification ROUTE is registered above,
        # because that is an HTTP endpoint the workers serve.
    return result


# Flask entry point
flask_app: flask.Flask = entry_point()
