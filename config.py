'''
Startup configuration for the Session Pro Backend: the `.INI` + environment parsing that produces a
`ParsedArgs`. Kept separate from `main.py` so it can be imported without side effects by both the Flask
entry point (`main.py`) and the maintenance mule (`providers/google_play/mule.py`) — importing `main`
would build the Flask app.
'''

import configparser
import dataclasses
import logging
import os
import pathlib
import sys

import pendulum

import base

log = logging.getLogger('pro')


class ConfigError(ValueError):
    '''Startup configuration is invalid. Carries every problem found: parse_args accumulates them so the
    operator sees all the bad/missing fields at once rather than one per rerun. `str(e)` is the joined,
    indented list ready to log.'''

    def __init__(self, errors: list[str]):
        self.errors: list[str] = errors
        super().__init__('\n  '.join(errors))


@dataclasses.dataclass
class SessionWebhook:
    enabled: bool = False
    url: str = ''
    name: str = ''


@dataclasses.dataclass
class ParsedArgs:
    ini_path: str = ''
    db_url: str = ''
    backend_key_path: str = ''
    log_path: str = ''
    unsafe_logging: bool = False

    with_provider_app_store: bool = False
    with_provider_google_play: bool = False

    provider_dry_run: bool = False

    dev_endpoints: bool = False

    # How old an account's voucher checkpoint must be before a maintenance pass charges it again. Does not
    # affect HOW MUCH is charged -- that is always the span since the checkpoint, whenever the pass runs --
    # only how promptly a spent voucher stops entitling the account, and how the write load is spread.
    voucher_processing_window: pendulum.Duration = 1 * base.DAY

    # How long a renewing subscription is honoured past its paid-through instant while we wait to learn
    # whether it renewed. Ours, not a store's — see base.RENEWAL_LATENCY_ALLOWANCE.
    renewal_latency_allowance: pendulum.Duration = base.RENEWAL_LATENCY_ALLOWANCE

    # How many proofs one account may be issued per base.PROOF_ISSUE_WINDOW; 0 = unlimited. See
    # base.MAX_PROOFS_PER_WINDOW for why unlimited is the default.
    max_proofs_per_window: int = base.MAX_PROOFS_PER_WINDOW

    # `[logging] level` -- the level every logger gets unless named individually below. INFO rather
    # than DEBUG so a fresh deploy is production-shaped: DEBUG adds a line per provider notification.
    log_level: int = logging.INFO
    # `[logging] level-<name>` -- per-logger overrides, keyed by the name in the log line. Not
    # restricted to this application's categories, so `level-werkzeug = error` works too.
    log_levels: dict[str, int] = dataclasses.field(default_factory=dict)

    session_webhooks: list[SessionWebhook] = dataclasses.field(default_factory=list)

    apple_key_id: str = ''
    apple_issuer_id: str = ''
    apple_bundle_id: str = ''
    apple_key_path: str = ''
    apple_root_cert_path: str = ''
    apple_root_cert_ca_g2_path: str = ''
    apple_root_cert_ca_g3_path: str = ''
    apple_key: bytes = b''
    apple_root_certs: list[bytes] = dataclasses.field(default_factory=list)
    apple_sandbox_env: bool = False
    apple_app_id: int | None = None

    google_package_name: str = ''
    google_cloud_app_credentials_path: str = ''
    google_cloud_project_id: str = ''
    google_cloud_subscription_name: str = ''
    google_subscription_product_id: str = ''


def parse_args() -> ParsedArgs:
    # NOTE: Parse .INI file if present and get arguments for it. Field-validation problems are
    # accumulated (so the operator sees every bad/missing field at once) and raised together as a
    # ConfigError at the end; unrecoverable structural problems (missing .INI, malformed webhook
    # section) still log + sys.exit immediately.
    errors: list[str] = []
    result = ParsedArgs()
    result.ini_path = os.getenv('SESH_PRO_BACKEND_INI_PATH', '')
    if len(result.ini_path) > 0:
        if not pathlib.Path(result.ini_path).exists():
            log.error(f'.INI config file "{result.ini_path}", was specified but does not exist/is not readable')
            sys.exit(1)

        ini_parser = configparser.ConfigParser()
        ini_parser.read(filenames=result.ini_path)

        base_section: configparser.SectionProxy = ini_parser['base']
        result.db_url = base_section.get(option='db_url', fallback='')
        result.backend_key_path = base_section.get(option='backend_key_path', fallback='')
        result.unsafe_logging = base_section.getboolean(option='unsafe_logging', fallback=False)

        result.with_provider_app_store = base_section.getboolean(option='with_provider_app_store', fallback=False)
        result.with_provider_google_play = base_section.getboolean(option='with_provider_google_play', fallback=False)

        result.provider_dry_run = base_section.getboolean(option='provider_dry_run', fallback=False)

        result.dev_endpoints = base_section.getboolean(option='dev_endpoints', fallback=False)

        allowance_s = base_section.getint(option='renewal_latency_allowance', fallback=None)
        if allowance_s is not None:
            if allowance_s < 0:
                errors.append(f'renewal_latency_allowance must not be negative, got {allowance_s}')
            else:
                # Bounded above as well as below, unlike the voucher window: this value EXTENDS entitlement,
                # so a units slip (milliseconds pasted into a seconds field) silently grants everyone years
                # of Pro. A week is well past any plausible outage and still orders of magnitude below a
                # typo.
                max_allowance_s = 7 * base.SECONDS_IN_DAY
                if allowance_s > max_allowance_s:
                    errors.append(
                        f'renewal_latency_allowance must not exceed {max_allowance_s}s (7 days), '
                        f'got {allowance_s} — it extends every renewing subscriber\'s entitlement'
                    )
                else:
                    result.renewal_latency_allowance = base.duration_from_seconds(allowance_s)

        max_proofs = base_section.getint(option='max_proofs_per_window', fallback=None)
        if max_proofs is not None:
            if max_proofs < 0:
                errors.append(f'max_proofs_per_window must not be negative (0 = unlimited), got {max_proofs}')
            else:
                result.max_proofs_per_window = max_proofs

        window_s = base_section.getint(option='voucher_processing_window', fallback=None)
        if window_s is not None:
            if window_s < 0:
                errors.append(f'voucher_processing_window must not be negative, got {window_s}')
            else:
                result.voucher_processing_window = base.duration_from_seconds(window_s)

        if ini_parser.has_section('logging'):
            logging_section: configparser.SectionProxy = ini_parser['logging']

            def parse_level(key: str, raw: str) -> int | None:
                # `getLevelName` maps a name to its number, but for anything it does not recognise it
                # returns the STRING 'Level <name>' rather than raising -- so an unrecognised value has to
                # be rejected here or it silently becomes a non-level and filters nothing.
                level = logging.getLevelName(raw.strip().upper())
                if isinstance(level, int):
                    return level
                errors.append(f'[logging] {key} must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL; got "{raw}"')
                return None

            for key, raw in logging_section.items():
                if key == 'level':
                    level = parse_level(key, raw)
                    if level is not None:
                        result.log_level = level
                elif key == 'path':
                    result.log_path = raw.strip()
                elif key.startswith('level-'):
                    # The logger NAME, verbatim after the prefix. configparser lower-cases keys, which is
                    # why the categories are lowercase: `level-google_play` has to be able to name the
                    # logger that writes the line.
                    name = key[len('level-') :]
                    level = parse_level(key, raw)
                    if not name:
                        errors.append('[logging] "level-" needs a logger name after the dash')
                    elif level is not None:
                        result.log_levels[name] = level
                else:
                    errors.append(f'[logging] unrecognised option "{key}" (expected level, level-<name> or path)')

        webhook_index = 0
        while True:
            webhook_label: str = f'session_webhook.{webhook_index}'
            if not ini_parser.has_section(webhook_label):
                break

            webhook_section: configparser.SectionProxy = ini_parser[webhook_label]
            webhook_enabled: bool | None = webhook_section.getboolean('enabled')
            webhook_url: str | None = webhook_section.get('url')
            webhook_name: str | None = webhook_section.get('name')

            if webhook_name is None:
                log.error(f"Failed to parse webhook section {webhook_label}, missing \'name\'")
                sys.exit(1)

            if webhook_url is None:
                log.error(f"Failed to parse webhook section {webhook_label}, missing \'url\'")
                sys.exit(1)

            if webhook_enabled is None:
                log.error(f"Failed to parse webhook section {webhook_label}, missing \'enabled\'")
                sys.exit(1)

            webhook_index += 1
            result.session_webhooks.append(SessionWebhook(name=webhook_name, url=webhook_url, enabled=webhook_enabled))

        if result.with_provider_app_store:
            if 'apple' in ini_parser:
                apple_section: configparser.SectionProxy = ini_parser['apple']
                result.apple_app_id = apple_section.getint(option='app_id')
                result.apple_bundle_id = apple_section.get(option='bundle_id', fallback='')
                result.apple_issuer_id = apple_section.get(option='issuer_id', fallback='')
                result.apple_key_id = apple_section.get(option='key_id', fallback='')
                result.apple_key_path = apple_section.get(option='key_path', fallback='')
                result.apple_root_cert_ca_g2_path = apple_section.get(option='root_cert_ca_g2_path', fallback='')
                result.apple_root_cert_ca_g3_path = apple_section.get(option='root_cert_ca_g3_path', fallback='')
                result.apple_root_cert_path = apple_section.get(option='root_cert_path', fallback='')
                result.apple_sandbox_env = apple_section.getboolean(option='sandbox_env', fallback=False)
            else:
                errors.append('Provider app_store was enabled but [apple] section is missing')

        if result.with_provider_google_play:
            if 'google' in ini_parser:
                google_section: configparser.SectionProxy = ini_parser['google']
                result.google_cloud_app_credentials_path = google_section.get(
                    option='cloud_app_credentials_path', fallback=''
                )
                result.google_cloud_project_id = google_section.get(option='cloud_project_id', fallback='')
                result.google_cloud_subscription_name = google_section.get(
                    option='cloud_subscription_name', fallback=''
                )
                result.google_package_name = google_section.get(option='package_name', fallback='')
                result.google_subscription_product_id = google_section.get(
                    option='subscription_product_id', fallback=''
                )
            else:
                errors.append('Provider google_play was enabled but [google] section is missing')

    # NOTE: Get arguments from environment, they override .INI values if specified
    result.db_url = os.getenv('SESH_PRO_BACKEND_DB_URL', result.db_url)
    result.backend_key_path = os.getenv('SESH_PRO_BACKEND_KEY_PATH', result.backend_key_path)
    result.log_path = os.getenv('SESH_PRO_BACKEND_LOG_PATH', result.log_path)
    result.with_provider_app_store = base.os_get_boolean_env(
        'SESH_PRO_BACKEND_WITH_PROVIDER_APP_STORE', result.with_provider_app_store
    )
    result.with_provider_google_play = base.os_get_boolean_env(
        'SESH_PRO_BACKEND_WITH_PROVIDER_GOOGLE_PLAY', result.with_provider_google_play
    )
    result.provider_dry_run = base.os_get_boolean_env('SESH_PRO_BACKEND_PROVIDER_DRY_RUN', result.provider_dry_run)
    result.dev_endpoints = base.os_get_boolean_env('SESH_PRO_BACKEND_DEV_ENDPOINTS', result.dev_endpoints)

    # NOTE: The dev endpoints forge payments out of thin air — no provider, no signature, no payment.
    # They are only ever safe on a throwaway instance, so they are hard-wired to provider_dry_run: an
    # instance that can still reach Apple/Google is, by definition, not throwaway. Refusing to start is
    # deliberate — a warning would be ignored, and the failure mode here is "anyone can mint Pro".
    if result.dev_endpoints and not result.provider_dry_run:
        errors.append(
            'dev_endpoints was enabled but provider_dry_run is not set. The dev endpoints mint payments'
            ' with no payment provider involved and MUST NOT run on an instance with live provider egress'
        )

    if result.with_provider_app_store:
        if len(result.apple_key_id) == 0:
            errors.append('Provider app_store was enabled but key_id was not specified')
        if len(result.apple_issuer_id) == 0:
            errors.append('Provider app_store was enabled but issuer_id was not specified')
        if len(result.apple_bundle_id) == 0:
            errors.append('Provider app_store was enabled but bundle_id was not specified')
        if len(result.apple_key_path) == 0:
            errors.append('Provider app_store was enabled but key_path was not specified')
        if len(result.apple_root_cert_path) == 0:
            errors.append('Provider app_store was enabled but root_cert_path was not specified')
        if len(result.apple_root_cert_ca_g2_path) == 0:
            errors.append('Provider app_store was enabled but root_cert_ca_g2_path was not specified')
        if len(result.apple_root_cert_ca_g3_path) == 0:
            errors.append('Provider app_store was enabled but root_cert_ca_g3_path was not specified')

        if not result.apple_sandbox_env:
            if result.apple_app_id is None:
                errors.append(
                    'Provider app_store was enabled in production mode (e.g. not sandbox mode)'
                    ' but the production_app_id was not specified'
                )

        if not errors:
            try:
                result.apple_key = pathlib.Path(result.apple_key_path).read_bytes()
                result.apple_root_certs = [
                    pathlib.Path(result.apple_root_cert_path).read_bytes(),
                    pathlib.Path(result.apple_root_cert_ca_g2_path).read_bytes(),
                    pathlib.Path(result.apple_root_cert_ca_g3_path).read_bytes(),
                ]
            except Exception as e:
                errors.append(f'Provider app_store was enabled but we are unable to read the path: {e}')

    if result.with_provider_google_play:
        if len(result.google_package_name) == 0:
            errors.append('Provider google_play was enabled but package_name was not specified')
        if len(result.google_cloud_project_id) == 0:
            errors.append('Provider google_play was enabled but cloud_project_id was not specified')
        if len(result.google_cloud_subscription_name) == 0:
            errors.append('Provider google_play was enabled but cloud_subscription_name was not specified')
        if len(result.google_cloud_app_credentials_path) == 0:
            errors.append('Provider google_play was enabled but cloud_application_credentials_path was not specified')
        if len(result.google_subscription_product_id) == 0:
            errors.append('Provider google_play was enabled but subscription_product_id was not specified')

    if errors:
        raise ConfigError(errors)

    return result
