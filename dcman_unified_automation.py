import os
import csv
import requests
import json
import logging
import logging.handlers
import urllib3
import argparse
import re
from time import sleep
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from dataclasses import dataclass
from ipaddress import ip_network
import sys
import itertools
from pathlib import Path

# Disable HTTPS Insecure Warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Request hardening defaults
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
ALLOW_INSECURE_TLS = False
ENV_FILE_PATH = Path(".env")

"""
Phosphorus Unified Automation Tool v6 - With Scan Export to Text or CSV

Enhancements in v6:
- Scan export functionality: export current scan configurations and completed scan history
- Text and CSV export formats for both current scans and historical data
- Advanced filtering: by status (completed/canceled/failed/all), date ranges, scan names
- Large dataset support with progress tracking and configurable limits
- Enhanced network extraction with multiple fallback sources
- Improved duration formatting and status detection

Previous enhancements (v5):
- Run-now scan support with three options: 'yes', 'no', 'only'
- Template generation and system info display
- SNMP comparison functionality and comprehensive validation

SCAN/TAG CREATION:
  Create template:    python phosphorus_unified_automation.py --create-template template.csv
  Process CSV:        python phosphorus_unified_automation.py --input-csv input.csv --api-host host --api-key key
  Dry run:            python phosphorus_unified_automation.py --input-csv input.csv --api-host host --api-key key --dry-run
  Get system info:    python phosphorus_unified_automation.py --phosphorus-info --api-host host --api-key key

SCAN SCHEDULE DETAILS:
  Current scans text: python phosphorus_unified_automation.py --scan-details-text scan_report.txt --api-host host --api-key key
  Current scans CSV:  python phosphorus_unified_automation.py --scan-details-csv scan_report.csv --api-host host --api-key key

SCAN HISTORY:
  Basic history:      python phosphorus_unified_automation.py --scan-history-csv history.csv --api-host host --api-key key
  Filter by name:     python phosphorus_unified_automation.py --scan-history-csv history.csv --scan-name-query "Nightly" --api-host host --api-key key
  Last 7 days:        python phosphorus_unified_automation.py --scan-history-csv history.csv --days-ago 7 --api-host host --api-key key
  Date range:         python phosphorus_unified_automation.py --scan-history-text history.txt --start-date 01-01-2025 --end-date 01-31-2025 --api-host host --api-key key
  Canceled scans:     python phosphorus_unified_automation.py --scan-history-csv canceled.csv --scan-status canceled --api-host host --api-key key
  All scan types:     python phosphorus_unified_automation.py --scan-history-text all_scans.txt --scan-status all --api-host host --api-key key
  Large datasets:     python phosphorus_unified_automation.py --scan-history-csv large.csv --max-results 100000 --api-host host --api-key key
"""

# --- VALIDATION CLASSES ---
@dataclass
class ValidationError(Exception):
    """Custom exception for CSV row validation failures.

    Attributes:
        message: Human-readable error description.
        row_number: 1-based CSV row where the error occurred.
        field: Name of the field that failed validation.
    """

    message: str
    row_number: int
    field: str


# Input validation helpers used before sending data to the API.
class InputValidator:
    """Collection of static validation methods for CSV input fields.

    All methods are stateless and operate on raw string values
    extracted from a CSV row.
    """

    @staticmethod
    def validate_color(color: str) -> bool:
        """Validate hex color format - accepts with or without ``#`` prefix.

        Args:
            color: Raw color string from CSV (e.g. ``"#FF5733"`` or ``"FF5733"``).

        Returns:
            ``True`` if *color* is a valid 3- or 6-character hex color.
        """
        if not color:
            return False
        # Remove # if present, then validate
        clean_color = color.lstrip('#')
        return bool(re.match(r'^([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$', clean_color))

    @staticmethod
    def validate_cron(cron: str) -> bool:
        """Allow any standard 5-field cron expression (basic check).

        Args:
            cron: Cron string (e.g. ``"0 0 1 * *"``).

        Returns:
            ``True`` when the string contains exactly five whitespace-separated fields.
        """
        fields = cron.split()
        return len(fields) == 5

    @staticmethod
    def validate_network(network: str) -> bool:
        """Validate network CIDR format (allow host addresses, not just network address).

        Args:
            network: CIDR string (e.g. ``"192.168.1.0/24"``).

        Returns:
            ``True`` if *network* parses as a valid IPv4/IPv6 network.
        """
        try:
            ip_network(network, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_required_fields(row: Dict[str, str], required_fields: list, row_number: int) -> None:
        """Validate required fields are present and not empty.

        Args:
            row: Mapping of column-name to value for a single CSV row.
            required_fields: Column names that must have non-empty values.
            row_number: 1-based row index used in error messages.

        Raises:
            ValidationError: If any required field is missing or blank.
        """
        for field in required_fields:
            if not row.get(field):
                raise ValidationError(
                    f"Required field '{field}' is missing or empty",
                    row_number,
                    field
                )

# --- CONFIGURATION ---
# Centralised runtime configuration populated from CLI arguments.
class Config:
    """Runtime configuration for the unified automation pipeline.

    Stores API credentials, processing flags, and the chosen UI mode.
    On construction the credentials are also pushed into environment
    variables so that helper functions can access them globally.

    Attributes:
        api_host: Phosphorus API hostname.
        api_key: API authentication key.
        input_csv: Path to the unified input CSV file.
        dry_run: When ``True`` no mutating API calls are made.
        force_scan_update: When ``True`` skip equality checks and always
            push scan updates.
        ui_mode: Progress display style (``'simple'``, ``'bar'``, or ``'rich'``).
        silent: Suppress all progress output when ``True``.
        validator: Shared :class:`InputValidator` instance.
    """

    def __init__(
        self,
        api_host: str,
        api_key: str,
        input_csv: str,
        dry_run: bool = False,
        force_scan_update: bool = False,
        ui_mode: str = 'simple',
        silent: bool = False,
    ):
        self.api_host = api_host
        self.api_key = api_key
        self.input_csv = input_csv
        self.dry_run = dry_run
        self.force_scan_update = force_scan_update
        self.ui_mode = ui_mode
        self.silent = silent
        self.validator = InputValidator()

        # Set environment variables so helper functions can access credentials.
        os.environ['PHO_API_HOST'] = api_host
        os.environ['PHO_API_KEY'] = api_key

# --- LOGGER SETUP ---
# Configures dual-output logging: console (WARNING+) and rotating file (DEBUG+).
def setup_logger(name: str, log_file: str) -> logging.Logger:
    """Create and configure a logger with console and rotating-file handlers.

    Args:
        name: Logger name (typically the script/module identifier).
        log_file: Path to the rotating log file.

    Returns:
        Configured :class:`logging.Logger` instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    # Console logging (WARNING and above only)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)  # Only show warnings/errors in terminal
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File logging (all levels)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10_000_000, backupCount=2
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger

logger = setup_logger('Phosphorus_Unified_Automation_v6', 'phosphorus_unified_automation.log')


# Read credentials / settings from a local .env file.
def parse_env_file(path: Path = ENV_FILE_PATH) -> Dict[str, str]:
    """Parse a simple ``.env`` file into a dictionary.

    Handles comments, ``export`` prefixes, and single/double quoted values.

    Args:
        path: Filesystem path to the ``.env`` file.

    Returns:
        Mapping of environment variable names to their string values.
    """
    env_data: Dict[str, str] = {}
    if not path.exists():
        return env_data

    for raw_line in path.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[len('export '):].strip()
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        env_data[key] = value
    return env_data


# Persist credentials back to the .env file in sorted key order.
def write_env_file(env_data: Dict[str, str], path: Path = ENV_FILE_PATH) -> None:
    """Write a deterministic ``.env`` file.

    Keys are sorted alphabetically to minimise diff noise between runs.

    Args:
        env_data: Key-value pairs to persist.
        path: Destination ``.env`` file path.
    """
    lines = [
        "# Phosphorus Unified Automation credentials",
        "# Generated/updated by phosphorus_unified_automation.py",
        ""
    ]
    for key in sorted(env_data.keys()):
        value = str(env_data[key]).replace('\n', ' ').strip()
        lines.append(f"{key}={value}")
    lines.append("")
    path.write_text("\n".join(lines), encoding='utf-8')


# Normalise a profile name so it can be used inside env-var keys.
def profile_key(profile_name: str) -> str:
    """Convert profile name to uppercase env-safe key segment.

    Non-alphanumeric characters (except underscores) are replaced with ``_``.

    Args:
        profile_name: Friendly profile name (e.g. ``"my-site"``).

    Returns:
        Uppercased key segment safe for use in environment variable names.
    """
    return re.sub(r'[^A-Za-z0-9_]', '_', profile_name.strip().upper())


# Scan parsed .env data for single or multi-profile credentials.
def extract_env_profiles(env_data: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    """Extract profile credentials from ``.env`` structure.

    Supports both the legacy single-profile keys (``PHO_API_HOST`` /
    ``PHO_API_KEY``) and multi-profile keys
    (``PHO_PROFILE_<NAME>_HOST`` / ``PHO_PROFILE_<NAME>_API_KEY``).

    Args:
        env_data: Parsed ``.env`` dictionary.

    Returns:
        Mapping of lowercase profile names to ``{'host': ..., 'api_key': ...}``.
    """
    profiles: Dict[str, Dict[str, str]] = {}

    # Backward-compatible single profile keys.
    if env_data.get('PHO_API_HOST') and env_data.get('PHO_API_KEY'):
        profiles['default'] = {
            'host': env_data['PHO_API_HOST'],
            'api_key': env_data['PHO_API_KEY']
        }

    # Multi-profile keys: PHO_PROFILE_<NAME>_HOST / _API_KEY
    for key, host_value in env_data.items():
        match = re.match(r'^PHO_PROFILE_([A-Z0-9_]+)_HOST$', key)
        if not match:
            continue
        segment = match.group(1)
        api_key = env_data.get(f'PHO_PROFILE_{segment}_API_KEY', '')
        if not api_key:
            continue
        # Preserve first discovered profile name case-insensitively.
        friendly_name = segment.lower()
        profiles[friendly_name] = {'host': host_value, 'api_key': api_key}

    return profiles


# Persist host/key under a named profile and keep legacy keys in sync.
def save_credentials_to_env(api_host: str, api_key: str, profile_name: str = 'default') -> None:
    """Save API host/key credentials to ``.env`` under a named profile.

    Updates the profile list and default-profile pointer.  When saving
    the ``"default"`` profile the legacy ``PHO_API_HOST`` / ``PHO_API_KEY``
    keys are kept in sync for backward compatibility.

    Args:
        api_host: Phosphorus API hostname.
        api_key: API authentication key.
        profile_name: Friendly profile label (default ``"default"``).
    """
    env_data = parse_env_file()
    pkey = profile_key(profile_name)

    env_data[f'PHO_PROFILE_{pkey}_HOST'] = api_host
    env_data[f'PHO_PROFILE_{pkey}_API_KEY'] = api_key

    profile_names = [name.strip() for name in env_data.get('PHO_PROFILE_NAMES', '').split(',') if name.strip()]
    if profile_name not in profile_names:
        profile_names.append(profile_name)
    env_data['PHO_PROFILE_NAMES'] = ",".join(profile_names) if profile_names else profile_name
    env_data['PHO_DEFAULT_PROFILE'] = profile_name

    # Keep legacy default keys in sync when saving default profile.
    if profile_name == 'default':
        env_data['PHO_API_HOST'] = api_host
        env_data['PHO_API_KEY'] = api_key

    write_env_file(env_data)


# Interactive profile chooser for terminals with multiple stored profiles.
def choose_profile_interactively(profiles: Dict[str, Dict[str, str]]) -> Optional[Dict[str, str]]:
    """Prompt user to choose a profile when multiple credentials exist.

    If only one profile is stored the function returns it immediately
    without prompting.

    Args:
        profiles: Mapping of profile names to ``{'host': ..., 'api_key': ...}``.

    Returns:
        The selected profile dictionary, or ``None`` if *profiles* is empty.
    """
    if not profiles:
        return None
    names = sorted(profiles.keys())
    if len(names) == 1:
        return profiles[names[0]]

    print("\nMultiple API profiles found in .env:")
    for idx, name in enumerate(names, 1):
        print(f"  {idx}) {name} ({profiles[name]['host']})")

    while True:
        selection = input("Select profile number: ").strip()
        if not selection.isdigit():
            print("Please enter a valid number.")
            continue
        selected_idx = int(selection)
        if 1 <= selected_idx <= len(names):
            return profiles[names[selected_idx - 1]]
        print("Selection out of range.")


# Determine API credentials from CLI args, .env profiles, or interactive selection.
def resolve_api_credentials(args, parser) -> tuple:
    """Resolve API credentials from args and ``.env`` profile(s).

    Resolution order:
    1. Explicit ``--api-host`` / ``--api-key`` CLI arguments.
    2. Named profile via ``--profile-name`` or ``PHO_DEFAULT_PROFILE``.
    3. Single profile auto-select.
    4. Interactive prompt when running in a TTY.

    Args:
        args: Parsed :class:`argparse.Namespace`.
        parser: The :class:`argparse.ArgumentParser` (used for error messages).

    Returns:
        Tuple of ``(api_host, api_key)``.

    Raises:
        SystemExit: Via ``parser.error()`` when credentials cannot be resolved.
    """
    if args.api_host and args.api_key:
        return args.api_host, args.api_key

    env_data = parse_env_file()
    profiles = extract_env_profiles(env_data)

    if not profiles:
        if args.api_host or args.api_key:
            parser.error("Both --api-host and --api-key are required when one is provided")
        parser.error("API credentials missing. Provide --api-host/--api-key or configure .env credentials.")

    # Explicit profile selection.
    selected_profile = getattr(args, 'profile_name', None) or env_data.get('PHO_DEFAULT_PROFILE')
    if selected_profile and selected_profile.lower() in profiles:
        selected = profiles[selected_profile.lower()]
        return selected['host'], selected['api_key']

    # Use single profile automatically.
    if len(profiles) == 1:
        selected = list(profiles.values())[0]
        return selected['host'], selected['api_key']

    # If running in interactive mode or terminal, prompt selection.
    if getattr(args, 'interactive', False) or sys.stdin.isatty():
        selected = choose_profile_interactively(profiles)
        if selected:
            return selected['host'], selected['api_key']

    parser.error(
        "Multiple API credential profiles found in .env. "
        "Use --profile-name to choose one."
    )
    return None, None


# Unified progress display supporting simple spinner, tqdm bar, and rich UIs.
class ProgressRenderer:
    """Centralized progress renderer supporting simple and bar UIs.

    Adapts output to the chosen *ui_mode* (``'simple'``, ``'bar'``, or
    ``'rich'``).  Falls back gracefully when optional dependencies
    (``tqdm`` / ``rich``) are not installed.

    Args:
        ui_mode: Display backend.
        total_rows: Total CSV rows to process.
        total_tags: Number of tag rows.
        total_scans: Number of scan rows.
        silent: Suppress all output when ``True``.
    """
    def __init__(self, ui_mode: str, total_rows: int, total_tags: int, total_scans: int, silent: bool = False):
        self.ui_mode = ui_mode
        self.total_rows = total_rows
        self.total_tags = total_tags
        self.total_scans = total_scans
        self.silent = silent
        self.spinner = itertools.cycle(['|', '/', '-', '\\'])
        self._bar = None
        self._using_bar = False
        self._using_rich = False
        self._rich_console = None
        self._rich_progress = None
        self._rich_task = None

        if self.silent:
            self.ui_mode = 'silent'
            return

        if ui_mode == 'rich':
            try:
                from rich.console import Console
                from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
                self._rich_console = Console()
                self._rich_progress = Progress(
                    SpinnerColumn(),
                    TextColumn("[bold cyan]{task.description}"),
                    BarColumn(),
                    TextColumn("{task.completed}/{task.total}"),
                    TimeElapsedColumn(),
                    TimeRemainingColumn(),
                    transient=True
                )
                self._using_rich = True
            except Exception:
                logger.warning("rich not available; falling back to simple UI mode")
                self.ui_mode = 'simple'
        elif ui_mode == 'bar':
            try:
                from tqdm import tqdm
                self._bar = tqdm(total=total_rows, unit='row', dynamic_ncols=True, leave=False)
                self._using_bar = True
            except Exception:
                logger.warning("tqdm not available; falling back to simple UI mode")
                self.ui_mode = 'simple'

    # Print initial row/tag/scan counts and activate the progress backend.
    def start(self) -> None:
        """Print initial CSV summary and start the progress backend."""
        if self.silent:
            return
        print(f"Loaded {self.total_rows} rows from CSV ({self.total_tags} tags, {self.total_scans} scans)")
        if self.total_tags == 0:
            print("Note: no tag rows found in CSV (type=tag)")
        if self.total_scans == 0:
            print("Note: no scan rows found in CSV (type=scan)")
        if self._using_rich and self._rich_progress is not None:
            self._rich_progress.start()
            self._rich_task = self._rich_progress.add_task("Processing CSV", total=self.total_rows)

    # Refresh the progress display with current counts and active item info.
    def update(self, processed_rows: int, processed_tags: int, processed_scans: int,
               item_type: str, item_name: str, tag_stats: tuple, scan_stats: tuple) -> None:
        """Refresh the live progress display with current processing stats."""
        if self.silent:
            return
        tag_created, tag_updated, tag_unchanged, tag_errors = tag_stats
        scan_created, scan_updated, scan_unchanged, scan_errors = scan_stats
        item_label = "Tag" if item_type == 'tag' else "Scan" if item_type == 'scan' else "Row"
        item_count = f"{processed_tags}/{self.total_tags}" if item_type == 'tag' else (
            f"{processed_scans}/{self.total_scans}" if item_type == 'scan' else f"{processed_rows}/{self.total_rows}"
        )
        status_text = (
            f"Row {processed_rows}/{self.total_rows} | "
            f"{item_label} {item_count} | "
            f"{item_label.lower()}: {item_name} | "
            f"Tags C/U/S/E={tag_created}/{tag_updated}/{tag_unchanged}/{tag_errors} | "
            f"Scans C/U/S/E={scan_created}/{scan_updated}/{scan_unchanged}/{scan_errors}"
        )

        if self._using_bar and self._bar is not None:
            self._bar.set_description(f"{item_label}: {item_name[:30]}")
            self._bar.set_postfix_str(
                f"T {tag_created}/{tag_updated}/{tag_unchanged}/{tag_errors} | "
                f"S {scan_created}/{scan_updated}/{scan_unchanged}/{scan_errors}"
            )
        elif self._using_rich and self._rich_progress is not None and self._rich_task is not None:
            self._rich_progress.update(
                self._rich_task,
                description=(
                    f"{item_label}: {item_name[:30]} | "
                    f"T {tag_created}/{tag_updated}/{tag_unchanged}/{tag_errors} | "
                    f"S {scan_created}/{scan_updated}/{scan_unchanged}/{scan_errors}"
                )
            )
        else:
            sys.stdout.write("\r" + " " * 180)
            sys.stdout.write(f"\r{next(self.spinner)} {status_text[:175]}")
            sys.stdout.flush()

    # Increment the progress counter by one row.
    def advance(self) -> None:
        """Advance the progress counter by one processed row."""
        if self.silent:
            return
        if self._using_bar and self._bar is not None:
            self._bar.update(1)
        elif self._using_rich and self._rich_progress is not None and self._rich_task is not None:
            self._rich_progress.advance(self._rich_task, 1)

    # Tear down the progress display (close tqdm bar, stop rich, clear line).
    def close(self) -> None:
        """Finalize and clean up the progress display."""
        if self.silent:
            return
        if self._using_bar and self._bar is not None:
            self._bar.close()
        elif self._using_rich and self._rich_progress is not None:
            self._rich_progress.stop()
        else:
            sys.stdout.write("\r" + " " * 180 + "\r\n")
            sys.stdout.flush()

# --- HELPER FUNCTIONS ---
# Append a "-v<N>" suffix when a duplicate name is detected.
def get_versioned_name(name: str, existing_names: set) -> str:
    """Add version number to name if it already exists.

    Increments the version suffix until a unique name is found.

    Args:
        name: Desired name.
        existing_names: Set of names already in use.

    Returns:
        *name* unchanged if unique, otherwise ``"<name>-v<N>"``.
    """
    if name not in existing_names:
        return name
    
    base_name = name
    version = 1
    while f"{base_name}-v{version}" in existing_names:
        version += 1
    
    return f"{base_name}-v{version}"

# Central API request helper with retry logic and sensitive-data redaction.
def make_api_request(method, endpoint, headers=None, json_data=None, params=None, api_version=None):
    """Generic API request function with error handling.

    Automatically retries on transient HTTP errors (429, 5xx) and
    network failures up to :data:`MAX_RETRIES` with exponential
    back-off.  Sensitive headers and payload fields are redacted before
    being written to the debug log.

    Args:
        method: HTTP method (``'GET'``, ``'POST'``, ``'PUT'``, etc.).
        endpoint: API path segment (e.g. ``'tag'`` or ``'scans/123'``).
        headers: Extra HTTP headers merged with the default API-key header.
        json_data: Request body serialised as JSON.
        params: URL query parameters.
        api_version: Explicit API version prefix (``'v2'`` or ``'v3'``).
            When ``None`` the version is inferred from the endpoint.

    Returns:
        Parsed JSON response as a ``dict`` / ``list``, or ``None`` on failure.
    """
    def redact_sensitive(data: Any) -> Any:
        """Redact sensitive keys before logging."""
        sensitive_keys = {
            'x-api-key', 'api_key', 'apikey', 'token', 'authorization',
            'passphrase', 'privacy_passphrase', 'password', 'secret'
        }
        if isinstance(data, dict):
            redacted = {}
            for key, value in data.items():
                if str(key).lower() in sensitive_keys:
                    redacted[key] = '***REDACTED***'
                else:
                    redacted[key] = redact_sensitive(value)
            return redacted
        if isinstance(data, list):
            return [redact_sensitive(item) for item in data]
        return data

    # Use provided api_version or infer from endpoint
    if api_version is None:
        api_version = 'v2' if endpoint.startswith('tag') else 'v3'
    url = f"https://urldefense.com/v3/__https://*7Bos.environ*'PHO_API_HOST'**A7D/api/*7Bapi_version*7D/*7Bendpoint*7D__;JVtdJSUlJSU!!KMayzP4JbQ!bXpV4E70WBzsDCvFmTUAdlgzTD6AAZOhdoGJ086VSsxMg-x9JQ1DNiu72vzn51dObXT6GGPlIgk_4Wg1yU3Z6H-mWgVrLT69lxO5yw$ "
    default_headers = {'X-API-Key': os.environ['PHO_API_KEY']}
    if headers:
        default_headers.update(headers)
    
    logger.debug(f"API request: {method} {url}")
    if json_data:
        logger.debug(f"API request payload: {json.dumps(redact_sensitive(json_data), indent=2)}")

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.request(
                method,
                url,
                headers=default_headers,
                json=json_data,
                params=params,
                verify=not ALLOW_INSECURE_TLS,
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            response_data = response.json()
            logger.debug(f"API response: {json.dumps(redact_sensitive(response_data), indent=2)}")
            return response_data
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response is not None else None
            should_retry = status_code in {429, 500, 502, 503, 504}
            if should_retry and attempt < MAX_RETRIES:
                backoff = attempt * 2
                logger.warning(
                    f"API request HTTP {status_code} (attempt {attempt}/{MAX_RETRIES}); retrying in {backoff}s..."
                )
                sleep(backoff)
                continue
            logger.error(f"API request failed with HTTP {status_code}: {str(e)}")
            return None
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            if attempt < MAX_RETRIES:
                backoff = attempt * 2
                logger.warning(
                    f"API request network error (attempt {attempt}/{MAX_RETRIES}): {str(e)}; retrying in {backoff}s..."
                )
                sleep(backoff)
                continue
            logger.error(f"API request failed after {MAX_RETRIES} attempts: {str(e)}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {str(e)}")
            return None


# API request helper that returns the raw response body as text.
def make_api_text_request(method, endpoint, headers=None, params=None, api_version=None) -> Optional[str]:
    """API request helper for text-based responses (e.g., JSONL/cloud exports).

    Behaves like :func:`make_api_request` but returns the raw response
    text instead of parsing JSON.  Retries on transient errors.

    Args:
        method: HTTP method.
        endpoint: API path segment.
        headers: Extra HTTP headers.
        params: URL query parameters.
        api_version: Explicit API version prefix (default ``'v3'``).

    Returns:
        Response body as a string, or ``None`` on failure.
    """
    if api_version is None:
        api_version = 'v3'
    url = f"https://urldefense.com/v3/__https://*7Bos.environ*'PHO_API_HOST'**A7D/api/*7Bapi_version*7D/*7Bendpoint*7D__;JVtdJSUlJSU!!KMayzP4JbQ!bXpV4E70WBzsDCvFmTUAdlgzTD6AAZOhdoGJ086VSsxMg-x9JQ1DNiu72vzn51dObXT6GGPlIgk_4Wg1yU3Z6H-mWgVrLT69lxO5yw$ "
    default_headers = {'X-API-Key': os.environ['PHO_API_KEY']}
    if headers:
        default_headers.update(headers)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.request(
                method,
                url,
                headers=default_headers,
                params=params,
                verify=not ALLOW_INSECURE_TLS,
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            return response.text
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response is not None else None
            should_retry = status_code in {429, 500, 502, 503, 504}
            if should_retry and attempt < MAX_RETRIES:
                sleep(attempt * 2)
                continue
            logger.error(f"Text API request failed with HTTP {status_code}: {str(e)}")
            return None
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            if attempt < MAX_RETRIES:
                sleep(attempt * 2)
                continue
            logger.error(f"Text API request failed after {MAX_RETRIES} attempts: {str(e)}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Text API request failed: {str(e)}")
            return None


# Strip unsafe characters from a string so it can be used as a filename part.
def sanitize_filename_component(value: str) -> str:
    """Sanitize text for safe filename usage.

    Replaces non-alphanumeric characters (except ``._-``) with underscores
    and strips leading/trailing punctuation.

    Args:
        value: Raw string (e.g. a scan name).

    Returns:
        Filesystem-safe string; falls back to ``'scan'`` if empty.
    """
    clean = re.sub(r'[^A-Za-z0-9._-]+', '_', (value or '').strip())
    return clean.strip('._-') or 'scan'

# --- TAG FUNCTIONS ---
# Fetch all tags currently registered in the Phosphorus platform.
def get_existing_tags():
    """Retrieve all existing tags.

    Returns:
        Dictionary mapping tag names to their full API representations.
        Empty dict when the request fails or no tags exist.
    """
    logger.info("Retrieving existing tags...")
    response = make_api_request('GET', 'tag', params={'limit': 1000})
    if response and response.get('success'):
        return {tag['name']: tag for tag in response.get('tags', [])}
    return {}

# Idempotent tag upsert: creates a new tag or updates an existing one.
def create_or_update_tag(tag_data, existing_tags, config: Config = None):
    """Create or update a tag.

    When *tag_data['name']* already exists in *existing_tags* the tag is
    updated via ``POST``; otherwise a new tag is created via ``PUT``.

    Args:
        tag_data: Dict with ``name``, ``description``, ``color``, ``query``.
        existing_tags: Current tags keyed by name (from :func:`get_existing_tags`).
        config: Optional runtime config; enables dry-run mode.

    Returns:
        API response dict on success, ``None`` on failure, or
        ``{'success': True, 'dry_run': True}`` in dry-run mode.
    """
    name = tag_data['name']
    
    if name in existing_tags:
        logger.info(f"Updating existing tag: {name}")
        if config and config.dry_run:
            logger.info(f"[DRY RUN] Would update tag: {name}")
            return {'success': True, 'dry_run': True}
        
        tag = existing_tags[name]
        tag_id = tag['id']
        # Prepare the payload with all required fields for update
        payload = {
            "tag": {
                "id": tag_id,
                "color": tag_data['color'],
                "name": name,
                "description": tag_data['description'],
                "query": tag_data['query'],
                "automatic": True,
                "count": tag.get('count', 0),
                "lost_devices_count": tag.get('lost_devices_count', 0)
            }
        }
        endpoint = f"tag/{tag_id}"
        method = 'POST'  # Use POST for update per HAR
    else:
        logger.info(f"Creating new tag: {name}")
        if config and config.dry_run:
            logger.info(f"[DRY RUN] Would create tag: {name}")
            return {'success': True, 'dry_run': True}
        
        # Prepare the payload for creation
        payload = {
            "tag": {
                "name": name,
                "description": tag_data['description'],
                "color": tag_data['color'],
                "query": tag_data['query'],
                "automatic": True
            }
        }
        endpoint = "tag"
        method = 'PUT'  # Use PUT for creation as per HAR
    
    response = make_api_request(
        method,
        endpoint,
        headers={'Content-Type': 'application/json'},
        json_data=payload
    )
    
    if response:
        logger.info(f"Successfully {'updated' if name in existing_tags else 'created'} tag: {name}")
    return response

# --- SCAN FUNCTIONS ---
# Load all scheduled scans including per-scan detail lookups.
def get_existing_scans(status_callback=None) -> Dict[str, Dict]:
    """Retrieve all existing scheduled scans with full details.

    Iterates through the combined actions/groups endpoint and fetches
    detailed scan data for each discovered scan.  Falls back to partial
    data if the detail request fails.

    Args:
        status_callback: Optional callable receiving progress messages
            (e.g. ``"Loading existing scans details: 5/20"``).

    Returns:
        Dictionary mapping scan names to their full API representations.
    """
    logger.info("Retrieving existing scheduled scans...")
    response = make_api_request(
        'GET',
        'actions/groups/combined',
        api_version='v3',
        params={
            'limit': 1000,
            'offset': 0,
            'sortBy': 'next_run',
            'sortDir': 'desc',
            'view': 'scheduled',
            'type': 'scan_devices'
        }
    )
    scans = {}
    if response and 'rows' in response:
        rows = response.get('rows', [])
        total_rows = len(rows)
        for idx, scan in enumerate(rows, start=1):
            scan_id = scan.get('id')
            if scan_id:
                if status_callback and (idx == 1 or idx % 10 == 0 or idx == total_rows):
                    status_callback(f"Loading existing scans details: {idx}/{total_rows}")
                full_scan = make_api_request('GET', f'scans/{scan_id}', api_version='v3')
                if full_scan:
                    scans[scan['name']] = full_scan
                else:
                    scans[scan['name']] = scan  # fallback to partial if detail fails
    else:
        logger.warning("Could not retrieve existing scans or parse response")
    return scans

# Create an immediate (non-scheduled) scan that runs once.
def create_run_now_scan(scan_data: Dict[str, Any], config: Config) -> Optional[Dict]:
    """Create a run-now scan (immediate execution, no scheduling).

    Generates a uniquely-named scan set to start one minute from now.
    SNMP configuration is propagated if present in *scan_data*.

    Args:
        scan_data: Processed scan configuration dict.
        config: Runtime config (checked for ``dry_run``).

    Returns:
        API response dict on success, ``None`` on failure, or
        dry-run stub.
    """
    
    # Generate a unique name for the run-now scan
    base_name = scan_data['name']
    run_now_name = f"{base_name} - Run Now"
    
    if config.dry_run:
        logger.info(f"[DRY RUN] Would create run-now scan: {run_now_name}")
        return {'success': True, 'dry_run': True}
    
    # Set immediate start time (current time + 1 minute)
    now = datetime.now()
    start_time = now + timedelta(minutes=1)
    
    # Create run-now scan payload based on HAR analysis
    # Key differences: simpler structure, no description field, proper SNMP handling
    run_now_payload = {
        'name': run_now_name,
        'cron': None,  # Key difference: no cron for run-now
        'start_date': start_time.strftime('%m/%d/%Y'),
        'start_time': start_time.strftime('%H:%M'),
        'timezone': scan_data.get('timezone', 'America/New_York'),
        'site_id': scan_data.get('site_id', ''),
        'provider_id': scan_data.get('provider_id', ''),
        'networks': scan_data.get('networks', ''),
        'excluded_networks': scan_data.get('excluded_networks', ''),
        'create_network_tag': False,
        'tag_name': '',
        'tag_description': '',
        'tag_color': '',
        'scan_options': {
            "file": "standard",
            "default": True,
            "display_name": "Standard xIoT Enterprise Discovery",
            "description": "This is the default Phosphorus xIoT Discovery Agenda that employs a tiered approach to progressively discover xIoT devices. This agenda stops sending discovery traffic to individual devices once classified and is intended for use with IP address ranges."
        }
    }
    
    # Add SNMP configuration - handle null values properly like in HAR
    if 'snmp' in scan_data and scan_data['snmp']:
        snmp_config = scan_data['snmp']
        # Convert empty strings to None as required by the API
        run_now_payload['snmp'] = {
            'username': snmp_config.get('username') if snmp_config.get('username') else None,
            'passphrase': snmp_config.get('passphrase') if snmp_config.get('passphrase') else None,
            'protocol': snmp_config.get('protocol') if snmp_config.get('protocol') else None,
            'context_name': snmp_config.get('context_name') if snmp_config.get('context_name') else None,
            'communities': snmp_config.get('communities') if snmp_config.get('communities') else None,
            'privacy_passphrase': snmp_config.get('privacy_passphrase') if snmp_config.get('privacy_passphrase') else None,
            'privacy_protocol': snmp_config.get('privacy_protocol') if snmp_config.get('privacy_protocol') else None
        }
    else:
        # Default SNMP structure with null values as shown in HAR
        run_now_payload['snmp'] = {
            'username': None,
            'passphrase': None,
            'protocol': None,
            'context_name': None,
            'communities': None,
            'privacy_passphrase': None,
            'privacy_protocol': None
        }
    
    # Create the run-now scan
    response = make_api_request(
        'POST',
        "scans",
        api_version='v3',
        headers={'Content-Type': 'application/json'},
        json_data=run_now_payload
    )
    
    if response:
        logger.info(f"Successfully created run-now scan: {run_now_name}")
        logger.debug(f"Run-now scan response: {json.dumps(response, indent=2)}")
        return response
    else:
        logger.warning(f"Failed to create run-now scan: {run_now_name}")
        return None

# Collect active and scheduled scan configurations for offline reporting.
def get_scan_details_for_export() -> Dict[str, list]:
    """Retrieve Active and Scheduled scan jobs with detailed information for export.

    Queries both the ``active`` and ``scheduled`` views of the combined
    actions endpoint and enriches each entry with full scan details.

    Returns:
        Dict with ``'active'`` and ``'scheduled'`` keys, each containing a
        list of extracted scan-info dicts.
    """
    logger.info("Retrieving scan details for export...")
    
    scan_details = {
        'active': [],
        'scheduled': []
    }
    
    # Get Active scans
    logger.info("Fetching active scans...")
    active_response = make_api_request(
        'GET',
        'actions/groups/combined',
        api_version='v3',
        params={
            'limit': 1000,
            'offset': 0,
            'sortBy': 'next_run',
            'sortDir': 'desc',
            'view': 'active',
            'type': 'scan_devices'
        }
    )
    
    if active_response and 'rows' in active_response:
        for scan in active_response.get('rows', []):
            scan_id = scan.get('id')
            if scan_id:
                # Get detailed scan information
                detailed_scan = make_api_request('GET', f'scans/{scan_id}', api_version='v3')
                if detailed_scan:
                    scan_info = extract_scan_info(detailed_scan, 'Active')
                    scan_details['active'].append(scan_info)
    
    # Get Scheduled scans
    logger.info("Fetching scheduled scans...")
    scheduled_response = make_api_request(
        'GET',
        'actions/groups/combined',
        api_version='v3',
        params={
            'limit': 1000,
            'offset': 0,
            'sortBy': 'next_run',
            'sortDir': 'desc',
            'view': 'scheduled',
            'type': 'scan_devices'
        }
    )
    
    if scheduled_response and 'rows' in scheduled_response:
        for scan in scheduled_response.get('rows', []):
            scan_id = scan.get('id')
            if scan_id:
                # Get detailed scan information
                detailed_scan = make_api_request('GET', f'scans/{scan_id}', api_version='v3')
                if detailed_scan:
                    scan_info = extract_scan_info(detailed_scan, 'Scheduled')
                    scan_details['scheduled'].append(scan_info)
    
    return scan_details

# Normalise raw scan API data into a flat dict suitable for text/CSV export.
def extract_scan_info(scan_data: Dict[str, Any], status: str) -> Dict[str, Any]:
    """Extract relevant information from scan data for export.

    Handles network lists, timestamp conversion, and nested field
    extraction so that callers receive a uniform flat dictionary.

    Args:
        scan_data: Full scan object from the API.
        status: Human-readable status label (e.g. ``'Active'``).

    Returns:
        Flat dict with keys like ``name``, ``status``, ``included_networks``,
        ``schedule``, ``next_run``, etc.
    """
    options = scan_data.get('options', {})
    
    # Extract networks
    networks = options.get('networks', '')
    if isinstance(networks, list):
        networks = ', '.join([str(n).strip() for n in networks if n])
    elif networks:
        networks = str(networks).replace('\n', ', ')
    
    # Extract excluded networks
    excluded_networks = options.get('excluded_networks', '')
    if isinstance(excluded_networks, list):
        excluded_networks = ', '.join([str(n).strip() for n in excluded_networks if n])
    elif excluded_networks:
        excluded_networks = str(excluded_networks).replace('\n', ', ')
    
    # Extract schedule information
    schedule = scan_data.get('cron', 'N/A')
    next_run = scan_data.get('next_run', 'N/A')
    if next_run and next_run != 'N/A':
        # Convert timestamp to readable format if it's a timestamp
        try:
            if isinstance(next_run, (int, float)):
                next_run = datetime.fromtimestamp(next_run).strftime('%Y-%m-%d %H:%M:%S')
            elif isinstance(next_run, str) and next_run.isdigit():
                next_run = datetime.fromtimestamp(int(next_run)).strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError, OSError):
            pass  # Keep original value if conversion fails
    
    return {
        'name': scan_data.get('name', 'Unknown'),
        'status': status,
        'included_networks': networks or 'None',
        'excluded_networks': excluded_networks or 'None',
        'schedule': schedule or 'N/A',
        'next_run': next_run or 'N/A',
        'timezone': scan_data.get('timezone', 'N/A'),
        'site_name': (scan_data.get('site', {}) or {}).get('name', 'N/A'),
        'created': scan_data.get('created', 'N/A'),
        'updated': scan_data.get('updated', 'N/A')
    }

# Write active + scheduled scan configurations to a human-readable text report.
def dump_scan_details_to_file(filename: str, api_host: str, api_key: str) -> None:
    """Fetch scan details and dump to text file.

    Produces a structured plain-text report containing all active and
    scheduled scans, including a summary section.

    Args:
        filename: Output text file path.
        api_host: Phosphorus API hostname.
        api_key: API authentication key.
    """
    print(f"Fetching scan details and saving to {filename}...")
    
    # Set up environment for API calls
    os.environ['PHO_API_HOST'] = api_host
    os.environ['PHO_API_KEY'] = api_key
    
    try:
        # Fetch scan details
        scan_details = get_scan_details_for_export()
        
        # Generate timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Write to file
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("PHOSPHORUS SCAN JOB DETAILS\n")
            f.write("="*80 + "\n")
            f.write(f"Generated: {timestamp}\n")
            f.write(f"API Host: {api_host}\n")
            f.write("="*80 + "\n\n")
            
            # Write Active Scans
            f.write("ACTIVE SCANS\n")
            f.write("-"*40 + "\n")
            if scan_details['active']:
                for i, scan in enumerate(scan_details['active'], 1):
                    f.write(f"\n{i}. {scan['name']}\n")
                    f.write(f"   Status: {scan['status']}\n")
                    f.write(f"   Included Networks: {scan['included_networks']}\n")
                    f.write(f"   Excluded Networks: {scan['excluded_networks']}\n")
                    f.write(f"   Schedule: {scan['schedule']}\n")
                    f.write(f"   Next Run: {scan['next_run']}\n")
                    f.write(f"   Timezone: {scan['timezone']}\n")
                    f.write(f"   Site: {scan['site_name']}\n")
                    f.write(f"   Created: {scan['created']}\n")
                    f.write(f"   Updated: {scan['updated']}\n")
            else:
                f.write("\nNo active scans found.\n")
            
            # Write Scheduled Scans
            f.write(f"\n{'='*80}\n")
            f.write("SCHEDULED SCANS\n")
            f.write("-"*40 + "\n")
            if scan_details['scheduled']:
                for i, scan in enumerate(scan_details['scheduled'], 1):
                    f.write(f"\n{i}. {scan['name']}\n")
                    f.write(f"   Status: {scan['status']}\n")
                    f.write(f"   Included Networks: {scan['included_networks']}\n")
                    f.write(f"   Excluded Networks: {scan['excluded_networks']}\n")
                    f.write(f"   Schedule: {scan['schedule']}\n")
                    f.write(f"   Next Run: {scan['next_run']}\n")
                    f.write(f"   Timezone: {scan['timezone']}\n")
                    f.write(f"   Site: {scan['site_name']}\n")
                    f.write(f"   Created: {scan['created']}\n")
                    f.write(f"   Updated: {scan['updated']}\n")
            else:
                f.write("\nNo scheduled scans found.\n")
            
            # Write summary
            f.write(f"\n{'='*80}\n")
            f.write("SUMMARY\n")
            f.write("-"*40 + "\n")
            f.write(f"Active Scans: {len(scan_details['active'])}\n")
            f.write(f"Scheduled Scans: {len(scan_details['scheduled'])}\n")
            f.write(f"Total Scans: {len(scan_details['active']) + len(scan_details['scheduled'])}\n")
            f.write(f"\n{'='*80}\n")
        
        print(f"✓ Scan details successfully saved to: {filename}")
        print(f"  - Active scans: {len(scan_details['active'])}")
        print(f"  - Scheduled scans: {len(scan_details['scheduled'])}")
        print(f"  - Total scans: {len(scan_details['active']) + len(scan_details['scheduled'])}")
        
    except Exception as e:
        print(f"✗ Error fetching or saving scan details: {str(e)}")
        logger.error(f"Error in dump_scan_details_to_file: {str(e)}")
        sys.exit(1)

# Write active + scheduled scan configurations to a machine-readable CSV.
def dump_scan_details_to_csv(filename: str, api_host: str, api_key: str) -> None:
    """Fetch scan details and dump to CSV file.

    Each row represents one active or scheduled scan with columns for
    name, status, networks, schedule, etc.

    Args:
        filename: Output CSV file path.
        api_host: Phosphorus API hostname.
        api_key: API authentication key.
    """
    print(f"Fetching scan details and saving to CSV: {filename}...")
    
    # Set up environment for API calls
    os.environ['PHO_API_HOST'] = api_host
    os.environ['PHO_API_KEY'] = api_key
    
    try:
        # Fetch scan details
        scan_details = get_scan_details_for_export()
        
        # Combine all scans into one list
        all_scans = scan_details['active'] + scan_details['scheduled']
        
        if not all_scans:
            print("No scans found to export.")
            return
        
        # Define CSV headers
        headers = [
            'Name',
            'Status',
            'Included Networks',
            'Excluded Networks', 
            'Schedule',
            'Next Run',
            'Timezone',
            'Site',
            'Created',
            'Updated'
        ]
        
        # Write to CSV file
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header row
            writer.writerow(headers)
            
            # Write scan data rows
            for scan in all_scans:
                row = [
                    scan['name'],
                    scan['status'],
                    scan['included_networks'],
                    scan['excluded_networks'],
                    scan['schedule'],
                    scan['next_run'],
                    scan['timezone'],
                    scan['site_name'],
                    scan['created'],
                    scan['updated']
                ]
                writer.writerow(row)
        
        print(f"✓ Scan details successfully saved to CSV: {filename}")
        print(f"  - Active scans: {len(scan_details['active'])}")
        print(f"  - Scheduled scans: {len(scan_details['scheduled'])}")
        print(f"  - Total scans: {len(all_scans)}")
        print(f"  - Columns: {', '.join(headers)}")
        
    except Exception as e:
        print(f"✗ Error fetching or saving scan details to CSV: {str(e)}")
        logger.error(f"Error in dump_scan_details_to_csv: {str(e)}")
        sys.exit(1)

# Paginated retrieval of historical scan runs with optional filters.
def get_completed_scan_history(name_filter: Optional[str] = None, 
                              start_date: Optional[str] = None,
                              end_date: Optional[str] = None,
                              scan_status: str = 'completed',
                              max_results: int = 500) -> list:
    """Retrieve scan history with optional filtering and pagination.

    Pages through the combined actions endpoint using ``limit``/``offset``
    and prints progress for large result sets.

    Args:
        name_filter: Partial name match (passed as ``name`` query param).
        start_date: ISO start date (``YYYY-MM-DD``).
        end_date: ISO end date (``YYYY-MM-DD``).
        scan_status: One of ``'completed'``, ``'canceled'``, ``'failed'``, ``'all'``.
        max_results: Hard cap on total scans returned.

    Returns:
        List of raw scan dicts (up to *max_results*).
    """
    # Normalize status to lowercase for case-insensitive matching
    status_lower = scan_status.lower().strip()
    
    # Map status to API view parameter (API expects completed_<status> format)
    if status_lower == 'all':
        view_param = 'all'
        logger.info("Retrieving all scan history...")
    elif status_lower == 'completed':
        view_param = 'completed_completed'
        logger.info("Retrieving completed scan history...")
    elif status_lower == 'canceled':
        view_param = 'completed_canceled'
        logger.info("Retrieving canceled scan history...")
    elif status_lower == 'failed':
        view_param = 'completed_failed'
        logger.info("Retrieving failed scan history...")
    else:
        logger.warning(f"Unknown scan status '{scan_status}', defaulting to 'completed'")
        view_param = 'completed_completed'
        logger.info("Retrieving completed scan history...")
    
    all_scans = []
    offset = 0
    limit = 50
    total_available = None
    
    while len(all_scans) < max_results:
        params = {
            'type': 'scan_devices',
            'view': view_param,
            'sortBy': 'completed',
            'sortDir': 'desc',
            'limit': limit,
            'offset': offset
        }
        
        if name_filter:
            params['name'] = name_filter
            logger.info(f"Applying name filter: {name_filter}")
        if start_date:
            params['startDate'] = start_date
        if end_date:
            params['endDate'] = end_date
        
        response = make_api_request(
            'GET',
            'actions/groups/combined',
            api_version='v3',
            params=params
        )
        
        if not response or 'rows' not in response:
            logger.warning("No response or rows not found in scan history query")
            break
            
        scans = response.get('rows', [])
        total = response.get('meta', {}).get('total', 0)
        
        # Capture total on first response
        if total_available is None:
            total_available = total
            if total_available > 0:
                print(f"  Found {total_available} total scans to retrieve...")
        
        if not scans:
            break
            
        all_scans.extend(scans)
        logger.debug(f"Fetched {len(scans)} scans, total so far: {len(all_scans)}")
        
        # Progress feedback for large datasets with total
        if len(all_scans) % 500 == 0 and total_available:
            percentage = (len(all_scans) / total_available) * 100
            print(f"  Progress: {len(all_scans)}/{total_available} scans retrieved ({percentage:.1f}%)...")
        
        if len(scans) < limit or len(all_scans) >= total:
            break
            
        offset += limit
    
    final_count = len(all_scans[:max_results])
    logger.info(f"Retrieved {final_count} scans")
    
    # Show final summary
    if total_available and final_count < total_available:
        if final_count >= max_results:
            print(f"  Retrieved {final_count} scans (limited by --max-results={max_results})")
            print(f"  Note: {total_available - final_count} additional scans available")
        else:
            print(f"  Retrieved {final_count}/{total_available} scans")
    
    return all_scans[:max_results]

# Enrich a completed-scan row with detailed stats and network info.
def extract_scan_history_info(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract relevant information from completed scan data for export.

    Fetches full scan details via the API and merges device statistics,
    site info, network lists, and human-friendly duration/status labels
    into a single flat dict.

    Args:
        scan_data: Partial scan object from the history listing.

    Returns:
        Flat dict with keys like ``id``, ``name``, ``status``, ``started``,
        ``duration``, ``total_devices``, ``networks``, etc.
    """
    
    def format_timestamp(timestamp_str: str) -> str:
        """Convert ISO timestamp to readable format"""
        if not timestamp_str or timestamp_str == 'Unknown':
            return 'Unknown'
        
        try:
            # Handle different timestamp formats
            if timestamp_str.endswith('Z'):
                dt_utc = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            elif '+' in timestamp_str or timestamp_str.count('T') == 1:
                dt_utc = datetime.fromisoformat(timestamp_str)
                if dt_utc.tzinfo is None:
                    dt_utc = dt_utc.replace(tzinfo=timezone.utc)
            else:
                dt_utc = datetime.fromisoformat(timestamp_str).replace(tzinfo=timezone.utc)
            
            # Convert to local time and format
            dt_local = dt_utc.astimezone()
            return dt_local.strftime('%Y-%m-%d %H:%M:%S')
            
        except (ValueError, TypeError):
            return timestamp_str
    
    def format_duration(duration_data: Any) -> str:
        """Format duration data to readable format"""
        if not duration_data:
            return 'Unknown'
        
        # Handle duration as object with minutes/seconds (drop milliseconds)
        if isinstance(duration_data, dict):
            minutes = int(duration_data.get('minutes', 0))
            seconds = int(duration_data.get('seconds', 0))
            
            if minutes > 0:
                return f"{minutes}m {seconds}s"
            else:
                return f"{seconds}s"
        
        # Handle duration as string with time format (e.g., "1m53.694599368s")
        if isinstance(duration_data, str) and ('m' in duration_data or 's' in duration_data):
            # Parse formats like "1m53.694599368s" or "53.694599368s"
            try:
                match = re.match(r'(?:(\d+)m)?(\d+(?:\.\d+)?)s', duration_data)
                if match:
                    minutes = int(match.group(1)) if match.group(1) else 0
                    seconds = int(float(match.group(2)))
                    if minutes > 0:
                        return f"{minutes}m {seconds}s"
                    else:
                        return f"{seconds}s"
            except (ValueError, AttributeError):
                pass
        
        # Handle duration as numeric (seconds or milliseconds)
        try:
            num_value = float(duration_data)
            
            # If the value is very large, assume it's milliseconds
            if num_value > 3600000:  # More than 1 hour in milliseconds
                seconds = int(num_value / 1000)
            else:
                seconds = int(num_value)
            
            hours, remainder = divmod(seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            
            if hours > 0:
                return f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                return f"{minutes}m {seconds}s"
            else:
                return f"{seconds}s"
        except (ValueError, TypeError):
            # If we can't parse it but it's not empty, log the issue for debugging
            logger.debug(f"Could not parse duration data: {duration_data} (type: {type(duration_data)})")
            return 'Unknown'
    
    # Get scan ID for detailed fetch
    scan_id = scan_data.get('id')
    if not scan_id:
        # Fallback to basic scan info if no ID
        return {
            'id': 'Unknown',
            'name': scan_data.get('name', 'Unknown'),
            'status': 'Completed',
            'started': format_timestamp(scan_data.get('started', '')),
            'completed': format_timestamp(scan_data.get('completed', '')),
            'duration': format_duration(scan_data.get('duration')),
            'total_devices': 'Unknown',
            'classified_devices': 'Unknown',
            'excluded_devices': 'Unknown',
            'unclassified_devices': 'Unknown',
            'site_name': 'Unknown',
            'networks': 'Unknown',
            'excluded_networks': 'None'
        }
    
    # Fetch detailed scan information
    detailed_scan = make_api_request('GET', f'scans/{scan_id}', api_version='v3')
    if not detailed_scan:
        logger.warning(f"Could not fetch detailed scan info for {scan_id}, using basic scan data")
        detailed_scan = scan_data  # Use basic data as fallback
    else:
        logger.debug(f"Successfully fetched detailed scan info for {scan_id}")
        # Merge basic scan data with detailed data to ensure we have all fields
        for key, value in scan_data.items():
            if key not in detailed_scan and value is not None:
                detailed_scan[key] = value
    
    # Extract device statistics from data.stats or fallback locations
    total_devices = 'Unknown'
    classified_devices = 'Unknown'
    excluded_devices = 'Unknown'
    unclassified_devices = 'Unknown'
    
    if 'data' in detailed_scan and detailed_scan['data']:
        data_section = detailed_scan['data']
        if 'stats' in data_section:
            stats = data_section['stats']
            total_devices = stats.get('total_enrolled', 0) + stats.get('total_excluded', 0) + stats.get('total_unknown', 0)
            classified_devices = stats.get('total_classified', stats.get('total_enrolled', 'Unknown'))
            excluded_devices = stats.get('total_excluded', 'Unknown')
            unclassified_devices = stats.get('total_unclassified', stats.get('total_unknown', 'Unknown'))
        
        # Try alternative locations for device counts
        if total_devices == 'Unknown':
            total_devices = data_section.get('totalAssets', 'Unknown')
            classified_devices = data_section.get('enrolledAssets', 'Unknown')
            excluded_devices = data_section.get('excludedAssets', 'Unknown')
            unclassified_devices = data_section.get('unknownAssets', 'Unknown')
    
    # Extract site information
    site_name = 'Unknown'
    if 'site' in detailed_scan and detailed_scan['site']:
        site_name = detailed_scan['site'].get('name', 'Unknown')
    
    # Extract network information from multiple possible locations
    networks = 'Unknown'
    excluded_networks = 'None'
    
    # Try multiple locations for network data
    network_sources = [
        detailed_scan.get('options', {}).get('networks'),
        detailed_scan.get('networks'),
        detailed_scan.get('data', {}).get('networks')
    ]
    
    excluded_network_sources = [
        detailed_scan.get('options', {}).get('excluded_networks'),
        detailed_scan.get('excluded_networks'),
        detailed_scan.get('data', {}).get('excluded_networks')
    ]
    
    # Process networks
    for network_data in network_sources:
        if network_data:
            if isinstance(network_data, list):
                networks = ', '.join([str(n).strip() for n in network_data if n])
                break
            elif isinstance(network_data, str) and network_data.strip():
                networks = str(network_data).replace('\n', ', ')
                break
    
    # Process excluded networks  
    for excluded_network_data in excluded_network_sources:
        if excluded_network_data:
            if isinstance(excluded_network_data, list):
                excluded_networks = ', '.join([str(n).strip() for n in excluded_network_data if n])
                break
            elif isinstance(excluded_network_data, str) and excluded_network_data.strip():
                excluded_networks = str(excluded_network_data).replace('\n', ', ')
                break
    
    # Debug logging for network extraction
    logger.debug(f"Scan {scan_id} network extraction: networks={networks}, excluded={excluded_networks}")
    if networks == 'Unknown':
        logger.debug(f"Scan {scan_id} network sources: options.networks={detailed_scan.get('options', {}).get('networks')}, "
                    f"networks={detailed_scan.get('networks')}, data.networks={detailed_scan.get('data', {}).get('networks')}")
    
    # Extract actual scan status
    actual_status = 'Unknown'
    if detailed_scan.get('is_complete'):
        actual_status = 'Completed'
    elif detailed_scan.get('is_canceled'):
        actual_status = 'Canceled'
    elif detailed_scan.get('is_failed'):
        actual_status = 'Failed'
    elif detailed_scan.get('is_running'):
        actual_status = 'Running'
    elif detailed_scan.get('is_paused'):
        actual_status = 'Paused'
    
    # Debug logging to understand status flags and duration data
    logger.debug(f"Scan {scan_id} status flags: complete={detailed_scan.get('is_complete')}, "
                f"canceled={detailed_scan.get('is_canceled')}, failed={detailed_scan.get('is_failed')}, "
                f"running={detailed_scan.get('is_running')}, paused={detailed_scan.get('is_paused')}")
    logger.debug(f"Scan {scan_id} duration sources: duration={detailed_scan.get('duration')}, "
                f"total_discovery_time={detailed_scan.get('data', {}).get('summary', {}).get('total_discovery_time')}, "
                f"discoveryTimeMs={detailed_scan.get('data', {}).get('discoveryTimeMs')}, "
                f"started={detailed_scan.get('started')}, completed={detailed_scan.get('completed')}")
    
    # Build final scan info
    scan_info = {
        'id': detailed_scan.get('id', scan_id),
        'name': detailed_scan.get('name', 'Unknown'),
        'status': actual_status,
        'started': format_timestamp(detailed_scan.get('started', '')),
        'completed': format_timestamp(detailed_scan.get('completed', '')),
        'duration': format_duration(
            # Try multiple duration sources in order of preference
            detailed_scan.get('duration') or
            detailed_scan.get('data', {}).get('summary', {}).get('total_discovery_time') or
            detailed_scan.get('data', {}).get('discoveryTimeMs') or
            calculate_duration_from_timestamps(detailed_scan.get('started'), detailed_scan.get('completed'))
        ),
        'total_devices': total_devices,
        'classified_devices': classified_devices,
        'excluded_devices': excluded_devices,
        'unclassified_devices': unclassified_devices,
        'site_name': site_name,
        'networks': networks,
        'excluded_networks': excluded_networks
    }
    
    return scan_info

# Convert user-friendly MM-DD-YYYY dates to the ISO format expected by the API.
def convert_date_format(date_str: str) -> str:
    """Convert ``MM-DD-YYYY`` to ``YYYY-MM-DD`` format.

    Also accepts dates already in ``YYYY-MM-DD``.

    Args:
        date_str: Date string in either format.

    Returns:
        ISO-formatted date string, or empty string if parsing fails.
    """
    if not date_str:
        return ""
    
    try:
        # Try to parse MM-DD-YYYY
        date_obj = datetime.strptime(date_str, "%m-%d-%Y")
        return date_obj.strftime("%Y-%m-%d")
    except ValueError:
        try:
            # Try to parse YYYY-MM-DD (already correct format)
            datetime.strptime(date_str, "%Y-%m-%d")
            return date_str
        except ValueError:
            print(f"Warning: Invalid date format '{date_str}'. Use MM-DD-YYYY or YYYY-MM-DD")
            return ""

# Helper to compute a start/end date tuple relative to today.
def calculate_days_ago_range(days_ago: int) -> tuple:
    """Calculate date range from X days ago to today.

    Args:
        days_ago: Number of days to look back (must be non-negative).

    Returns:
        Tuple ``(start_date, end_date)`` as ``YYYY-MM-DD`` strings,
        or ``("", "")`` when *days_ago* is negative.
    """
    if days_ago < 0:
        print(f"Warning: days_ago must be positive, got {days_ago}")
        return "", ""
    
    today = datetime.now()
    start_date = today - timedelta(days=days_ago)
    
    start_str = start_date.strftime("%Y-%m-%d")
    end_str = today.strftime("%Y-%m-%d")
    
    return start_str, end_str

# Fallback duration calculator when the API doesn't provide an explicit duration.
def calculate_duration_from_timestamps(started: str, completed: str) -> Optional[int]:
    """Calculate duration in seconds from start and end timestamps.

    Used as a fallback when no explicit duration field is available.

    Args:
        started: ISO-format start timestamp.
        completed: ISO-format end timestamp.

    Returns:
        Positive duration in seconds, or ``None`` if parsing fails or
        one of the timestamps is missing.
    """
    if not started or not completed:
        return None
    
    try:
        # Parse start timestamp
        if started.endswith('Z'):
            start_dt = datetime.fromisoformat(started.replace('Z', '+00:00'))
        else:
            start_dt = datetime.fromisoformat(started)
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
        
        # Parse end timestamp
        if completed.endswith('Z'):
            end_dt = datetime.fromisoformat(completed.replace('Z', '+00:00'))
        else:
            end_dt = datetime.fromisoformat(completed)
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)
        
        # Calculate difference in seconds
        duration_seconds = int((end_dt - start_dt).total_seconds())
        return duration_seconds if duration_seconds > 0 else None
        
    except (ValueError, TypeError) as e:
        logger.debug(f"Could not calculate duration from timestamps: {e}")
        return None

# Write scan history to a structured plain-text report.
def dump_scan_history_to_file(filename: str, api_host: str, api_key: str, 
                             name_filter: Optional[str] = None,
                             start_date: Optional[str] = None,
                             end_date: Optional[str] = None,
                             scan_status: str = 'completed',
                             max_results: int = 500) -> None:
    """Fetch completed scan history and dump to text file.

    Each scan entry includes ID, status, timestamps, duration, device
    statistics, site, and network information.

    Args:
        filename: Output text file path.
        api_host: Phosphorus API hostname.
        api_key: API authentication key.
        name_filter: Optional partial-name filter.
        start_date: Optional ISO start-date boundary.
        end_date: Optional ISO end-date boundary.
        scan_status: Status category to retrieve.
        max_results: Maximum scans to include.
    """
    print(f"Fetching scan history and saving to {filename}...")
    if name_filter:
        print(f"Applying name filter: {name_filter}")
    if start_date:
        print(f"Start date filter: {start_date}")
    if end_date:
        print(f"End date filter: {end_date}")
    print(f"Scan status filter: {scan_status.capitalize()}")
    
    # Set up environment for API calls
    os.environ['PHO_API_HOST'] = api_host
    os.environ['PHO_API_KEY'] = api_key
    
    try:
        # Fetch scan history
        scan_history = get_completed_scan_history(name_filter=name_filter, start_date=start_date, end_date=end_date, scan_status=scan_status, max_results=max_results)
        
        if not scan_history:
            print("No completed scans found.")
            return
        
        # Generate timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Write to file
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("PHOSPHORUS COMPLETED SCAN HISTORY\n")
            f.write("="*80 + "\n")
            f.write(f"Generated: {timestamp}\n")
            f.write(f"API Host: {api_host}\n")
            if name_filter:
                f.write(f"Name Filter: {name_filter}\n")
            f.write("="*80 + "\n\n")
            
            # Process and write scan history
            for i, scan in enumerate(scan_history, 1):
                scan_info = extract_scan_history_info(scan)
                
                f.write(f"{i}. {scan_info['name']}\n")
                f.write(f"   ID: {scan_info['id']}\n")
                f.write(f"   Status: {scan_info['status']}\n")
                f.write(f"   Started: {scan_info['started']}\n")
                f.write(f"   Completed: {scan_info['completed']}\n")
                f.write(f"   Duration: {scan_info['duration']}\n")
                f.write(f"   Site: {scan_info['site_name']}\n")
                f.write(f"   Networks: {scan_info['networks']}\n")
                f.write(f"   Excluded Networks: {scan_info['excluded_networks']}\n")
                f.write(f"   Total Devices: {scan_info['total_devices']}\n")
                f.write(f"   Classified: {scan_info['classified_devices']}\n")
                f.write(f"   Excluded: {scan_info['excluded_devices']}\n")
                f.write(f"   Unclassified: {scan_info['unclassified_devices']}\n")
                f.write("\n")
            
            # Write summary
            f.write(f"{'='*80}\n")
            f.write("SUMMARY\n")
            f.write("-"*40 + "\n")
            f.write(f"Total Completed Scans: {len(scan_history)}\n")
            if name_filter:
                f.write(f"Name Filter Applied: {name_filter}\n")
            f.write(f"\n{'='*80}\n")
        
        print(f"✓ Scan history successfully saved to: {filename}")
        print(f"  - Total completed scans: {len(scan_history)}")
        if name_filter:
            print(f"  - Name filter applied: {name_filter}")
        
    except Exception as e:
        print(f"✗ Error fetching or saving scan history: {str(e)}")
        logger.error(f"Error in dump_scan_history_to_file: {str(e)}")
        sys.exit(1)

# Write scan history to a CSV file for downstream analysis.
def dump_scan_history_to_csv(filename: str, api_host: str, api_key: str, 
                            name_filter: Optional[str] = None,
                            start_date: Optional[str] = None,
                            end_date: Optional[str] = None,
                            scan_status: str = 'completed',
                            max_results: int = 500) -> None:
    """Fetch scan history and dump to CSV file.

    Produces a CSV with columns for ID, name, status, timestamps,
    duration, device counts, site, and networks.

    Args:
        filename: Output CSV file path.
        api_host: Phosphorus API hostname.
        api_key: API authentication key.
        name_filter: Optional partial-name filter.
        start_date: Optional ISO start-date boundary.
        end_date: Optional ISO end-date boundary.
        scan_status: Status category to retrieve.
        max_results: Maximum scans to include.
    """
    print(f"Fetching scan history and saving to CSV: {filename}...")
    if name_filter:
        print(f"Applying name filter: {name_filter}")
    if start_date:
        print(f"Start date filter: {start_date}")
    if end_date:
        print(f"End date filter: {end_date}")
    print(f"Scan status filter: {scan_status.capitalize()}")
    
    # Set up environment for API calls
    os.environ['PHO_API_HOST'] = api_host
    os.environ['PHO_API_KEY'] = api_key
    
    try:
        # Fetch scan history
        scan_history = get_completed_scan_history(name_filter=name_filter, start_date=start_date, end_date=end_date, scan_status=scan_status, max_results=max_results)
        
        if not scan_history:
            print("No completed scans found to export.")
            return
        
        # Define CSV headers
        headers = [
            'ID',
            'Name',
            'Status',
            'Started',
            'Completed',
            'Duration',
            'Site',
            'Networks',
            'Excluded Networks',
            'Total Devices',
            'Classified Devices',
            'Excluded Devices',
            'Unclassified Devices'
        ]
        
        # Write to CSV file
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header row
            writer.writerow(headers)
            
            # Write scan data rows
            for scan in scan_history:
                scan_info = extract_scan_history_info(scan)
                row = [
                    scan_info['id'],
                    scan_info['name'],
                    scan_info['status'],
                    scan_info['started'],
                    scan_info['completed'],
                    scan_info['duration'],
                    scan_info['site_name'],
                    scan_info['networks'],
                    scan_info['excluded_networks'],
                    scan_info['total_devices'],
                    scan_info['classified_devices'],
                    scan_info['excluded_devices'],
                    scan_info['unclassified_devices']
                ]
                writer.writerow(row)
        
        print(f"✓ Scan history successfully saved to CSV: {filename}")
        print(f"  - Total completed scans: {len(scan_history)}")
        if name_filter:
            print(f"  - Name filter applied: {name_filter}")
        print(f"  - Columns: {', '.join(headers)}")
        
    except Exception as e:
        print(f"✗ Error fetching or saving scan history to CSV: {str(e)}")
        logger.error(f"Error in dump_scan_history_to_csv: {str(e)}")
        sys.exit(1)


# Convert JSONL device-export lines into rows suitable for CSV output.
def parse_jsonl_device_records(jsonl_data: str, scan_id: str, scan_name: str, category: str) -> list:
    """Parse exported JSONL records to flat CSV-friendly rows.

    Skips metadata header lines and invalid JSON.  Each valid device
    record is mapped to a dict with ``scan_id``, ``ip_address``,
    ``manufacturer``, ``model``, etc.

    Args:
        jsonl_data: Raw JSONL text (one JSON object per line).
        scan_id: Owning scan identifier.
        scan_name: Human-readable scan name.
        category: Device category label (e.g. ``'profiled'``).

    Returns:
        List of flat dicts ready for :class:`csv.DictWriter`.
    """
    rows = []
    if not jsonl_data or not jsonl_data.strip():
        return rows

    for line_num, line in enumerate(jsonl_data.splitlines(), start=1):
        content = line.strip()
        if not content:
            continue
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            logger.debug(f"Skipping invalid JSONL line {line_num} for scan {scan_id}")
            continue

        # Skip scan metadata line if present.
        if line_num == 1 and isinstance(payload, dict) and 'addr' not in payload and 'options' in payload:
            continue

        rows.append({
            'scan_id': scan_id,
            'scan_name': scan_name,
            'category': category,
            'created': payload.get('created', ''),
            'ip_address': payload.get('addr', ''),
            'manufacturer': payload.get('manufacturer', ''),
            'model': payload.get('model', ''),
            'type': payload.get('type', ''),
            'discovery_state': payload.get('discovery_state', ''),
            'reason': payload.get('reason', '')
        })
    return rows


# Export individual device records from scan results in JSONL, CSV, or cloud mode.
def export_raw_scan_records(api_host: str, api_key: str,
                           output_mode: str = 'jsonl',
                           categories: Optional[list] = None,
                           output_filename: Optional[str] = None,
                           name_filter: Optional[str] = None,
                           start_date: Optional[str] = None,
                           end_date: Optional[str] = None,
                           max_results: int = 100,
                           scan_status: str = 'completed') -> None:
    """Export raw scan records by category in JSONL/CSV or send directly to Phosphorus.

    For each matching scan, exports device-level records either locally
    (one file per scan) or pushes them to the Phosphorus cloud.

    Args:
        api_host: Phosphorus API hostname.
        api_key: API authentication key.
        output_mode: ``'jsonl'``, ``'csv'``, or ``'send'``.
        categories: List of device categories to export
            (``'profiled'``, ``'excluded'``, ``'unclassified'``, ``'unknown'``).
            ``None`` means all records.
        output_filename: Base filename / prefix for local outputs.
        name_filter: Optional partial-name filter for scans.
        start_date: Optional ISO start-date boundary.
        end_date: Optional ISO end-date boundary.
        max_results: Maximum scans to process.
        scan_status: Status category of scans to export from.
    """
    def build_output_filename(base_name: str, scan_name: str, scan_id: str, category: str) -> str:
        """Build a unique output filename incorporating scan name, id, and category."""
        path = Path(base_name)
        stem = path.stem or "scan_records"
        suffix = path.suffix or ('.jsonl' if output_mode == 'jsonl' else '.csv')
        safe_scan = sanitize_filename_component(scan_name)
        short_id = sanitize_filename_component(scan_id)[:8]
        return str(path.with_name(f"{stem}-{safe_scan}-{short_id}-{category}{suffix}"))

    valid_categories = {'profiled', 'excluded', 'unclassified', 'unknown'}
    all_records_mode = categories is None
    if not all_records_mode:
        categories = [c for c in (categories or []) if c in valid_categories]
        if not categories:
            print("No valid categories selected.")
            return

    os.environ['PHO_API_HOST'] = api_host
    os.environ['PHO_API_KEY'] = api_key

    print(f"Fetching scan list for raw export (status={scan_status}, max={max_results})...")
    scans = get_completed_scan_history(
        name_filter=name_filter,
        start_date=start_date,
        end_date=end_date,
        scan_status=scan_status,
        max_results=max_results
    )
    if not scans:
        print("No scans found matching the selected filters.")
        return

    category_label = "all records" if all_records_mode else ", ".join(categories)
    print(f"Found {len(scans)} scans. Categories: {category_label}")
    all_categories_selected = (not all_records_mode) and set(categories) == {'profiled', 'excluded', 'unclassified', 'unknown'}
    if all_records_mode:
        effective_categories = [None]
    elif output_mode == 'send' and all_categories_selected:
        effective_categories = [None]  # Single "all records" cloud export per scan.
    else:
        effective_categories = categories

    total_requests = len(scans) * len(effective_categories)
    request_counter = 0
    success_counter = 0
    file_counter = 0

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_base = f"scan_records_{timestamp}.{ 'jsonl' if output_mode == 'jsonl' else 'csv' }"
    base_output_name = output_filename or default_base
    is_multi_export = total_requests > 1

    for scan in scans:
        scan_id = scan.get('id')
        scan_name = scan.get('name', 'Unknown')
        if not scan_id:
            continue
        for category in effective_categories:
            request_counter += 1
            category_label = category if category else "all"
            print(f"  [{request_counter}/{total_requests}] {scan_name} :: {category_label}")
            params = {'category': category}
            if category is None:
                params.pop('category', None)
            if output_mode == 'send':
                params['format'] = 'cloud'
                payload_text = make_api_text_request('GET', f"scans/{scan_id}/records/export", params=params, api_version='v3')
                if payload_text is not None:
                    success_counter += 1
                continue

            # Local outputs retrieve JSONL payload.
            params['format'] = 'jsonl'
            params['includeData'] = 'true'
            payload_text = make_api_text_request('GET', f"scans/{scan_id}/records/export", params=params, api_version='v3')
            if payload_text is None:
                continue
            success_counter += 1

            if output_mode == 'jsonl':
                file_category = category or "records"
                out_file = build_output_filename(base_output_name, scan_name, scan_id, file_category) if is_multi_export else base_output_name
                with open(out_file, 'w', encoding='utf-8') as f:
                    f.write(payload_text.strip())
                    if not payload_text.endswith("\n"):
                        f.write("\n")
                file_counter += 1
                print(f"    wrote {out_file}")
            elif output_mode == 'csv':
                file_category = category or "records"
                out_file = build_output_filename(base_output_name, scan_name, scan_id, file_category) if is_multi_export else base_output_name
                rows = parse_jsonl_device_records(payload_text, scan_id, scan_name, file_category)
                headers = [
                    'scan_id', 'scan_name', 'category', 'created', 'ip_address',
                    'manufacturer', 'model', 'type', 'discovery_state', 'reason'
                ]
                with open(out_file, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=headers)
                    writer.writeheader()
                    writer.writerows(rows)
                file_counter += 1
                print(f"    wrote {out_file} ({len(rows)} rows)")

    if output_mode == 'send':
        print(f"✓ Sent {success_counter}/{total_requests} category exports to Phosphorus (cloud format).")
        return

    if output_mode == 'jsonl':
        print(
            f"✓ JSONL export complete: wrote {file_counter} file(s) "
            f"(successful exports: {success_counter}/{total_requests})"
        )
    elif output_mode == 'csv':
        print(
            f"✓ CSV export complete: wrote {file_counter} file(s) "
            f"(successful exports: {success_counter}/{total_requests})"
        )


# Export complete scan data as JSONL with a multi-strategy endpoint fallback.
def export_full_scan_jsonl(api_host: str, api_key: str,
                           output_filename: Optional[str] = None,
                           output_directory: str = ".",
                           combine_into_single_file: bool = False,
                           name_filter: Optional[str] = None,
                           start_date: Optional[str] = None,
                           end_date: Optional[str] = None,
                           max_results: int = 100,
                           scan_status: str = 'completed') -> None:
    """Export full scan JSONL with endpoint fallback strategy.

    Tries single-call v3 exports first, then falls back to category
    fan-out merge.  Can write one file per scan or combine all into a
    single JSONL stream.

    Args:
        api_host: Phosphorus API hostname.
        api_key: API authentication key.
        output_filename: Filename for combined output (or per-scan prefix).
        output_directory: Target directory for output files.
        combine_into_single_file: When ``True`` append all scans to one file.
        name_filter: Optional partial-name filter.
        start_date: Optional ISO start-date boundary.
        end_date: Optional ISO end-date boundary.
        max_results: Maximum scans to export.
        scan_status: Status category of scans to export from.
    """
    def _is_metadata_line(line: str) -> bool:
        """Return ``True`` if *line* is a JSONL scan-metadata header."""
        try:
            obj = json.loads(line)
            return isinstance(obj, dict) and 'addr' not in obj and 'options' in obj
        except Exception:
            return False

    def _combine_jsonl_chunks(chunks: list) -> str:
        """Merge category JSONL chunks into one stream with one metadata line."""
        merged = []
        metadata_kept = False
        for chunk in chunks:
            for raw_line in chunk.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                if _is_metadata_line(line):
                    if metadata_kept:
                        continue
                    metadata_kept = True
                merged.append(line)
        return "\n".join(merged) + ("\n" if merged else "")

    def _fetch_full_jsonl_for_scan(scan_id: str) -> tuple[Optional[str], str]:
        """Try multiple export strategies and return the first success."""
        # Strategy 1: single-call export, no category
        payload = make_api_text_request(
            'GET',
            f"scans/{scan_id}/records/export",
            params={'format': 'jsonl', 'includeData': 'true'},
            api_version='v3'
        )
        if payload:
            return payload, "v3 export (no category)"

        # Strategy 2: single-call export with category=all
        payload = make_api_text_request(
            'GET',
            f"scans/{scan_id}/records/export",
            params={'format': 'jsonl', 'includeData': 'true', 'category': 'all'},
            api_version='v3'
        )
        if payload:
            return payload, "v3 export (category=all)"

        # Strategy 3: category fan-out and merge
        category_chunks = []
        for category in ['profiled', 'excluded', 'unclassified', 'unknown']:
            category_payload = make_api_text_request(
                'GET',
                f"scans/{scan_id}/records/export",
                params={'format': 'jsonl', 'includeData': 'true', 'category': category},
                api_version='v3'
            )
            if category_payload:
                category_chunks.append(category_payload)
        if category_chunks:
            return _combine_jsonl_chunks(category_chunks), "v3 export (merged categories)"

        return None, "no working endpoint"

    os.environ['PHO_API_HOST'] = api_host
    os.environ['PHO_API_KEY'] = api_key

    print(f"Fetching scan list for full JSONL export (status={scan_status}, max={max_results})...")
    scans = get_completed_scan_history(
        name_filter=name_filter,
        start_date=start_date,
        end_date=end_date,
        scan_status=scan_status,
        max_results=max_results
    )
    if not scans:
        print("No scans found matching the selected filters.")
        return

    target_dir = Path(output_directory).expanduser()
    target_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    combined_filename = output_filename or f"full_scans_{timestamp}.jsonl"
    combined_path = target_dir / combined_filename
    combined_count = 0
    written_files = []

    print(f"Found {len(scans)} scans. Starting full JSONL export...")
    for idx, scan in enumerate(scans, start=1):
        scan_id = scan.get('id')
        scan_name = scan.get('name', 'Unknown')
        if not scan_id:
            logger.warning(f"Skipping scan without ID: {scan_name}")
            continue

        print(f"  [{idx}/{len(scans)}] {scan_name}")
        payload_text, strategy_used = _fetch_full_jsonl_for_scan(scan_id)
        if payload_text is None:
            print(f"    failed: unable to export full JSONL ({strategy_used})")
            continue
        print(f"    using: {strategy_used}")

        if combine_into_single_file:
            with open(combined_path, 'a', encoding='utf-8') as f:
                content = payload_text.strip()
                if content:
                    f.write(content)
                    if not content.endswith("\n"):
                        f.write("\n")
                    combined_count += 1
        else:
            safe_name = sanitize_filename_component(scan_name)
            per_scan_name = f"scan-{safe_name}-{scan_id[:8]}.jsonl"
            per_scan_path = target_dir / per_scan_name
            with open(per_scan_path, 'w', encoding='utf-8') as f:
                f.write(payload_text.strip())
                if not payload_text.endswith("\n"):
                    f.write("\n")
            written_files.append(str(per_scan_path))

    success_total = combined_count if combine_into_single_file else len(written_files)
    if success_total == 0:
        print("✗ Full JSONL export finished with 0 successful scan exports.")
        return
    if combine_into_single_file:
        print(f"✓ Full JSONL export complete: {combined_path} (scans written: {combined_count})")
    else:
        print(f"✓ Full JSONL export complete: wrote {len(written_files)} file(s) to {target_dir}")

# Idempotent scan upsert: creates a new scheduled scan or updates an existing one.
def create_or_update_scan(scan_data: Dict[str, Any], existing_scans: Dict[str, Dict],
                         config: Config, is_new_scan: bool = False) -> Optional[Dict]:
    """Create or update a scan with versioning.

    If a scan with the same name already exists it is updated via
    ``PUT``; otherwise a new scan is created via ``POST``.  When the
    existing scan has no ID a versioned name is generated.

    Args:
        scan_data: Processed scan configuration dict.
        existing_scans: Current scans keyed by name.
        config: Runtime config (checked for ``dry_run``).
        is_new_scan: Hint from CSV processing about newness.

    Returns:
        API response dict on success, ``None`` on failure, or
        ``{'success': True, 'dry_run': True}`` in dry-run mode.
    """
    name = scan_data['name']
    # If scan exists, handle update case
    if name in existing_scans:
        existing_scan = existing_scans[name]
        scan_id = existing_scan.get('id')
        if not scan_id:
            logger.warning(f"Existing scan {name} found but has no ID. Will create as new.")
            name = get_versioned_name(name, existing_scans.keys())
            scan_data['name'] = name
        else:
            logger.info(f"Updating existing scan with ID {scan_id}: {name}")
            if config.dry_run:
                logger.info(f"[DRY RUN] Would update scan: {name} (ID: {scan_id})")
                return {'success': True, 'dry_run': True}
            # Keep provider_id for updates only when explicitly provided.
            scan_data = dict(scan_data)
            if not scan_data.get('provider_id'):
                scan_data.pop('provider_id', None)
            # Use v3 API for scan updates
            response = make_api_request(
                'PUT',
                f"scans/{scan_id}",
                api_version='v3',
                headers={'Content-Type': 'application/json'},
                json_data=scan_data
            )
            if response:
                logger.info(f"Successfully updated scan: {name}")
                logger.debug(f"Scan updated response: {json.dumps(response, indent=2)}")
                return response
            else:
                logger.warning(f"Failed to update scan {name}")
                return None
    # Handle creating a new scan
    if config.dry_run:
        logger.info(f"[DRY RUN] Would create scan: {name}")
        return {'success': True, 'dry_run': True}
    # Use the format we know works for creating scans
    simple_scan_payload = {
        'name': scan_data['name'],
        'description': scan_data.get('description', ''),
        'cron': scan_data.get('cron'),
        'timezone': scan_data.get('timezone', 'America/New_York'),  # Fixed default timezone
        'networks': scan_data.get('networks', ''),  # Already converted to newline format
        'site_id': scan_data.get('site_id', ''),
        'provider_id': scan_data.get('provider_id', ''),
        'start_date': scan_data.get('options', {}).get('start_date', '') or scan_data.get('start_date', ''),
        'start_time': scan_data.get('options', {}).get('start_time', '') or scan_data.get('start_time', ''),
        'scan_options': {
            "file": "standard",
            "default": True,
            "display_name": "Standard xIoT Enterprise Discovery",
            "description": "This is the default Phosphorus Active xIoT Discovery Agenda that employs a tiered approach to progressively discover xIoT devices in your environment."
        }
    }
    # Add SNMP configuration if available
    if 'options' in scan_data and 'snmp' in scan_data['options']:
        simple_scan_payload['snmp'] = scan_data['options']['snmp']
    elif 'snmp' in scan_data:
        simple_scan_payload['snmp'] = scan_data['snmp']
    # Add excluded networks if available
    if 'excluded_networks' in scan_data and scan_data['excluded_networks']:
        simple_scan_payload['excluded_networks'] = scan_data['excluded_networks']  # Already in newline format
    # Use v3 API for scan creation
    response = make_api_request(
        'POST',
        "scans",
        api_version='v3',
        headers={'Content-Type': 'application/json'},
        json_data=simple_scan_payload
    )
    if response:
        logger.info(f"Successfully created scan: {name}")
        logger.debug(f"Scan created response: {json.dumps(response, indent=2)}")
        return response
    else:
        logger.warning(f"Failed to create scan {name}")
        return None

# --- MAIN PROCESSING FUNCTION ---
# Shallow equality check for tag fields.
def tags_equal(csv_tag, api_tag):
    """Compare CSV tag data against the API representation.

    Checks ``name``, ``description``, ``color``, ``query``, and
    ``automatic`` fields for equality.

    Args:
        csv_tag: Tag dict built from the CSV row.
        api_tag: Tag dict retrieved from the API.

    Returns:
        ``True`` when all compared fields match.
    """
    # Compare relevant fields for tags
    return (
        csv_tag['name'] == api_tag.get('name') and
        csv_tag['description'] == api_tag.get('description') and
        csv_tag['color'] == api_tag.get('color') and
        csv_tag['query'] == api_tag.get('query') and
        csv_tag['automatic'] == api_tag.get('automatic', True)
    )

# Normalise network strings/lists into a comparable sorted list.
def normalize_network_list(networks_input) -> list:
    """Convert network string or list to normalized sorted list.

    Handles comma-separated strings, newline-separated strings, and
    lists that may themselves contain comma/newline-separated entries.

    Args:
        networks_input: Raw network data from CSV or API.

    Returns:
        Sorted list of stripped CIDR strings.
    """
    if not networks_input:
        return []
    
    # Handle if input is already a list
    if isinstance(networks_input, list):
        # API sometimes returns a list with a single comma-separated string
        # e.g., ['10.1.1.1/24, 10.2.2.2/24'] instead of ['10.1.1.1/24', '10.2.2.2/24']
        all_networks = []
        for item in networks_input:
            item_str = str(item).strip()
            if ',' in item_str:
                # Split comma-separated string within list item
                all_networks.extend([n.strip() for n in item_str.split(',') if n.strip()])
            elif '\n' in item_str:
                # Split newline-separated string within list item
                all_networks.extend([n.strip() for n in item_str.split('\n') if n.strip()])
            else:
                # Single network
                if item_str:
                    all_networks.append(item_str)
        networks = all_networks
    else:
        # Handle both comma and newline separators for strings
        networks_str = str(networks_input)
        if '\n' in networks_str:
            networks = networks_str.split('\n')
        else:
            networks = networks_str.split(',')
    
    # Clean up and sort
    return sorted([str(n).strip() for n in networks if str(n).strip()])

# Coerce None and empty-string to a common empty sentinel for comparisons.
def normalize_value(value: Any) -> Any:
    """Normalize values for comparison - handle empty strings vs ``None``.

    Args:
        value: Any scalar value.

    Returns:
        Stripped string representation, or ``''`` for ``None``/empty.
    """
    if value is None or value == '':
        return ''
    return str(value).strip()

# Deep equality check for scan configurations including SNMP.
def scans_equal(csv_scan, api_scan, is_new=False):
    """Fixed comparison function that properly handles CSV vs API format differences.

    This function includes comprehensive SNMP settings comparison to detect
    changes in SNMP communities, credentials, and other SNMP configuration
    parameters.  Site-ID comparison is skipped because the API returns
    ``null`` inconsistently for that field.

    Args:
        csv_scan: Scan dict built from the CSV row.
        api_scan: Scan dict retrieved from the API.
        is_new: When ``True`` also compare ``provider_id``.

    Returns:
        ``True`` when all compared fields match.
    """
    
    # Get API scan options
    options = api_scan.get('options', {})
    
    # Compare networks - handle both comma and newline separated
    csv_networks = normalize_network_list(csv_scan.get('networks', ''))
    api_networks = normalize_network_list(options.get('networks', ''))
    
    # Compare excluded networks
    csv_excluded = normalize_network_list(csv_scan.get('excluded_networks', ''))
    api_excluded = normalize_network_list(options.get('excluded_networks', ''))
    
    # Compare site_id from nested site object
    csv_site_id = normalize_value(csv_scan.get('site_id', ''))
    api_site_id = normalize_value((api_scan.get('site', {}) or {}).get('id', ''))
    
    # WORKAROUND: API returns site.id as null even when site_id was provided
    # For existing scans, skip site_id comparison since it can't be changed after creation
    # and the API doesn't return it consistently
    site_id_match = True  # Skip site_id comparison for existing scans
    
    # Compare timezone with proper default handling
    csv_timezone = normalize_value(csv_scan.get('timezone', 'America/New_York'))
    api_timezone = normalize_value(api_scan.get('timezone', 'America/New_York'))
    
    # Compare cron
    csv_cron = normalize_value(csv_scan.get('cron', ''))
    api_cron = normalize_value(api_scan.get('cron', ''))

    # Compare start date/time from options or top-level fallback
    csv_start_date = normalize_value(csv_scan.get('start_date', ''))
    api_start_date = normalize_value(
        (api_scan.get('options', {}) or {}).get('start_date', api_scan.get('start_date', ''))
    )
    csv_start_time = normalize_value(csv_scan.get('start_time', ''))
    api_start_time = normalize_value(
        (api_scan.get('options', {}) or {}).get('start_time', api_scan.get('start_time', ''))
    )
    
    # Compare name
    csv_name = normalize_value(csv_scan.get('name', ''))
    api_name = normalize_value(api_scan.get('name', ''))
    
    # Compare SNMP settings
    csv_snmp = csv_scan.get('snmp', {})
    api_snmp = options.get('snmp', {})
    
    csv_snmp_communities = normalize_value(csv_snmp.get('communities', ''))
    api_snmp_communities = normalize_value(api_snmp.get('communities', ''))
    
    csv_snmp_username = normalize_value(csv_snmp.get('username', ''))
    api_snmp_username = normalize_value(api_snmp.get('username', ''))
    
    csv_snmp_protocol = normalize_value(csv_snmp.get('protocol', ''))
    api_snmp_protocol = normalize_value(api_snmp.get('protocol', ''))
    
    csv_snmp_context = normalize_value(csv_snmp.get('context_name', ''))
    api_snmp_context = normalize_value(api_snmp.get('context_name', ''))
    
    csv_snmp_privacy_protocol = normalize_value(csv_snmp.get('privacy_protocol', ''))
    api_snmp_privacy_protocol = normalize_value(api_snmp.get('privacy_protocol', ''))
    
    csv_snmp_passphrase = normalize_value(csv_snmp.get('passphrase', ''))
    api_snmp_passphrase = normalize_value(api_snmp.get('passphrase', ''))
    
    csv_snmp_privacy_passphrase = normalize_value(csv_snmp.get('privacy_passphrase', ''))
    api_snmp_privacy_passphrase = normalize_value(api_snmp.get('privacy_passphrase', ''))
    
    # Log comparison details for debugging
    logger.debug(f"Comparing scan: {csv_name}")
    logger.debug(f"  CSV networks: {csv_networks}")
    logger.debug(f"  API networks: {api_networks}")
    logger.debug(f"  CSV excluded: {csv_excluded}")
    logger.debug(f"  API excluded: {api_excluded}")
    logger.debug(f"  CSV site_id: '{csv_site_id}'")
    logger.debug(f"  API site_id: '{api_site_id}' (skipping comparison due to API inconsistency)")
    logger.debug(f"  CSV timezone: '{csv_timezone}'")
    logger.debug(f"  API timezone: '{api_timezone}'")
    logger.debug(f"  CSV cron: '{csv_cron}'")
    logger.debug(f"  API cron: '{api_cron}'")
    logger.debug(f"  CSV start_date: '{csv_start_date}'")
    logger.debug(f"  API start_date: '{api_start_date}'")
    logger.debug(f"  CSV start_time: '{csv_start_time}'")
    logger.debug(f"  API start_time: '{api_start_time}'")
    logger.debug(f"  CSV SNMP communities: '{csv_snmp_communities}'")
    logger.debug(f"  API SNMP communities: '{api_snmp_communities}'")
    logger.debug(f"  CSV SNMP username: '{csv_snmp_username}'")
    logger.debug(f"  API SNMP username: '{api_snmp_username}'")
    logger.debug(f"  CSV SNMP protocol: '{csv_snmp_protocol}'")
    logger.debug(f"  API SNMP protocol: '{api_snmp_protocol}'")
    logger.debug(f"  CSV SNMP context: '{csv_snmp_context}'")
    logger.debug(f"  API SNMP context: '{api_snmp_context}'")
    logger.debug(f"  CSV SNMP privacy protocol: '{csv_snmp_privacy_protocol}'")
    logger.debug(f"  API SNMP privacy protocol: '{api_snmp_privacy_protocol}'")
    logger.debug(f"  CSV SNMP passphrase: '{'*' * len(csv_snmp_passphrase) if csv_snmp_passphrase else ''}'")
    logger.debug(f"  API SNMP passphrase: '{'*' * len(api_snmp_passphrase) if api_snmp_passphrase else ''}'")
    logger.debug(f"  CSV SNMP privacy passphrase: '{'*' * len(csv_snmp_privacy_passphrase) if csv_snmp_privacy_passphrase else ''}'")
    logger.debug(f"  API SNMP privacy passphrase: '{'*' * len(api_snmp_privacy_passphrase) if api_snmp_privacy_passphrase else ''}')")
    
    # Perform comparison
    name_match = csv_name == api_name
    cron_match = csv_cron == api_cron
    start_date_match = csv_start_date == api_start_date
    start_time_match = csv_start_time == api_start_time
    timezone_match = csv_timezone == api_timezone
    networks_match = csv_networks == api_networks
    excluded_match = csv_excluded == api_excluded
    
    # SNMP comparisons
    snmp_communities_match = csv_snmp_communities == api_snmp_communities
    snmp_username_match = csv_snmp_username == api_snmp_username
    snmp_protocol_match = csv_snmp_protocol == api_snmp_protocol
    snmp_context_match = csv_snmp_context == api_snmp_context
    snmp_privacy_protocol_match = csv_snmp_privacy_protocol == api_snmp_privacy_protocol
    snmp_passphrase_match = csv_snmp_passphrase == api_snmp_passphrase
    snmp_privacy_passphrase_match = csv_snmp_privacy_passphrase == api_snmp_privacy_passphrase
    
    # Log individual comparison results
    logger.debug(f"  Name match: {name_match}")
    logger.debug(f"  Cron match: {cron_match}")
    logger.debug(f"  Start date match: {start_date_match}")
    logger.debug(f"  Start time match: {start_time_match}")
    logger.debug(f"  Timezone match: {timezone_match}")
    logger.debug(f"  Networks match: {networks_match}")
    logger.debug(f"  Excluded match: {excluded_match}")
    logger.debug(f"  Site ID match: {site_id_match} (skipped - API returns null)")
    logger.debug(f"  SNMP communities match: {snmp_communities_match}")
    logger.debug(f"  SNMP username match: {snmp_username_match}")
    logger.debug(f"  SNMP protocol match: {snmp_protocol_match}")
    logger.debug(f"  SNMP context match: {snmp_context_match}")
    logger.debug(f"  SNMP privacy protocol match: {snmp_privacy_protocol_match}")
    logger.debug(f"  SNMP passphrase match: {snmp_passphrase_match}")
    logger.debug(f"  SNMP privacy passphrase match: {snmp_privacy_passphrase_match}")
    
    # Only compare provider_id for new scans
    provider_id_match = True
    if is_new:
        api_provider_id = ''
        if 'credential_provider' in api_scan and api_scan['credential_provider']:
            api_provider_id = api_scan['credential_provider'].get('id', '')
        elif 'provider_id' in api_scan and api_scan['provider_id']:
            api_provider_id = api_scan['provider_id']
        provider_id_match = normalize_value(csv_scan.get('provider_id', '')) == normalize_value(api_provider_id)
        logger.debug(f"  Provider ID match: {provider_id_match}")
    
    # Final result
    result = (name_match and cron_match and start_date_match and start_time_match and timezone_match and 
              networks_match and excluded_match and site_id_match and provider_id_match and
              snmp_communities_match and snmp_username_match and snmp_protocol_match and
              snmp_context_match and snmp_privacy_protocol_match and snmp_passphrase_match and
              snmp_privacy_passphrase_match)
    
    logger.debug(f"  Overall match: {result}")
    return result

# Main pipeline: reads the CSV and orchestrates tag/scan creates/updates.
def process_unified_csv(config: Config) -> None:
    """Process unified CSV file containing both tags and scans.

    Executes a three-phase pipeline:

    1. Fetch existing tags from the API.
    2. Fetch existing scans (with full detail lookups).
    3. Iterate CSV rows, comparing each against the API state to decide
       whether to create, update, or skip.

    Progress is rendered via :class:`ProgressRenderer`.  Failed rows are
    collected and written to a ``*-retry.csv`` at the end.

    Args:
        config: Runtime configuration including CSV path and API credentials.
    """
    import time
    preflight_spinner = itertools.cycle(['|', '/', '-', '\\'])
    preflight_bar = None
    preflight_bar_current = 0
    preflight_rich_progress = None
    preflight_rich_task = None
    preflight_ui_mode = config.ui_mode

    if not config.silent and preflight_ui_mode == 'bar':
        try:
            from tqdm import tqdm
            preflight_bar = tqdm(total=0, desc="Phase 2/3 scan details", unit='scan', dynamic_ncols=True, leave=False)
        except Exception:
            logger.warning("tqdm not available for preflight; falling back to simple preflight UI")
            preflight_ui_mode = 'simple'

    if not config.silent and preflight_ui_mode == 'rich':
        try:
            from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
            preflight_rich_progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                transient=True
            )
            preflight_rich_progress.start()
            preflight_rich_task = preflight_rich_progress.add_task("Phase 2/3 scan details", total=100)
        except Exception:
            logger.warning("rich not available for preflight; falling back to simple preflight UI")
            preflight_ui_mode = 'simple'

    def preflight_status(message: str) -> None:
        """Render a preflight progress update to the chosen UI backend."""
        if config.silent:
            return
        nonlocal preflight_bar_current
        match = re.search(r'(\d+)/(\d+)$', message.strip())
        if preflight_ui_mode == 'bar' and preflight_bar is not None:
            if match:
                current = int(match.group(1))
                total = int(match.group(2))
                if preflight_bar.total != total:
                    preflight_bar.total = total
                delta = max(0, current - preflight_bar_current)
                if delta:
                    preflight_bar.update(delta)
                    preflight_bar_current = current
            preflight_bar.set_description(f"Phase 2/3 scan details")
            preflight_bar.set_postfix_str(message[:60])
        elif preflight_ui_mode == 'rich' and preflight_rich_progress is not None and preflight_rich_task is not None:
            if match:
                current = int(match.group(1))
                total = int(match.group(2))
                preflight_rich_progress.update(preflight_rich_task, total=total, completed=current)
            preflight_rich_progress.update(preflight_rich_task, description=f"[bold cyan]{message[:80]}")
        else:
            sys.stdout.write("\r" + " " * 140)
            sys.stdout.write(f"\r{next(preflight_spinner)} {message[:135]}")
            sys.stdout.flush()

    if not config.silent:
        print("Phase 1/3: Fetching existing tags...")
    existing_tags = get_existing_tags()
    if not config.silent:
        print(f"Phase 1/3 complete: loaded {len(existing_tags)} existing tags")
        print("Phase 2/3: Fetching existing scans and details (this may take a while)...")
    existing_scans = get_existing_scans(status_callback=preflight_status if not config.silent else None)
    if not config.silent:
        if preflight_bar is not None:
            preflight_bar.close()
        if preflight_rich_progress is not None:
            preflight_rich_progress.stop()
        if preflight_ui_mode == 'simple':
            sys.stdout.write("\r" + " " * 140 + "\r")
            sys.stdout.flush()
        print(f"Phase 2/3 complete: loaded {len(existing_scans)} existing scans")
        print("Phase 3/3: Processing CSV rows...")
    
    tag_created = 0
    tag_updated = 0
    tag_unchanged = 0
    scan_created = 0
    scan_updated = 0
    scan_unchanged = 0
    tag_errors = []
    scan_errors = []
    # Track names for each status
    tag_created_names = []
    tag_updated_names = []
    tag_unchanged_names = []
    scan_created_names = []
    scan_updated_names = []
    scan_unchanged_names = []
    # Track all names seen in CSV
    csv_tag_names = set()
    csv_scan_names = set()
    failed_rows: Dict[int, Dict[str, Any]] = {}
    retry_csv_file: Optional[str] = None

    def track_failed_row(row_number: int, row_data: Dict[str, Any], error_message: str) -> None:
        """Track failed rows so we can generate a retry CSV at the end."""
        entry = failed_rows.get(row_number)
        if not entry:
            failed_rows[row_number] = {
                'row': dict(row_data),
                'errors': [error_message]
            }
        else:
            entry['errors'].append(error_message)

    with open(config.input_csv, newline='', encoding='utf-8') as csvfile:
        rows = list(csv.DictReader(csvfile))

    total_rows = len(rows)
    total_tags = sum(1 for r in rows if str(r.get('type', '')).strip().lower() == 'tag')
    total_scans = sum(1 for r in rows if str(r.get('type', '')).strip().lower() == 'scan')
    processed_rows = 0
    processed_tags = 0
    processed_scans = 0

    progress = ProgressRenderer(config.ui_mode, total_rows, total_tags, total_scans, silent=config.silent)
    progress.start()

    for row_number, row in enumerate(rows, start=2):  # Start from 2 to account for header
            item_type = str(row.get('type', '')).strip().lower()
            try:
                if item_type == 'tag':
                    processed_tags += 1
                    progress.update(
                        processed_rows + 1, processed_tags, processed_scans, item_type, row.get('name', ''),
                        (tag_created, tag_updated, tag_unchanged, len(tag_errors)),
                        (scan_created, scan_updated, scan_unchanged, len(scan_errors))
                    )
                    csv_tag_names.add(row['name'])
                    config.validator.validate_required_fields(
                        row, 
                        ['name', 'description', 'color', 'query'],
                        row_number
                    )
                    if not config.validator.validate_color(row['color']):
                        raise ValidationError(
                            f"Invalid color format: {row['color']}",
                            row_number,
                            'color'
                        )
                    # Ensure color has # prefix for API
                    color = row['color'].strip()
                    if color and not color.startswith('#'):
                        color = '#' + color
                    
                    tag_data = {
                        "name": row['name'],
                        "description": row['description'],
                        "color": color,
                        "query": row['query'],
                        "automatic": True
                    }
                    if tag_data['name'] in existing_tags:
                        logger.info(f"Tag '{tag_data['name']}' found - checking for changes.")
                        if tags_equal(tag_data, existing_tags[tag_data['name']]):
                            tag_unchanged += 1
                            tag_unchanged_names.append(tag_data['name'])
                            logger.info(f"Tag '{tag_data['name']}' unchanged.")
                        else:
                            tag_updated += 1
                            tag_updated_names.append(tag_data['name'])
                            logger.info(f"Tag '{tag_data['name']}' changed - updating.")
                            response = create_or_update_tag(tag_data, existing_tags, config)
                            if not response:
                                error_msg = f"Tag '{tag_data['name']}' failed to update (row {row_number}) - see log for details."
                                tag_errors.append(error_msg)
                                track_failed_row(row_number, row, error_msg)
                    else:
                        tag_created += 1
                        tag_created_names.append(tag_data['name'])
                        logger.info(f"Tag '{tag_data['name']}' not found - creating.")
                        response = create_or_update_tag(tag_data, existing_tags, config)
                        if not response:
                            error_msg = f"Tag '{tag_data['name']}' failed to create (row {row_number}) - see log for details."
                            tag_errors.append(error_msg)
                            track_failed_row(row_number, row, error_msg)
                
                elif item_type == 'scan':
                    processed_scans += 1
                    progress.update(
                        processed_rows + 1, processed_tags, processed_scans, item_type, row.get('name', ''),
                        (tag_created, tag_updated, tag_unchanged, len(tag_errors)),
                        (scan_created, scan_updated, scan_unchanged, len(scan_errors))
                    )
                    csv_scan_names.add(row['name'])
                    
                    # Get run_now setting (default to 'no' if not specified)
                    run_now = row.get('run_now', 'no').lower().strip()
                    if run_now not in ['yes', 'no', 'only']:
                        raise ValidationError(
                            f"Invalid run_now value: {run_now}. Must be 'yes', 'no', or 'only'",
                            row_number,
                            'run_now'
                        )
                    
                    # Determine if this is a new scan (not in existing_scans)
                    is_new_scan = row['name'] not in existing_scans
                    # Use the correct provider column for new scans only
                    provider_column = 'credential_provider_id_NEW_ONLY' if is_new_scan else None
                    
                    # Set required fields based on run_now setting
                    required_fields = ['name', 'timezone', 'site_id', 'networks']
                    if run_now == 'no' or run_now == 'yes':
                        # Scheduled scan needs cron (no=scheduled only, yes=both scheduled+run-now)
                        required_fields.append('cron')
                    # 'only' doesn't need cron since it's run-now only
                    if is_new_scan:
                        required_fields.append('credential_provider_id_NEW_ONLY')
                    
                    config.validator.validate_required_fields(
                        row,
                        required_fields,
                        row_number
                    )
                    
                    # Validate cron only if needed for scheduled scans
                    if (run_now == 'no' or run_now == 'yes') and row.get('cron'):
                        if not config.validator.validate_cron(row['cron']):
                            raise ValidationError(
                                f"Invalid cron expression: {row['cron']}",
                                row_number,
                                'cron'
                            )
                    # Handle networks field - could be string or list
                    networks_field = row['networks']
                    if isinstance(networks_field, list):
                        networks_to_validate = networks_field
                    else:
                        networks_to_validate = networks_field.replace(';', ',').split(',')
                    
                    for network in networks_to_validate:
                        if network and not config.validator.validate_network(str(network).strip()):
                            raise ValidationError(
                                f"Invalid network CIDR: {str(network).strip()}",
                                row_number,
                                'networks'
                            )
                    scan_data = process_scan_data(row, row_number, is_new_scan)
                    
                    # Handle different run_now scenarios
                    if run_now == 'only':
                        # Only create run-now scan, no scheduled scan
                        logger.info(f"Creating run-now only scan for: {scan_data['name']}")
                        run_now_response = create_run_now_scan(scan_data, config)
                        if run_now_response:
                            scan_created += 1
                            scan_created_names.append(f"{scan_data['name']} (Run Now)")
                        else:
                            error_msg = f"Run-now scan for '{scan_data['name']}' failed to create (row {row_number}) - see log for details."
                            scan_errors.append(error_msg)
                            track_failed_row(row_number, row, error_msg)
                    
                    elif run_now == 'yes':
                        # Create/update scheduled scan AND create run-now scan
                        logger.info(f"Creating both scheduled and run-now scan for: {scan_data['name']}")
                        
                        # Handle scheduled scan
                        if scan_data['name'] in existing_scans:
                            logger.info(f"Scheduled scan '{scan_data['name']}' found - checking for changes.")
                            if config.force_scan_update:
                                logger.info(
                                    f"Force update enabled - updating scheduled scan '{scan_data['name']}' without equality check."
                                )
                                scan_updated += 1
                                scan_updated_names.append(scan_data['name'])
                                response = create_or_update_scan(scan_data, existing_scans, config, is_new_scan)
                                if not response:
                                    error_msg = f"Scheduled scan '{scan_data['name']}' failed to update (row {row_number}) - see log for details."
                                    scan_errors.append(error_msg)
                                    track_failed_row(row_number, row, error_msg)
                            elif scans_equal(scan_data, existing_scans[scan_data['name']], is_new=False):
                                scan_unchanged += 1
                                scan_unchanged_names.append(scan_data['name'])
                                logger.info(f"Scheduled scan '{scan_data['name']}' unchanged.")
                            else:
                                scan_updated += 1
                                scan_updated_names.append(scan_data['name'])
                                logger.info(f"Scheduled scan '{scan_data['name']}' changed - updating.")
                                response = create_or_update_scan(scan_data, existing_scans, config, is_new_scan)
                                if not response:
                                    error_msg = f"Scheduled scan '{scan_data['name']}' failed to update (row {row_number}) - see log for details."
                                    scan_errors.append(error_msg)
                                    track_failed_row(row_number, row, error_msg)
                        else:
                            scan_created += 1
                            scan_created_names.append(scan_data['name'])
                            logger.info(f"Scheduled scan '{scan_data['name']}' not found - creating.")
                            response = create_or_update_scan(scan_data, existing_scans, config, is_new_scan)
                            if not response:
                                error_msg = f"Scheduled scan '{scan_data['name']}' failed to create (row {row_number}) - see log for details."
                                scan_errors.append(error_msg)
                                track_failed_row(row_number, row, error_msg)
                        
                        # Create run-now scan
                        run_now_response = create_run_now_scan(scan_data, config)
                        if run_now_response:
                            scan_created += 1
                            scan_created_names.append(f"{scan_data['name']} (Run Now)")
                        else:
                            error_msg = f"Run-now scan for '{scan_data['name']}' failed to create (row {row_number}) - see log for details."
                            scan_errors.append(error_msg)
                            track_failed_row(row_number, row, error_msg)
                    
                    else:  # run_now == 'no'
                        # Only handle scheduled scan (existing behavior)
                        if scan_data['name'] in existing_scans:
                            logger.info(f"Scan '{scan_data['name']}' found - checking for changes.")
                            if config.force_scan_update:
                                logger.info(
                                    f"Force update enabled - updating scan '{scan_data['name']}' without equality check."
                                )
                                scan_updated += 1
                                scan_updated_names.append(scan_data['name'])
                                response = create_or_update_scan(scan_data, existing_scans, config, is_new_scan)
                                if not response:
                                    error_msg = f"Scan '{scan_data['name']}' failed to update (row {row_number}) - see log for details."
                                    scan_errors.append(error_msg)
                                    track_failed_row(row_number, row, error_msg)
                            elif scans_equal(scan_data, existing_scans[scan_data['name']], is_new=False):
                                scan_unchanged += 1
                                scan_unchanged_names.append(scan_data['name'])
                                logger.info(f"Scan '{scan_data['name']}' unchanged.")
                            else:
                                scan_updated += 1
                                scan_updated_names.append(scan_data['name'])
                                logger.info(f"Scan '{scan_data['name']}' changed - updating.")
                                response = create_or_update_scan(scan_data, existing_scans, config, is_new_scan)
                                if not response:
                                    error_msg = f"Scan '{scan_data['name']}' failed to update (row {row_number}) - see log for details."
                                    scan_errors.append(error_msg)
                                    track_failed_row(row_number, row, error_msg)
                        else:
                            scan_created += 1
                            scan_created_names.append(scan_data['name'])
                            logger.info(f"Scan '{scan_data['name']}' not found - creating.")
                            response = create_or_update_scan(scan_data, existing_scans, config, is_new_scan)
                            if not response:
                                error_msg = f"Scan '{scan_data['name']}' failed to create (row {row_number}) - see log for details."
                                scan_errors.append(error_msg)
                                track_failed_row(row_number, row, error_msg)
                else:
                    progress.update(
                        processed_rows + 1, processed_tags, processed_scans, item_type, row.get('name', ''),
                        (tag_created, tag_updated, tag_unchanged, len(tag_errors)),
                        (scan_created, scan_updated, scan_unchanged, len(scan_errors))
                    )
                    logger.warning(
                        f"Skipping row {row_number} with invalid type '{row.get('type', '')}'. "
                        "Expected 'tag' or 'scan'."
                    )
                    track_failed_row(
                        row_number,
                        row,
                        f"Invalid type '{row.get('type', '')}' (expected 'tag' or 'scan')"
                    )
                processed_rows += 1
                progress.advance()
                time.sleep(1)  # Rate limiting
            except ValidationError as e:
                processed_rows += 1
                progress.advance()
                if item_type == 'tag':
                    error_msg = f"Tag '{row.get('name', '')}' failed validation (row {row_number}): {e.message}"
                    tag_errors.append(error_msg)
                    track_failed_row(row_number, row, error_msg)
                elif item_type == 'scan':
                    error_msg = f"Scan '{row.get('name', '')}' failed validation (row {row_number}): {e.message}"
                    scan_errors.append(error_msg)
                    track_failed_row(row_number, row, error_msg)
                else:
                    track_failed_row(row_number, row, f"Validation error: {e.message}")
            except Exception as e:
                processed_rows += 1
                progress.advance()
                if item_type == 'tag':
                    error_msg = f"Tag '{row.get('name', '')}' error (row {row_number}): {str(e)}"
                    tag_errors.append(error_msg)
                    track_failed_row(row_number, row, error_msg)
                elif item_type == 'scan':
                    error_msg = f"Scan '{row.get('name', '')}' error (row {row_number}): {str(e)}"
                    scan_errors.append(error_msg)
                    track_failed_row(row_number, row, error_msg)
                else:
                    track_failed_row(row_number, row, f"Unhandled error: {str(e)}")
    progress.close()

    # Write retry CSV with only failed rows.
    if failed_rows:
        input_path = Path(config.input_csv)
        retry_path = input_path.with_name(f"{input_path.stem}-retry{input_path.suffix}")
        with open(retry_path, 'w', newline='', encoding='utf-8') as retry_file:
            # Preserve original header order and append retry metadata columns.
            base_headers = list(rows[0].keys()) if rows else []
            headers = base_headers + ['retry_row_number', 'retry_error']
            writer = csv.DictWriter(retry_file, fieldnames=headers, extrasaction='ignore')
            writer.writeheader()
            for failed_row_number in sorted(failed_rows.keys()):
                payload = dict(failed_rows[failed_row_number]['row'])
                payload['retry_row_number'] = failed_row_number
                payload['retry_error'] = " | ".join(failed_rows[failed_row_number]['errors'])
                writer.writerow(payload)
        retry_csv_file = str(retry_path)
    # Find tags/scans in API but not in CSV
    api_tag_names = set(existing_tags.keys())
    api_scan_names = set(existing_scans.keys())
    tags_not_in_csv = sorted(api_tag_names - csv_tag_names)
    scans_not_in_csv = sorted(api_scan_names - csv_scan_names)
    # Print enhanced summary with improved layout
    print("\nSummary:\n")
    print(f"   Tags created: {tag_created}, updated: {tag_updated}, unchanged: {tag_unchanged}")
    print(f"   Scans created: {scan_created}, updated: {scan_updated}, unchanged: {scan_unchanged}\n")
    print("Tags:\n")
    print(f"  Created:   {', '.join(tag_created_names) if tag_created_names else '-'}")
    print(f"  Updated:   {', '.join(tag_updated_names) if tag_updated_names else '-'}")
    print(f"  Unchanged: {', '.join(tag_unchanged_names) if tag_unchanged_names else '-'}")
    if tags_not_in_csv:
        print(f"  Not in CSV: {', '.join(tags_not_in_csv)}")
    print("\nScans:\n")
    print(f"  Created:   {', '.join(scan_created_names) if scan_created_names else '-'}")
    print(f"  Updated:   {', '.join(scan_updated_names) if scan_updated_names else '-'}")
    print(f"  Unchanged: {', '.join(scan_unchanged_names) if scan_unchanged_names else '-'}")
    if scans_not_in_csv:
        print(f"  Not in CSV: {', '.join(scans_not_in_csv)}")
    if tag_errors:
        print("\nTag errors:")
        for err in tag_errors:
            print(f"  - {err}")
    if scan_errors:
        print("\nScan errors:")
        for err in scan_errors:
            print(f"  - {err}")
    if retry_csv_file:
        print(f"\nRetry CSV created: {retry_csv_file}")

# Transform a raw CSV row into the API-compatible scan payload.
def process_scan_data(row: Dict[str, str], row_number: int, is_new_scan: bool = False) -> Dict[str, Any]:
    """Process scan data from CSV row into API format matching required structure.

    Converts comma/semicolon-separated network fields to newline-separated
    values as expected by the API, and builds the full scan payload
    including SNMP configuration.

    Args:
        row: Raw CSV row as a column-name → value dict.
        row_number: 1-based CSV row number (for diagnostics).
        is_new_scan: Whether this scan is new (affects provider handling).

    Returns:
        Dict ready to send as JSON to the scan creation/update endpoint.
    """
    # Convert networks and excluded_networks - handle both string and list formats
    # API expects NEWLINE-separated networks, not comma-separated
    networks_field = row.get('networks', '')
    if isinstance(networks_field, list):
        # Join list items with commas first, then split and rejoin with newlines
        networks_str = ', '.join([str(n).strip() for n in networks_field if n])
        networks = '\n'.join([n.strip() for n in networks_str.replace(';', ',').split(',') if n.strip()])
    else:
        # Convert comma/semicolon separated to newline separated
        networks_str = str(networks_field).strip()
        if networks_str:
            networks = '\n'.join([n.strip() for n in networks_str.replace(';', ',').split(',') if n.strip()])
        else:
            networks = ''
    
    excluded_networks_field = row.get('excluded_networks', '')
    if isinstance(excluded_networks_field, list):
        # Join list items with commas first, then split and rejoin with newlines
        excluded_str = ', '.join([str(n).strip() for n in excluded_networks_field if n])
        excluded_networks = '\n'.join([n.strip() for n in excluded_str.replace(';', ',').split(',') if n.strip()])
    else:
        # Convert comma/semicolon separated to newline separated
        excluded_str = str(excluded_networks_field).strip()
        if excluded_str:
            excluded_networks = '\n'.join([n.strip() for n in excluded_str.replace(';', ',').split(',') if n.strip()])
        else:
            excluded_networks = ''
    
    # Provider handling:
    # - New scans: use credential_provider_id_NEW_ONLY
    # - Existing scans: allow optional provider change using the same column
    provider_id = str(row.get('credential_provider_id_NEW_ONLY', '')).strip()
    
    # Basic scan data structure 
    scan_data = {
        'name': str(row['name']).strip(),
        'description': str(row.get('description', '')).strip(),
        'cron': str(row.get('cron', '')).strip() or None,
        'timezone': str(row.get('timezone', 'America/New_York')).strip(),  # Fixed default
        'site_id': str(row.get('site_id', '')).strip(),
        'provider_id': provider_id,
        'networks': networks,
        'excluded_networks': excluded_networks,
        'start_date': str(row.get('start_date', '')).strip(),
        'start_time': str(row.get('start_time', '')).strip(),
        'snmp': {
            'username': str(row.get('snmp_username', '')).strip(),
            'passphrase': str(row.get('snmp_passphrase', '')).strip(),
            'protocol': str(row.get('snmp_protocol', '')).strip(),
            'context_name': str(row.get('snmp_context_name', '')).strip(),
            'privacy_passphrase': str(row.get('snmp_privacy_passphrase', '')).strip(),
            'privacy_protocol': str(row.get('snmp_privacy_protocol', '')).strip(),
            'communities': str(row.get('snmp_communities', '')).replace(';', ',').replace(' ', '').strip()
        },
        'scan_options': {
            "file": "standard",
            "default": True,
            "display_name": "Standard xIoT Enterprise Discovery",
            "description": "This is the default Phosphorus Active xIoT Discovery Agenda that employs a tiered approach to progressively discover xIoT devices in your environment."
        }
    }
    # Remove provider_id if empty
    if not provider_id:
        scan_data.pop('provider_id', None)
    return scan_data

# --- PHOSPHORUS INFO FUNCTIONS ---
# List all sites registered on the platform.
def get_available_sites() -> list:
    """Retrieve all available sites from Phosphorus.

    Returns:
        Sorted list of site dicts (by name), or empty list on failure.
    """
    logger.info("Retrieving available sites...")
    response = make_api_request('GET', 'sites', api_version='v2', params={'limit': 1000})
    if response and response.get('success'):
        sites = response.get('items', [])
        logger.info(f"Found {len(sites)} sites")
        return sorted(sites, key=lambda x: x.get('name', '').lower())
    else:
        logger.error("Failed to retrieve sites")
        return []

# List all credential providers configured on the platform.
def get_available_credential_providers() -> list:
    """Retrieve all available credential providers from Phosphorus.

    Returns:
        Sorted list of provider dicts (by name), or empty list on failure.
    """
    logger.info("Retrieving available credential providers...")
    response = make_api_request('GET', 'providers', api_version='v3')
    if response:
        # v3 API returns a list directly
        if isinstance(response, list):
            providers = response
        else:
            # Fallback for v2-like structure
            providers = response.get('items', [])
        logger.info(f"Found {len(providers)} credential providers")
        return sorted(providers, key=lambda x: x.get('name', '').lower())
    else:
        logger.error("Failed to retrieve credential providers")
        return []

# Print a formatted overview of sites and credential providers to stdout.
def display_phosphorus_info(api_host: str, api_key: str) -> None:
    """Display available sites and credential providers with their IDs.

    Useful for discovering the ``site_id`` and
    ``credential_provider_id_NEW_ONLY`` values needed in the input CSV.

    Args:
        api_host: Phosphorus API hostname.
        api_key: API authentication key.
    """
    print("\n" + "="*80)
    print("PHOSPHORUS SYSTEM INFORMATION")
    print("="*80)
    print(f"API Host: {api_host}")
    print("="*80)
    
    # Set up environment for API calls
    os.environ['PHO_API_HOST'] = api_host
    os.environ['PHO_API_KEY'] = api_key
    
    # Get sites
    print("\n📍 AVAILABLE SITES:")
    print("-" * 50)
    sites = get_available_sites()
    if sites:
        print(f"{'Name':<40} {'ID'}")
        print("-" * 50)
        for site in sites:
            name = site.get('name', 'Unknown')
            site_id = site.get('id', 'Unknown')
            print(f"{name:<40} {site_id}")
    else:
        print("❌ No sites found or failed to retrieve sites")
    
    # Get credential providers
    print(f"\n🔑 AVAILABLE CREDENTIAL PROVIDERS:")
    print("-" * 50)
    providers = get_available_credential_providers()
    if providers:
        print(f"{'Name':<40} {'ID'}")
        print("-" * 50)
        for provider in providers:
            name = provider.get('name', 'Unknown')
            provider_id = provider.get('id', 'Unknown')
            print(f"{name:<40} {provider_id}")
    else:
        print("❌ No credential providers found or failed to retrieve providers")
    
    print("\n" + "="*80)
    print("💡 USAGE TIPS:")
    print("- Copy the Site ID to use in the 'site_id' column of your CSV")
    print("- Copy the Credential Provider ID to use in the 'credential_provider_id_NEW_ONLY' column")
    print("- Use these IDs exactly as shown (they are case-sensitive)")
    print("="*80 + "\n")

# --- TEMPLATE FUNCTIONS ---
# Generate a blank CSV template with sample rows for tags and scans.
def create_csv_template(filename: str) -> None:
    """Create a CSV template file with all required headers.

    Includes sample rows demonstrating tag, scheduled-scan, run-now-only,
    and combined (scheduled + run-now) scan configurations.

    Args:
        filename: Output CSV file path.
    """
    headers = [
        'type',
        'name', 
        'description',
        'color',
        'query',
        'run_now',
        'cron',
        'timezone',
        'site_id',
        'credential_provider_id_NEW_ONLY',
        'networks',
        'excluded_networks',
        'start_date',
        'start_time',
        'snmp_username',
        'snmp_passphrase',
        'snmp_protocol',
        'snmp_context_name',
        'snmp_communities',
        'snmp_privacy_protocol',
        'snmp_privacy_passphrase'
    ]
    
    sample_rows = [
        # Tag example
        [
            'tag',
            'Example-Tag-Name',
            'Example tag description for device categorization',
            '#FF5733',
            'Manufacturer="Cisco" AND type="Router"',
            '',  # run_now - not used for tags
            '',  # cron - not used for tags
            '',  # timezone - not used for tags
            '',  # site_id - not used for tags
            '',  # credential_provider_id_NEW_ONLY - not used for tags
            '',  # networks - not used for tags
            '',  # excluded_networks - not used for tags
            '',  # start_date - not used for tags
            '',  # start_time - not used for tags
            '',  # snmp_username - not used for tags
            '',  # snmp_passphrase - not used for tags
            '',  # snmp_protocol - not used for tags
            '',  # snmp_context_name - not used for tags
            '',  # snmp_communities - not used for tags
            '',  # snmp_privacy_protocol - not used for tags
            ''   # snmp_privacy_passphrase - not used for tags
        ],
        # Scheduled scan example
        [
            'scan',
            'Example-Scheduled-Scan',
            '',  # description - not used for scans
            '',  # color - not used for scans
            '',  # query - not used for scans
            'no',  # run_now - scheduled only
            '0 0 1 * *',  # cron - monthly on 1st at midnight
            'America/New_York',
            'your-site-id-here',
            'your-credential-provider-id-here',
            '192.168.1.0/24, 10.0.0.0/8',
            '192.168.1.1/32',
            '12/1/24',
            '02:00',
            'snmp_user',
            'snmp_password',
            'SHA',
            'context_name',
            'public, private',
            'AES',
            'privacy_password'
        ],
        # Run-now only scan example
        [
            'scan',
            'Example-RunNow-Only-Scan',
            '',  # description - not used for scans
            '',  # color - not used for scans
            '',  # query - not used for scans
            'only',  # run_now - run now only
            '',  # cron - not needed for run-now only
            'America/New_York',
            'your-site-id-here',
            'your-credential-provider-id-here',
            '192.168.2.0/24',
            '',  # excluded_networks
            '',  # start_date - auto-generated for run-now
            '',  # start_time - auto-generated for run-now
            '',  # snmp_username
            '',  # snmp_passphrase
            '',  # snmp_protocol
            '',  # snmp_context_name
            'public',  # snmp_communities
            '',  # snmp_privacy_protocol
            ''   # snmp_privacy_passphrase
        ],
        # Both scheduled and run-now scan example
        [
            'scan',
            'Example-Both-Scan',
            '',  # description - not used for scans
            '',  # color - not used for scans
            '',  # query - not used for scans
            'yes',  # run_now - both scheduled and run-now
            '0 0 * * 0',  # cron - weekly on Sunday at midnight
            'America/New_York',
            'your-site-id-here',
            'your-credential-provider-id-here',
            '10.0.0.0/24',
            '',  # excluded_networks
            '',  # start_date
            '',  # start_time
            '',  # snmp_username
            '',  # snmp_passphrase
            '',  # snmp_protocol
            '',  # snmp_context_name
            'public, private',  # snmp_communities
            '',  # snmp_privacy_protocol
            ''   # snmp_privacy_passphrase
        ]
    ]
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            writer.writerows(sample_rows)
        
        print(f"✓ CSV template created successfully: {filename}")
        print("\nTemplate includes:")
        print("  - Header row with all required columns")
        print("  - Example tag row (type='tag')")
        print("  - Example scheduled scan row (run_now='no')")
        print("  - Example run-now only scan row (run_now='only')")
        print("  - Example both scheduled and run-now scan row (run_now='yes')")
        print("\nKey notes:")
        print("  - For tags: only 'type', 'name', 'description', 'color', and 'query' are required")
        print("  - For new scans: 'credential_provider_id_NEW_ONLY' is required")
        print("  - For existing scans: leave 'credential_provider_id_NEW_ONLY' empty")
        print("  - Networks can be comma-separated: '192.168.1.0/24, 10.0.0.0/8'")
        print("  - SNMP communities can be comma-separated: 'public, private'")
        print("  - Cron format: 'minute hour day month dayofweek' (e.g., '0 0 1 * *' = monthly)")
        print("\nRun Now Options (run_now column):")
        print("  - 'no': Creates/updates only scheduled scan (default behavior)")
        print("  - 'only': Creates only run-now scan (immediate execution, no scheduling)")
        print("  - 'yes': Creates/updates scheduled scan AND creates run-now scan")
        print("  - For 'only' option: cron field is not required")
        print("  - For 'no' and 'yes' options: cron field is required")
        
    except Exception as e:
        print(f"✗ Error creating template: {str(e)}")
        sys.exit(1)

# Generate a pre-filled CSV from currently scheduled scans on the platform.
def create_template_from_system_scans(api_host: str, api_key: str) -> None:
    """Create a CSV template from current scheduled scans.

    Fetches every scheduled scan from the API, converts each to a CSV
    row, and writes the result.  Warns if SNMP passwords are exported.

    Args:
        api_host: Phosphorus API hostname.
        api_key: API authentication key.
    """
    print("Fetching scheduled scans to create template...")
    
    # Set up environment for API calls
    os.environ['PHO_API_HOST'] = api_host
    os.environ['PHO_API_KEY'] = api_key
    
    try:
        # Get scheduled scans
        scheduled_response = make_api_request(
            'GET',
            'actions/groups/combined',
            api_version='v3',
            params={
                'limit': 1000,
                'offset': 0,
                'sortBy': 'next_run',
                'sortDir': 'desc',
                'view': 'scheduled',
                'type': 'scan_devices'
            }
        )
        
        if not scheduled_response or 'rows' not in scheduled_response:
            print("No scheduled scans found or error retrieving scans.")
            return
        
        scheduled_scans = scheduled_response.get('rows', [])
        if not scheduled_scans:
            print("No scheduled scans found to create template from.")
            return
        
        print(f"Found {len(scheduled_scans)} scheduled scans")
        
        # Generate filename with hostname
        hostname = api_host.split('.')[0] if '.' in api_host else api_host
        filename = f"{hostname}-system-scans-input-file.csv"
        
        # CSV headers matching the template format
        headers = [
            'type',
            'name', 
            'description',
            'color',
            'query',
            'run_now',
            'cron',
            'timezone',
            'site_id',
            'credential_provider_id_NEW_ONLY',
            'networks',
            'excluded_networks',
            'start_date',
            'start_time',
            'snmp_username',
            'snmp_passphrase',
            'snmp_protocol',
            'snmp_context_name',
            'snmp_communities',
            'snmp_privacy_protocol',
            'snmp_privacy_passphrase'
        ]
        
        # Collect scan data and track password presence
        scan_rows = []
        has_snmp_passwords = False
        
        for scan in scheduled_scans:
            scan_id = scan.get('id')
            if scan_id:
                # Get detailed scan information
                detailed_scan = make_api_request('GET', f'scans/{scan_id}', api_version='v3')
                if detailed_scan:
                    scan_row = convert_scan_to_csv_row(detailed_scan)
                    scan_rows.append(scan_row)
                    
                    # Check if this scan has SNMP passwords
                    snmp_data = detailed_scan.get('options', {}).get('snmp', {})
                    if snmp_data.get('passphrase') or snmp_data.get('privacy_passphrase'):
                        has_snmp_passwords = True
        
        # Write to CSV file
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            writer.writerows(scan_rows)
        
        print(f"✓ Template created from {len(scan_rows)} scheduled scans: {filename}")
        print("\nTemplate notes:")
        print("  - All scans are set to type='scan' and run_now='no' (scheduled only)")
        print("  - credential_provider_id_NEW_ONLY is left empty (for existing scans)")
        print("  - Edit the CSV as needed and use --input-csv to apply changes")
        
        # Security warning if passwords are present
        if has_snmp_passwords:
            print("\n⚠️  SECURITY WARNING:")
            print("  - SNMP passwords have been exported to the CSV file")
            print("  - Please safeguard this file and restrict access appropriately")
            print("  - Consider removing passwords from CSV if sharing with others")
        else:
            print("  - No SNMP passwords found in the exported scans")
        
    except Exception as e:
        print(f"✗ Error creating template from system scans: {str(e)}")
        logger.error(f"Error in create_template_from_system_scans: {str(e)}")
        sys.exit(1)

# Generate a pre-filled CSV from both scheduled scans and tags.
def create_template_from_system_all(api_host: str, api_key: str) -> None:
    """Create a CSV template from current scheduled scans and tags.

    Combines scan and tag data into a single CSV for full-system export.
    Warns if SNMP passwords are exported.

    Args:
        api_host: Phosphorus API hostname.
        api_key: API authentication key.
    """
    print("Fetching scheduled scans and tags to create template...")
    
    # Set up environment for API calls
    os.environ['PHO_API_HOST'] = api_host
    os.environ['PHO_API_KEY'] = api_key
    
    try:
        # Get scheduled scans
        scheduled_response = make_api_request(
            'GET',
            'actions/groups/combined',
            api_version='v3',
            params={
                'limit': 1000,
                'offset': 0,
                'sortBy': 'next_run',
                'sortDir': 'desc',
                'view': 'scheduled',
                'type': 'scan_devices'
            }
        )
        
        # Get tags
        tags_response = make_api_request('GET', 'tag', params={'limit': 1000})
        
        # Generate filename with hostname
        hostname = api_host.split('.')[0] if '.' in api_host else api_host
        filename = f"{hostname}-system-all-input-file.csv"
        
        # CSV headers matching the template format
        headers = [
            'type',
            'name', 
            'description',
            'color',
            'query',
            'run_now',
            'cron',
            'timezone',
            'site_id',
            'credential_provider_id_NEW_ONLY',
            'networks',
            'excluded_networks',
            'start_date',
            'start_time',
            'snmp_username',
            'snmp_passphrase',
            'snmp_protocol',
            'snmp_context_name',
            'snmp_communities',
            'snmp_privacy_protocol',
            'snmp_privacy_passphrase'
        ]
        
        # Collect all data
        all_rows = []
        has_snmp_passwords = False
        
        # Process scheduled scans
        if scheduled_response and 'rows' in scheduled_response:
            scheduled_scans = scheduled_response.get('rows', [])
            print(f"Found {len(scheduled_scans)} scheduled scans")
            
            for scan in scheduled_scans:
                scan_id = scan.get('id')
                if scan_id:
                    # Get detailed scan information
                    detailed_scan = make_api_request('GET', f'scans/{scan_id}', api_version='v3')
                    if detailed_scan:
                        scan_row = convert_scan_to_csv_row(detailed_scan)
                        all_rows.append(scan_row)
                        
                        # Check if this scan has SNMP passwords
                        snmp_data = detailed_scan.get('options', {}).get('snmp', {})
                        if snmp_data.get('passphrase') or snmp_data.get('privacy_passphrase'):
                            has_snmp_passwords = True
        else:
            print("No scheduled scans found")
        
        # Process tags
        if tags_response and tags_response.get('success'):
            tags = tags_response.get('tags', [])
            print(f"Found {len(tags)} tags")
            
            for tag in tags:
                tag_row = convert_tag_to_csv_row(tag)
                all_rows.append(tag_row)
        else:
            print("No tags found")
        
        # Write to CSV file
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            writer.writerows(all_rows)
        
        scan_count = len([row for row in all_rows if row[0] == 'scan'])
        tag_count = len([row for row in all_rows if row[0] == 'tag'])
        
        print(f"✓ Template created with {scan_count} scans and {tag_count} tags: {filename}")
        print("\nTemplate notes:")
        print("  - All scans are set to type='scan' and run_now='no' (scheduled only)")
        print("  - All tags are set to type='tag' with existing configurations")
        print("  - credential_provider_id_NEW_ONLY is left empty (for existing items)")
        print("  - Edit the CSV as needed and use --input-csv to apply changes")
        
        # Security warning if passwords are present
        if has_snmp_passwords:
            print("\n⚠️  SECURITY WARNING:")
            print("  - SNMP passwords have been exported to the CSV file")
            print("  - Please safeguard this file and restrict access appropriately")
            print("  - Consider removing passwords from CSV if sharing with others")
        else:
            print("  - No SNMP passwords found in the exported scans")
        
    except Exception as e:
        print(f"✗ Error creating template from system all: {str(e)}")
        logger.error(f"Error in create_template_from_system_all: {str(e)}")
        sys.exit(1)

# Generate a pre-filled CSV from current tags only.
def create_template_from_system_tags(api_host: str, api_key: str) -> None:
    """Create a CSV template from current tags only.

    Fetches all tags from the API and converts them to CSV rows.

    Args:
        api_host: Phosphorus API hostname.
        api_key: API authentication key.
    """
    print("Fetching tags to create template...")
    
    # Set up environment for API calls
    os.environ['PHO_API_HOST'] = api_host
    os.environ['PHO_API_KEY'] = api_key
    
    try:
        # Get tags
        tags_response = make_api_request('GET', 'tag', params={'limit': 1000})
        
        if not tags_response or not tags_response.get('success'):
            print("No tags found or error retrieving tags.")
            return
        
        tags = tags_response.get('tags', [])
        if not tags:
            print("No tags found to create template from.")
            return
        
        print(f"Found {len(tags)} tags")
        
        # Generate filename with hostname
        hostname = api_host.split('.')[0] if '.' in api_host else api_host
        filename = f"{hostname}-system-tags-input-file.csv"
        
        # CSV headers matching the template format
        headers = [
            'type',
            'name', 
            'description',
            'color',
            'query',
            'run_now',
            'cron',
            'timezone',
            'site_id',
            'credential_provider_id_NEW_ONLY',
            'networks',
            'excluded_networks',
            'start_date',
            'start_time',
            'snmp_username',
            'snmp_passphrase',
            'snmp_protocol',
            'snmp_context_name',
            'snmp_communities',
            'snmp_privacy_protocol',
            'snmp_privacy_passphrase'
        ]
        
        # Collect tag data
        tag_rows = []
        for tag in tags:
            tag_row = convert_tag_to_csv_row(tag)
            tag_rows.append(tag_row)
        
        # Write to CSV file
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            writer.writerows(tag_rows)
        
        print(f"✓ Template created from {len(tag_rows)} tags: {filename}")
        print("\nTemplate notes:")
        print("  - All items are set to type='tag' with existing configurations")
        print("  - Edit the CSV as needed and use --input-csv to apply changes")
        
    except Exception as e:
        print(f"✗ Error creating template from system tags: {str(e)}")
        logger.error(f"Error in create_template_from_system_tags: {str(e)}")
        sys.exit(1)

# Map a tag API object to a flat list matching the CSV column order.
def convert_tag_to_csv_row(tag_data: Dict[str, Any]) -> list:
    """Convert a tag API response to CSV template row format.

    Scan-specific columns are left blank.

    Args:
        tag_data: Tag dict from the API.

    Returns:
        Ordered list of field values matching the CSV header layout.
    """
    
    # Extract tag information
    tag_name = str(tag_data.get('name', ''))
    description = str(tag_data.get('description', ''))
    color = str(tag_data.get('color', ''))
    query = str(tag_data.get('query', ''))
    
    # Build the CSV row - tags don't use most scan-specific fields
    row = [
        'tag',                    # type
        tag_name,                 # name
        description,              # description
        color,                    # color
        query,                    # query
        '',                       # run_now (not applicable for tags)
        '',                       # cron (not applicable for tags)
        '',                       # timezone (not applicable for tags)
        '',                       # site_id (not applicable for tags)
        '',                       # credential_provider_id_NEW_ONLY
        '',                       # networks (not applicable for tags)
        '',                       # excluded_networks (not applicable for tags)
        '',                       # start_date (not applicable for tags)
        '',                       # start_time (not applicable for tags)
        '',                       # snmp_username (not applicable for tags)
        '',                       # snmp_passphrase (not applicable for tags)
        '',                       # snmp_protocol (not applicable for tags)
        '',                       # snmp_context_name (not applicable for tags)
        '',                       # snmp_communities (not applicable for tags)
        '',                       # snmp_privacy_protocol (not applicable for tags)
        ''                        # snmp_privacy_passphrase (not applicable for tags)
    ]
    
    return row

# Map a scan API object to a flat list matching the CSV column order.
def convert_scan_to_csv_row(scan_data: Dict[str, Any]) -> list:
    """Convert a scan API response to CSV template row format.

    Extracts networks, SNMP settings, and schedule information from
    nested API structures into a flat ordered list.

    Args:
        scan_data: Full scan dict from the API.

    Returns:
        Ordered list of field values matching the CSV header layout.
    """
    
    # Extract networks
    networks = ''
    excluded_networks = ''
    options = scan_data.get('options', {})
    
    if 'networks' in options:
        network_data = options['networks']
        if isinstance(network_data, list):
            networks = ', '.join([str(n).strip() for n in network_data if n])
        elif network_data:
            networks = str(network_data).replace('\n', ', ')
    
    if 'excluded_networks' in options:
        excluded_network_data = options['excluded_networks']
        if isinstance(excluded_network_data, list):
            excluded_networks = ', '.join([str(n).strip() for n in excluded_network_data if n])
        elif excluded_network_data:
            excluded_networks = str(excluded_network_data).replace('\n', ', ')
    
    # Extract SNMP settings
    snmp_data = options.get('snmp', {})
    snmp_communities = ''
    if 'communities' in snmp_data and snmp_data['communities']:
        if isinstance(snmp_data['communities'], list):
            snmp_communities = ', '.join([str(c).strip() for c in snmp_data['communities'] if c])
        else:
            snmp_communities = str(snmp_data['communities']).replace(',', ', ')
    
    # Extract site ID
    site_id = ''
    if 'site' in scan_data and scan_data['site']:
        site_id = scan_data['site'].get('id', '')
    
    # Extract start date and time from options
    start_date = options.get('start_date', '')
    start_time = options.get('start_time', '')
    
    # Build CSV row
    row = [
        'scan',  # type
        scan_data.get('name', ''),  # name
        '',  # description (not used for scans)
        '',  # color (not used for scans)
        '',  # query (not used for scans)
        'no',  # run_now (scheduled only)
        scan_data.get('cron', ''),  # cron
        scan_data.get('timezone', ''),  # timezone
        site_id,  # site_id
        '',  # credential_provider_id_NEW_ONLY (empty for existing scans)
        networks,  # networks
        excluded_networks,  # excluded_networks
        start_date,  # start_date
        start_time,  # start_time
        snmp_data.get('username', ''),  # snmp_username
        snmp_data.get('passphrase', ''),  # snmp_passphrase
        snmp_data.get('protocol', ''),  # snmp_protocol
        snmp_data.get('context_name', ''),  # snmp_context_name
        snmp_communities,  # snmp_communities
        snmp_data.get('privacy_protocol', ''),  # snmp_privacy_protocol
        snmp_data.get('privacy_passphrase', '')  # snmp_privacy_passphrase
    ]
    
    return row

# Terminal-based interactive menu for users who prefer guided workflows.
def interactive_menu() -> None:
    """Simple interactive menu for common operations.

    Provides a loop-based CLI allowing the user to create templates,
    export scan data, process CSV files, display system info, or save
    credentials without memorising CLI flags.
    """
    banner = r":: P■  PHOSPHORUS  |  UNIFIED AUTOMATION INTERACTIVE ::"
    print("\n" + "=" * 80)
    print(banner.rstrip("\n"))
    print("=" * 80)

    def ask(prompt: str, required: bool = True, default: Optional[str] = None) -> str:
        """Prompt for text input with optional default value."""
        while True:
            suffix = f" [{default}]" if default else ""
            value = input(f"{prompt}{suffix}: ").strip()
            if not value and default is not None:
                return default
            if value or not required:
                return value
            print("Value is required.")

    def ask_bool(prompt: str, default: bool = False) -> bool:
        """Prompt for a yes/no answer."""
        default_text = "Y/n" if default else "y/N"
        value = input(f"{prompt} ({default_text}): ").strip().lower()
        if not value:
            return default
        return value in {"y", "yes", "true", "1"}

    def choose_from_menu(title: str, options: list, default_idx: Optional[int] = None) -> int:
        """Display numbered options and return selected index (0-based)."""
        print(f"\n{title}")
        for idx, label in enumerate(options, 1):
            default_marker = " (default)" if default_idx is not None and idx - 1 == default_idx else ""
            print(f"  {idx}) {label}{default_marker}")
        while True:
            raw = input("Select option number: ").strip()
            if not raw and default_idx is not None:
                return default_idx
            if raw.isdigit():
                num = int(raw)
                if 1 <= num <= len(options):
                    return num - 1
            print("Invalid selection. Please choose a valid number.")

    def choose_local_csv_file() -> str:
        """Prompt user to select a CSV file from current directory."""
        csv_files = sorted(
            [p.name for p in Path('.').glob('*.csv') if p.is_file()],
            key=lambda x: x.lower()
        )
        if not csv_files:
            print("No CSV files found in current directory.")
            return ask("Input CSV path")

        print("\nCSV files in current directory:")
        for idx, filename in enumerate(csv_files, 1):
            print(f"  {idx}) {filename}")
        print("  0) Enter a custom path")

        while True:
            selection = input("Select CSV file number: ").strip()
            if not selection.isdigit():
                print("Please enter a valid number.")
                continue
            selected_idx = int(selection)
            if selected_idx == 0:
                return ask("Input CSV path")
            if 1 <= selected_idx <= len(csv_files):
                chosen = csv_files[selected_idx - 1]
                print(f"Selected CSV: {chosen}")
                return chosen
            print("Selection out of range.")

    def get_credentials_from_env_or_prompt() -> tuple:
        """Load credentials from .env or prompt interactively."""
        env_data = parse_env_file()
        profiles = extract_env_profiles(env_data)
        selected = None
        if profiles:
            selected = choose_profile_interactively(profiles)
        if selected:
            api_host_local = selected['host']
            api_key_local = selected['api_key']
            print(f"Using profile host: {api_host_local}")
            return api_host_local, api_key_local

        api_host_local = ask("API host")
        api_key_local = ask("API key")
        if ask_bool("Save credentials to .env", default=True):
            profile = ask("Profile name", required=False, default="default")
            save_credentials_to_env(api_host_local, api_key_local, profile_name=profile)
            print(f"Saved credentials for profile '{profile}' to .env")
        return api_host_local, api_key_local

    while True:
        print("\nChoose an action:")
        print("")
        print("  1) Create CSV Template")
        print("  2) Export Scan Data")
        print("  3) Process CSV (update scans and/or tags)")
        print("  4) Display sites and credential providers")
        print("  5) Save/update API credentials in .env")
        print("  0) Exit")

        try:
            choice = input("\nEnter choice: ").strip()
        except KeyboardInterrupt:
            print("\nInput cancelled. Returning to menu.")
            continue

        try:
            if choice == "0":
                print("Exiting interactive mode.")
                return
            if choice == "1":
                template_idx = choose_from_menu(
                    "Template source:",
                    ["Sample template", "System scans", "System tags", "System scans & tags"],
                    default_idx=0
                )

                if template_idx == 0:
                    filename = ask("Template filename", default="template.csv")
                    create_csv_template(filename)
                else:
                    api_host, api_key = get_credentials_from_env_or_prompt()
                    if template_idx == 1:
                        create_template_from_system_scans(api_host, api_key)
                    elif template_idx == 2:
                        create_template_from_system_tags(api_host, api_key)
                    else:
                        create_template_from_system_all(api_host, api_key)
                continue

            if choice == "5":
                api_host = ask("API host")
                api_key = ask("API key")
                profile = ask("Profile name", required=False, default="default")
                save_credentials_to_env(api_host, api_key, profile_name=profile)
                print(f"Saved credentials for profile '{profile}' to .env")
                continue

            if choice == "3":
                # Process CSV needs credentials.
                api_host, api_key = get_credentials_from_env_or_prompt()
                input_csv = choose_local_csv_file()
                dry_run = ask_bool("Dry run", default=False)
                force_scan_update = ask_bool("Force update existing scans", default=False)
                ui_idx = choose_from_menu("UI mode:", ["Simple", "Bar", "Rich"], default_idx=0)
                ui_mode = ["simple", "bar", "rich"][ui_idx]
                config = Config(api_host, api_key, input_csv, dry_run, force_scan_update, ui_mode=ui_mode)
                process_unified_csv(config)
            elif choice == "2":
                # Export needs credentials.
                api_host, api_key = get_credentials_from_env_or_prompt()
                export_choice_idx = choose_from_menu("Export type:", ["Details", "History", "Scan Records"])

                if export_choice_idx == 0:
                    format_choice_idx = choose_from_menu("Details format:", ["Text", "CSV"], default_idx=0)
                    export_format = "csv" if format_choice_idx == 1 else "text"
                    if export_format == "csv":
                        output = ask("Output CSV filename", default="scan_details.csv")
                        dump_scan_details_to_csv(output, api_host, api_key)
                    else:
                        output = ask("Output text filename", default="scan_details.txt")
                        dump_scan_details_to_file(output, api_host, api_key)
                elif export_choice_idx == 1:
                    format_choice_idx = choose_from_menu("History format:", ["Text", "CSV"], default_idx=0)
                    export_format = "csv" if format_choice_idx == 1 else "text"
                    query = ask("Scan name query (optional)", required=False)
                    status = ask("Scan status (completed/canceled/failed/all)", default="completed")
                    use_days_ago = ask_bool("Use days-ago filter", default=True)
                    start_date = None
                    end_date = None
                    if use_days_ago:
                        days_ago_raw = ask("Days ago", default="7")
                        start_date, end_date = calculate_days_ago_range(int(days_ago_raw))
                    else:
                        start_raw = ask("Start date (MM-DD-YYYY or YYYY-MM-DD)", required=False)
                        end_raw = ask("End date (MM-DD-YYYY or YYYY-MM-DD)", required=False)
                        start_date = convert_date_format(start_raw) if start_raw else None
                        end_date = convert_date_format(end_raw) if end_raw else None
                    max_results = int(ask("Max results", default="500"))
                    if export_format == "csv":
                        output = ask("Output CSV filename", default="scan_history.csv")
                        dump_scan_history_to_csv(output, api_host, api_key, query or None, start_date, end_date, status, max_results)
                    else:
                        output = ask("Output text filename", default="scan_history.txt")
                        dump_scan_history_to_file(output, api_host, api_key, query or None, start_date, end_date, status, max_results)
                else:
                    mode_idx = choose_from_menu(
                        "Scan records output mode:",
                        ["JSONL", "CSV", "Send to Phosphorus"],
                        default_idx=0
                    )
                    output_mode = "jsonl" if mode_idx == 0 else "csv" if mode_idx == 1 else "send"

                    status = ask("Scan status (completed/canceled/failed/all)", default="completed")
                    query = ask("Scan name query (optional)", required=False)

                    use_days_ago = ask_bool("Use days-ago filter", default=True)
                    start_date = None
                    end_date = None
                    if use_days_ago:
                        days_ago_raw = ask("Days ago", default="7")
                        start_date, end_date = calculate_days_ago_range(int(days_ago_raw))
                    else:
                        start_raw = ask("Start date (MM-DD-YYYY or YYYY-MM-DD)", required=False)
                        end_raw = ask("End date (MM-DD-YYYY or YYYY-MM-DD)", required=False)
                        start_date = convert_date_format(start_raw) if start_raw else None
                        end_date = convert_date_format(end_raw) if end_raw else None

                    max_results = int(ask("Max scans", default="100"))
                    scope_idx = choose_from_menu(
                        "Record scope:",
                        ["All records (entire scan)", "Single category"],
                        default_idx=0
                    )

                    categories = None
                    if scope_idx == 1:
                        cat_idx = choose_from_menu(
                            "Category:",
                            ["profiled", "excluded", "unclassified", "unknown"],
                            default_idx=0
                        )
                        categories = [["profiled", "excluded", "unclassified", "unknown"][cat_idx]]

                    output_filename = None
                    if output_mode == "jsonl":
                        output_filename = ask("Output JSONL filename/prefix", default="scan_records.jsonl")
                        print("Note: local scan-record exports write one file per scan.")
                    elif output_mode == "csv":
                        output_filename = ask("Output CSV filename/prefix", default="scan_records.csv")
                        print("Note: local scan-record exports write one file per scan.")

                    export_raw_scan_records(
                        api_host=api_host,
                        api_key=api_key,
                        output_mode=output_mode,
                        categories=categories,
                        output_filename=output_filename,
                        name_filter=query or None,
                        start_date=start_date,
                        end_date=end_date,
                        max_results=max_results,
                        scan_status=status
                    )
            elif choice == "4":
                api_host, api_key = get_credentials_from_env_or_prompt()
                display_phosphorus_info(api_host, api_key)
            else:
                print("Invalid selection. Please choose a listed option.")
        except KeyboardInterrupt:
            print("\nInput cancelled. Returning to menu.")
            continue

# CLI entry point: parse arguments and dispatch to the appropriate workflow.
def main():
    """Parse CLI arguments and dispatch to the appropriate workflow.

    Supports template creation, scan export (details/history/records),
    system info display, credential management, interactive mode, and
    full CSV-driven tag/scan processing.
    """
    parser = argparse.ArgumentParser(
        description='Phosphorus Unified Automation Tool v6 - With Scan Export to Text or CSV',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SCAN/TAG CREATION:

  Create template:     %(prog)s --create-template template.csv
  Template from scans: %(prog)s --create-template-from-system-scans --api-host host --api-key key
  Template scans+tags: %(prog)s --create-template-from-system-all --api-host host --api-key key
  Template tags only:  %(prog)s --create-template-from-system-tags --api-host host --api-key key
  Process CSV:         %(prog)s --input-csv input.csv --api-host host --api-key key
  Dry run:             %(prog)s --input-csv input.csv --api-host host --api-key key --dry-run
  Get system info:     %(prog)s --phosphorus-info --api-host host --api-key key

SCAN SCHEDULE DETAILS:

  Current scans text:  %(prog)s --scan-details-text scan_report.txt --api-host host --api-key key
  Current scans CSV:   %(prog)s --scan-details-csv scan_report.csv --api-host host --api-key key

SCAN HISTORY:

  Basic history:       %(prog)s --scan-history-csv history.csv --api-host host --api-key key
  Filter by name:      %(prog)s --scan-history-csv history.csv --scan-name-query "Nightly" --api-host host --api-key key
  Last 7 days:         %(prog)s --scan-history-csv history.csv --days-ago 7 --api-host host --api-key key
  Date range:          %(prog)s --scan-history-text history.txt --start-date 01-01-2025 --end-date 01-31-2025 --api-host host --api-key key
  Canceled scans:      %(prog)s --scan-history-csv canceled.csv --scan-status canceled --api-host host --api-key key
  All scan types:      %(prog)s --scan-history-text all_scans.txt --scan-status all --api-host host --api-key key
  Large datasets:      %(prog)s --scan-history-csv large.csv --max-results 10000 --api-host host --api-key key
        """
    )
    parser.add_argument('--input-csv', help='Path to unified input CSV file')
    parser.add_argument('--api-host', help='Phosphorus API host')
    parser.add_argument('--api-key', help='Phosphorus API key')
    parser.add_argument('--dry-run', action='store_true', help='Run in dry-run mode (no changes made)')
    parser.add_argument('--create-template', metavar='FILENAME', help='Create a CSV template file with the specified name')
    parser.add_argument('--create-template-from-system-scans', action='store_true', help='Create a CSV template from current scheduled scans (filename: hostname-system-scans-input-file.csv)')
    parser.add_argument('--create-template-from-system-all', action='store_true', help='Create a CSV template from current scheduled scans and tags (filename: hostname-system-all-input-file.csv)')
    parser.add_argument('--create-template-from-system-tags', action='store_true', help='Create a CSV template from current tags only (filename: hostname-system-tags-input-file.csv)')
    parser.add_argument('--phosphorus-info', action='store_true', help='Display available sites and credential providers with their IDs')
    parser.add_argument('--scan-details-text', metavar='FILENAME', help='Fetch current scan job (active & scheduled) configurations and dump to text file')
    parser.add_argument('--scan-details-csv', metavar='FILENAME', help='Fetch current scan job (active & scheduled) configurations and dump to CSV file')
    parser.add_argument('--scan-history-text', metavar='FILENAME', help='Fetch completed scan job history and dump to text file')
    parser.add_argument('--scan-history-csv', metavar='FILENAME', help='Fetch completed scan job history and dump to CSV file')
    parser.add_argument('--scan-name-query', help='Filter scans by name (partial match) - used with scan history options')
    parser.add_argument('--start-date', help='Start date filter for scan history (MM-DD-YYYY or YYYY-MM-DD)')
    parser.add_argument('--end-date', help='End date filter for scan history (MM-DD-YYYY or YYYY-MM-DD)')
    parser.add_argument('--days-ago', type=int, help='Analyze scans from X days ago to today (alternative to start/end dates)')
    parser.add_argument('--scan-status', default='completed', help='Scan status filter: completed (default), canceled, failed, or all (case-insensitive)')
    parser.add_argument('--max-results', type=int, default=500, help='Maximum number of scans to retrieve (default: 500)')
    parser.add_argument('--interactive', action='store_true', help='Launch interactive menu mode')
    parser.add_argument('--force-scan-update', action='store_true', help='Force update existing scans instead of skipping unchanged ones')
    parser.add_argument('--silent', action='store_true', help='Suppress live progress output; print only final summary/errors')
    parser.add_argument('--profile-name', help='Credential profile name from .env (used when multiple profiles exist)')
    parser.add_argument('--save-credentials', action='store_true', help='Save --api-host and --api-key to .env')
    parser.add_argument('--insecure', action='store_true', help='Disable TLS certificate verification (not recommended)')
    parser.add_argument('--request-timeout', type=int, default=30, help='API request timeout in seconds (default: 30)')
    parser.add_argument('--max-retries', type=int, default=3, help='Maximum retries for transient API errors (default: 3)')
    args = parser.parse_args()

    global REQUEST_TIMEOUT, MAX_RETRIES, ALLOW_INSECURE_TLS
    REQUEST_TIMEOUT = max(1, int(args.request_timeout))
    MAX_RETRIES = max(1, int(args.max_retries))
    ALLOW_INSECURE_TLS = args.insecure

    if args.interactive:
        interactive_menu()
        return

    if args.save_credentials:
        if not args.api_host or not args.api_key:
            parser.error("--save-credentials requires both --api-host and --api-key")
        target_profile = args.profile_name if args.profile_name else "default"
        save_credentials_to_env(args.api_host, args.api_key, profile_name=target_profile)
        print(f"✓ Saved credentials for profile '{target_profile}' to .env")
        return
    
    # Handle template creation
    if args.create_template:
        create_csv_template(args.create_template)
        return
    
    # Handle template creation from system scans
    if args.create_template_from_system_scans:
        api_host, api_key = resolve_api_credentials(args, parser)
        create_template_from_system_scans(api_host, api_key)
        return
    
    # Handle template creation from system all (scans + tags)
    if args.create_template_from_system_all:
        api_host, api_key = resolve_api_credentials(args, parser)
        create_template_from_system_all(api_host, api_key)
        return
    
    # Handle template creation from system tags only
    if args.create_template_from_system_tags:
        api_host, api_key = resolve_api_credentials(args, parser)
        create_template_from_system_tags(api_host, api_key)
        return
    
    # Handle phosphorus info display
    if args.phosphorus_info:
        api_host, api_key = resolve_api_credentials(args, parser)
        display_phosphorus_info(api_host, api_key)
        return
    
    # Handle scan details export (text format)
    if args.scan_details_text:
        api_host, api_key = resolve_api_credentials(args, parser)
        dump_scan_details_to_file(args.scan_details_text, api_host, api_key)
        return
    
    # Handle scan details export (CSV format)
    if args.scan_details_csv:
        api_host, api_key = resolve_api_credentials(args, parser)
        dump_scan_details_to_csv(args.scan_details_csv, api_host, api_key)
        return
    
    # Handle scan history export (text format)
    if args.scan_history_text:
        api_host, api_key = resolve_api_credentials(args, parser)
        
        # Handle date logic - days_ago takes precedence over explicit dates
        start_date = None
        end_date = None
        
        if args.days_ago is not None:
            if args.start_date or args.end_date:
                print("Warning: Both --days-ago and explicit dates provided. Using --days-ago.")
            start_date, end_date = calculate_days_ago_range(args.days_ago)
            print(f"Analyzing scans from {args.days_ago} days ago ({start_date}) to today ({end_date})")
        else:
            # Convert explicit date formats if provided
            start_date = convert_date_format(args.start_date) if args.start_date else None
            end_date = convert_date_format(args.end_date) if args.end_date else None
        
        dump_scan_history_to_file(args.scan_history_text, api_host, api_key,
                                 args.scan_name_query, start_date, end_date, args.scan_status, args.max_results)
        return
    
    # Handle scan history export (CSV format)
    if args.scan_history_csv:
        api_host, api_key = resolve_api_credentials(args, parser)
        
        # Handle date logic - days_ago takes precedence over explicit dates
        start_date = None
        end_date = None
        
        if args.days_ago is not None:
            if args.start_date or args.end_date:
                print("Warning: Both --days-ago and explicit dates provided. Using --days-ago.")
            start_date, end_date = calculate_days_ago_range(args.days_ago)
            print(f"Analyzing scans from {args.days_ago} days ago ({start_date}) to today ({end_date})")
        else:
            # Convert explicit date formats if provided
            start_date = convert_date_format(args.start_date) if args.start_date else None
            end_date = convert_date_format(args.end_date) if args.end_date else None
        
        dump_scan_history_to_csv(args.scan_history_csv, api_host, api_key,
                                args.scan_name_query, start_date, end_date, args.scan_status, args.max_results)
        return
    
    # For normal operation, require API credentials and input file
    if not args.input_csv:
        parser.error("--input-csv is required (unless using --create-template, --create-template-from-system-scans, --create-template-from-system-all, --create-template-from-system-tags, --phosphorus-info, --scan-details-text, --scan-details-csv, --scan-history-text, or --scan-history-csv)")
    api_host, api_key = resolve_api_credentials(args, parser)

    config = Config(api_host, api_key, args.input_csv, args.dry_run, args.force_scan_update, ui_mode='simple', silent=args.silent)
    
    start_time = datetime.now()
    logger.info("Starting Phosphorus Unified Automation v6")
    if config.dry_run:
        logger.info("Running in DRY RUN mode - no changes will be made")
    logger.info(f"Processing unified input file: {args.input_csv}")
    process_unified_csv(config)
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\nScript completed in {int(duration.total_seconds())} seconds\n")

if __name__ == "__main__":
    main() 