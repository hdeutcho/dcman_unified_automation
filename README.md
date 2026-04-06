# Phosphorus Unified Automation Tool v6

A production-grade CLI tool for automating **IoT/OT device management** on the [Phosphorus](https://www.phosphorus.io/) xIoT platform. Manage tags, schedule scans, export scan history, and handle SNMP credentials — all from a single unified CSV workflow.

---

## Table of Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [How-To Guides](#how-to-guides)
  - [Create a CSV Template](#1-create-a-csv-template)
  - [Process a CSV (Tags & Scans)](#2-process-a-csv-tags--scans)
  - [Export Scan Details](#3-export-current-scan-details)
  - [Export Scan History](#4-export-scan-history)
  - [Manage Credential Profiles](#5-manage-credential-profiles)
  - [Use Interactive Mode](#6-use-interactive-mode)
  - [Display System Info](#7-display-system-info)
- [CSV Format Reference](#csv-format-reference)
- [API Reference](#api-reference)
- [Logging & Error Recovery](#logging--error-recovery)
- [CLI Reference](#cli-reference)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CLI / Interactive Menu                      │
│  argparse dispatcher  ·  --interactive guided menu                  │
└──────────┬──────────────────────┬───────────────────┬───────────────┘
           │                      │                   │
     ┌─────▼─────┐        ┌──────▼──────┐     ┌──────▼──────┐
     │  Unified   │        │  Scan Export │     │  Template   │
     │  CSV       │        │  Engine      │     │  Generator  │
     │  Pipeline  │        │              │     │             │
     └─────┬──────┘        └──────┬───────┘     └──────┬──────┘
           │                      │                    │
     ┌─────▼──────────────────────▼────────────────────▼──────┐
     │                   Core Services                         │
     │  ┌──────────┐  ┌──────────┐  ┌────────────┐            │
     │  │   Tag    │  │   Scan   │  │  Credential│            │
     │  │  Manager │  │  Manager │  │  Profiles  │            │
     │  └────┬─────┘  └────┬─────┘  └─────┬──────┘            │
     └───────┼─────────────┼───────────────┼───────────────────┘
             │             │               │
     ┌───────▼─────────────▼───────────────▼───────────────────┐
     │                 API Communication Layer                  │
     │  make_api_request()  ·  retry logic  ·  data redaction   │
     │  Transient error retry (429, 5xx)  ·  Exp. backoff       │
     └────────────────────────┬────────────────────────────────┘
                              │  HTTPS
                    ┌─────────▼──────────┐
                    │  Phosphorus xIoT   │
                    │  Platform API      │
                    │  v2 (tags/sites)   │
                    │  v3 (scans/history)│
                    └────────────────────┘

  Supporting Subsystems:
  ┌──────────────┐  ┌────────────────┐  ┌────────────────────┐
  │ InputValidator│  │ ProgressRenderer│  │ Rotating File Logger│
  │ CIDR, cron,  │  │ simple│bar│rich │  │ DEBUG→file         │
  │ color, fields│  │ live stats      │  │ WARNING+→console   │
  └──────────────┘  └────────────────┘  └────────────────────┘
```

### Component Overview

| Component | Purpose |
|-----------|---------|
| **CLI Dispatcher** | Parses `argparse` arguments and routes to the correct workflow |
| **Unified CSV Pipeline** | Three-phase processor: fetch state → diff → create/update tags & scans |
| **Scan Export Engine** | Exports active scan configurations and paginated scan history |
| **Template Generator** | Produces blank or system-populated CSV templates |
| **Tag Manager** | Idempotent create/update of platform tags via the v2 API |
| **Scan Manager** | Idempotent create/update of scheduled and run-now scans via the v3 API |
| **Credential Profiles** | Multi-profile `.env` storage with interactive profile selection |
| **API Layer** | Centralized HTTP client with retry, backoff, timeout, and sensitive-data redaction |
| **InputValidator** | Validates CIDR networks, cron expressions, hex colors, and required fields |
| **ProgressRenderer** | Pluggable progress UI — simple spinner, `tqdm` bar, or `rich` console |

### Processing Pipeline

The main CSV processing workflow (`process_unified_csv`) runs in three phases:

```
Phase 1 ─ Fetch existing tags from API        → Dict[name → tag]
Phase 2 ─ Fetch existing scheduled scans      → Dict[name → scan]
Phase 3 ─ Iterate CSV rows:
           ├─ type=tag  → validate → compare → create/update tag
           └─ type=scan → validate → compare → create/update scan
                          ├─ run_now='no'   → scheduled scan only
                          ├─ run_now='yes'  → scheduled + immediate scan
                          └─ run_now='only' → immediate scan only
           └─ On failure → capture row → write retry CSV
```

Key design properties:
- **Idempotent** — safe to run repeatedly; unchanged resources are skipped
- **Dry-run** — preview all changes without executing them
- **Error recovery** — failed rows are saved to a `*-retry.csv` for re-processing

---

## Prerequisites

- **Python 3.8+**
- **Phosphorus API credentials** (host + API key)

## Installation

```bash
git clone git@github.com:hdeutcho/dcman_unified_automation.git
cd dcman_unified_automation

# Install required dependency
pip install requests

# Optional: enhanced progress UIs
pip install tqdm        # --ui-mode bar
pip install rich        # --ui-mode rich
```

---

## Quick Start

```bash
# 1. Save your credentials
python dcman_unified_automation.py \
  --save-credentials \
  --api-host your-instance.phosphorus.io \
  --api-key sk_your_api_key

# 2. Generate a CSV template from your current system
python dcman_unified_automation.py --create-template-from-system-all

# 3. Edit the generated CSV, then apply changes
python dcman_unified_automation.py --input-csv your-template.csv

# 4. Or launch interactive mode
python dcman_unified_automation.py --interactive
```

---

## Configuration

Credentials are resolved in this order:

1. **CLI arguments**: `--api-host` and `--api-key`
2. **Named profile**: `--profile-name` or `PHO_DEFAULT_PROFILE` in `.env`
3. **Single profile**: auto-selected when only one exists
4. **Interactive prompt**: when running in a TTY

### `.env` File

Single profile:
```env
PHO_API_HOST=your-instance.phosphorus.io
PHO_API_KEY=sk_your_api_key
```

Multiple profiles:
```env
PHO_PROFILE_PRODUCTION_HOST=prod.phosphorus.io
PHO_PROFILE_PRODUCTION_API_KEY=sk_prod_...
PHO_PROFILE_DEVELOPMENT_HOST=dev.phosphorus.io
PHO_PROFILE_DEVELOPMENT_API_KEY=sk_dev_...
PHO_PROFILE_NAMES=production,development
PHO_DEFAULT_PROFILE=production
```

### Global Defaults

| Constant | Default | Override |
|----------|---------|----------|
| `REQUEST_TIMEOUT` | 30s | `--request-timeout` |
| `MAX_RETRIES` | 3 | `--max-retries` |
| `ALLOW_INSECURE_TLS` | `False` | `--insecure` |

---

## How-To Guides

### 1. Create a CSV Template

**Blank template** with sample rows:
```bash
python dcman_unified_automation.py --create-template template.csv
```

**From current system scans** (generates a pre-filled CSV):
```bash
python dcman_unified_automation.py \
  --create-template-from-system-scans \
  --api-host host --api-key key
```

**From current tags only**:
```bash
python dcman_unified_automation.py \
  --create-template-from-system-tags \
  --api-host host --api-key key
```

**From scans + tags combined**:
```bash
python dcman_unified_automation.py \
  --create-template-from-system-all \
  --api-host host --api-key key
```

### 2. Process a CSV (Tags & Scans)

**Standard run** — creates or updates tags and scans:
```bash
python dcman_unified_automation.py \
  --input-csv input.csv \
  --api-host host --api-key key
```

**Dry run** — preview changes without modifying anything:
```bash
python dcman_unified_automation.py \
  --input-csv input.csv \
  --api-host host --api-key key \
  --dry-run
```

**Force update** — push all rows even if unchanged:
```bash
python dcman_unified_automation.py \
  --input-csv input.csv \
  --api-host host --api-key key \
  --force-scan-update
```

**With progress bar**:
```bash
python dcman_unified_automation.py \
  --input-csv input.csv \
  --api-host host --api-key key \
  --ui-mode bar
```

### 3. Export Current Scan Details

**Text report** of all active and scheduled scans:
```bash
python dcman_unified_automation.py \
  --scan-details-text scan_report.txt \
  --api-host host --api-key key
```

**CSV format**:
```bash
python dcman_unified_automation.py \
  --scan-details-csv scan_report.csv \
  --api-host host --api-key key
```

### 4. Export Scan History

**All completed scans**:
```bash
python dcman_unified_automation.py \
  --scan-history-csv history.csv \
  --api-host host --api-key key
```

**Last 7 days**:
```bash
python dcman_unified_automation.py \
  --scan-history-csv history.csv \
  --days-ago 7 \
  --api-host host --api-key key
```

**Date range**:
```bash
python dcman_unified_automation.py \
  --scan-history-text history.txt \
  --start-date 01-01-2025 --end-date 01-31-2025 \
  --api-host host --api-key key
```

**Filter by scan name**:
```bash
python dcman_unified_automation.py \
  --scan-history-csv history.csv \
  --scan-name-query "Nightly" \
  --api-host host --api-key key
```

**Filter by status** (`completed`, `canceled`, `failed`, or `all`):
```bash
python dcman_unified_automation.py \
  --scan-history-csv canceled.csv \
  --scan-status canceled \
  --api-host host --api-key key
```

**Large datasets** with custom limit:
```bash
python dcman_unified_automation.py \
  --scan-history-csv large.csv \
  --max-results 100000 \
  --api-host host --api-key key
```

### 5. Manage Credential Profiles

**Save credentials** under a named profile:
```bash
python dcman_unified_automation.py \
  --save-credentials \
  --api-host prod.phosphorus.io \
  --api-key sk_prod_... \
  --profile-name production
```

**Use a specific profile**:
```bash
python dcman_unified_automation.py \
  --input-csv config.csv \
  --profile-name production
```

When multiple profiles exist and no `--profile-name` is given, an interactive prompt appears.

### 6. Use Interactive Mode

```bash
python dcman_unified_automation.py --interactive
```

The interactive menu provides guided access to all features without memorising CLI flags.

### 7. Display System Info

```bash
python dcman_unified_automation.py \
  --phosphorus-info \
  --api-host host --api-key key
```

Shows available sites and credential providers on the platform.

---

## CSV Format Reference

### Headers

```
type, name, description, color, query, run_now, cron, timezone, site_id,
credential_provider_id_NEW_ONLY, networks, excluded_networks, start_date,
start_time, snmp_username, snmp_passphrase, snmp_protocol, snmp_context_name,
snmp_communities, snmp_privacy_protocol, snmp_privacy_passphrase
```

### Column Usage by Row Type

| Column | `type=tag` | `type=scan` |
|--------|-----------|-------------|
| `name` | **Required** | **Required** |
| `description` | **Required** | Optional |
| `color` | **Required** (hex) | — |
| `query` | **Required** | — |
| `run_now` | — | `no` / `yes` / `only` |
| `cron` | — | **Required** unless `run_now=only` |
| `timezone` | — | **Required** |
| `site_id` | — | **Required** |
| `networks` | — | **Required** (CIDR, comma-separated) |
| `excluded_networks` | — | Optional (CIDR) |
| `credential_provider_id_NEW_ONLY` | — | Required for new scans |
| `start_date` | — | Optional (MM-DD-YYYY) |
| `start_time` | — | Optional (HH:MM) |
| `snmp_*` | — | Optional SNMP configuration |

### Run-Now Modes

| Mode | Creates | Cron Required |
|------|---------|---------------|
| `no` (default) | 1 scheduled scan | Yes |
| `only` | 1 immediate scan | No |
| `yes` | 1 scheduled + 1 immediate scan | Yes |

---

## API Reference

### Endpoints Used

| API | Method | Endpoint | Operation |
|-----|--------|----------|-----------|
| Tags v2 | `GET` | `/api/v2/tag` | List all tags |
| Tags v2 | `PUT` | `/api/v2/tag` | Create tag |
| Tags v2 | `POST` | `/api/v2/tag/{id}` | Update tag |
| Scans v3 | `GET` | `/api/v3/actions/groups/combined` | List scans (scheduled/active/history) |
| Scans v3 | `GET` | `/api/v3/scans/{id}` | Get scan details |
| Scans v3 | `POST` | `/api/v3/scans` | Create scan |
| Scans v3 | `PUT` | `/api/v3/scans/{id}` | Update scan |
| Scans v3 | `GET` | `/api/v3/scans/{id}/records/export` | Export device records (JSONL/CSV) |
| Sites v2 | `GET` | `/api/v2/sites` | List sites |
| Providers v3 | `GET` | `/api/v3/providers` | List credential providers |

### Request Hardening

- **Retry**: Automatic retry with exponential backoff on `429` and `5xx` errors
- **Timeout**: Configurable per-request timeout (default 30s)
- **TLS**: Certificate verification enabled by default (`--insecure` to disable)
- **Redaction**: API keys, SNMP passwords, and passphrases are redacted in all logs

---

## Logging & Error Recovery

### Log Output

| Destination | Level | Format |
|-------------|-------|--------|
| Console (stderr) | `WARNING+` | Message only |
| `phosphorus_unified_automation.log` | `DEBUG+` | Timestamp + level + message |

Log files rotate at 10 MB with 2 backups.

### Error Recovery

When CSV processing encounters errors, failed rows are automatically saved to a retry file (e.g., `input-retry.csv`). The retry CSV includes an `error_message` column. Fix the issues and re-run:

```bash
python dcman_unified_automation.py \
  --input-csv input-retry.csv \
  --api-host host --api-key key
```

---

## CLI Reference

```
usage: dcman_unified_automation.py [options]

Template Creation:
  --create-template FILE              Generate blank CSV template
  --create-template-from-system-scans Export current scans to CSV template
  --create-template-from-system-tags  Export current tags to CSV template
  --create-template-from-system-all   Export scans + tags to CSV template

CSV Processing:
  --input-csv FILE                    Process unified CSV file
  --dry-run                           Preview changes without executing
  --force-scan-update                 Skip equality checks, force all updates

Scan Details Export:
  --scan-details-text FILE            Export active scans to text
  --scan-details-csv FILE             Export active scans to CSV

Scan History Export:
  --scan-history-text FILE            Export scan history to text
  --scan-history-csv FILE             Export scan history to CSV
  --scan-name-query STRING            Filter by scan name (partial match)
  --scan-status STATUS                Filter: completed|canceled|failed|all
  --start-date DATE                   Start date (MM-DD-YYYY)
  --end-date DATE                     End date (MM-DD-YYYY)
  --days-ago N                        Scans from the last N days
  --max-results N                     Maximum results to retrieve (default: 500)

System Info:
  --phosphorus-info                   Display sites and credential providers

Credentials:
  --api-host HOST                     Phosphorus API hostname
  --api-key KEY                       Phosphorus API key
  --save-credentials                  Save credentials to .env file
  --profile-name NAME                 Named credential profile

UI & Behavior:
  --interactive                       Launch guided interactive menu
  --silent                            Suppress progress output
  --ui-mode {simple,bar,rich}         Progress display backend

Advanced:
  --insecure                          Disable TLS certificate verification
  --request-timeout SECONDS           API request timeout (default: 30)
  --max-retries N                     Retry attempts for transient errors (default: 3)
```

---

## License

See repository for license details.
