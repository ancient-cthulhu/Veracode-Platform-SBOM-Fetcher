# Veracode SBOM Generator

Generate SBOMs from the Veracode platform for applications, collections, and SCA workspaces. Supports both interactive and command-line modes.

---

## How It Works

The script connects to the Veracode API and generates Software Bill of Materials (SBOM) files in CycloneDX or SPDX format for:

- **Application Profiles** - Upload/policy scan results
- **Collections** - All applications in a collection
- **SCA Workspaces** - Agent-based scan projects

> **Note:** SBOM generation requires a scan completed within the last 13 months. Applications with older scans are marked as "stale" and cannot be used for SBOM generation until rescanned.

---

## Quickstart

### Interactive mode

```bash
python veracode_sbom_generator.py
```

### Single application

```bash
python veracode_sbom_generator.py --app "MyApp" --format cyclonedx
```

### Collection (all applications)

```bash
python veracode_sbom_generator.py --collection "MyCollection" --format spdx
```

### SCA workspace project

```bash
python veracode_sbom_generator.py --workspace "MyWorkspace" --project "MyProject"
```

### All projects in a workspace

```bash
python veracode_sbom_generator.py --workspace "MyWorkspace"
```

---

## Requirements

```bash
python --version  # Python 3.8+
pip install requests veracode-api-signing
```

---

## Credentials

### Environment variables

```bash
export VERACODE_API_KEY_ID=your_api_key_id
export VERACODE_API_KEY_SECRET=your_api_key_secret
```

### Credentials file

Create `~/.veracode/credentials`:

```ini
[default]
veracode_api_key_id = your_api_key_id
veracode_api_key_secret = your_api_key_secret
```

---

## Command-Line Reference

| Flag | Description |
|------|-------------|
| `--app`, `-a` | Application profile name |
| `--collection`, `-c` | Collection name |
| `--workspace`, `-w` | SCA workspace name |
| `--project`, `-p` | SCA project name (requires `--workspace`) |
| `--format`, `-f` | SBOM format: `cyclonedx` (default) or `spdx` |
| `--linked`, `-l` | Include linked agent-based scan results |
| `--no-vulns` | Exclude vulnerability information |
| `--output`, `-o` | Output directory (default: `sbom_output`) |
| `--region`, `-r` | Veracode region: `commercial` (default), `european`, or `federal` |

---

## Stale Application Handling

SBOM generation requires a scan within the last 13 months. Applications with older or missing scans are "stale."

| Mode | Behavior |
|------|----------|
| Interactive | Stale apps shown with `[STALE]` marker, cannot be selected |
| CLI `--app` | Hard exit if application is stale |
| CLI `--collection` | Warning displayed, stale apps skipped automatically. Hard exit if all apps are stale. |

**To resolve:** Rescan the application in Veracode, then re-run the generator.

---

## Interactive Mode Features

### Main Menu

```
MAIN MENU
----------------------------------------
  1. Application Profile SBOM
  2. Multiple Application SBOMs
  3. Collection SBOMs
  4. Agent-Based Project SBOM
  5. Workspace SBOMs (All Projects)
----------------------------------------
  0. Exit
```

### Browser Controls

| Key | Action |
|-----|--------|
| `#` | Select by number (single) or add by number (multi-select) |
| `1,3,5` | Add multiple items by number |
| `N` / `P` | Next / Previous page |
| `A` | Add all eligible items (multi-select mode) |
| `R` | Review selected items |
| `D` | Done - proceed with selection |
| `X` | Clear selection |
| `C` | Clear filter |
| `text` | Filter by name |
| `0` | Cancel |

---

## Output

SBOMs are saved to `sbom_output/` by default (override with `--output`).

### File naming

| Mode | Pattern |
|------|---------|
| Single app | `{app_name}_sbom_{timestamp}.json` |
| Collection | `collection_{name}_{timestamp}/{app_name}_sbom.json` |
| Workspace | `workspace_{name}_{timestamp}/{project_name}_sbom.json` |
| Agent project | `{project_name}_agent_sbom_{timestamp}.json` |

---

## Regions

| Region | Flag | API Endpoint |
|--------|------|--------------|
| Commercial (US) | `--region commercial` | `api.veracode.com` |
| European | `--region european` | `api.veracode.eu` |
| Federal | `--region federal` | `api.veracode.us` |

---

## Troubleshooting

- **"Authentication failed. Check your API credentials."**
  - Verify `VERACODE_API_KEY_ID` and `VERACODE_API_KEY_SECRET` are set correctly, or check `~/.veracode/credentials`

- **"Application 'X' is stale"**
  - The application has not been scanned in 13+ months. Rescan it in Veracode.

- **"All applications in collection 'X' are stale"**
  - No applications in the collection have recent scans. Rescan at least one application.

- **"Resource not found"**
  - The application, collection, workspace, or project name may be misspelled or you may lack access

- **"Rate limit exceeded"**
  - The script automatically waits and retries. For large batch operations, consider spacing requests

- **Empty SBOM or no components**
  - The scan may not have detected any dependencies. Verify the scan completed successfully in Veracode.

- **"Required packages not installed"**
  - Run: `pip install requests veracode-api-signing`

---

## SBOM Formats

### CycloneDX (default)

Industry-standard format with strong support for vulnerability tracking. Recommended for most use cases.

### SPDX

ISO/IEC standard format. Use when SPDX compliance is required.

Both formats are output as JSON files.

---

Supported platforms: Veracode Commercial · Veracode European · Veracode Federal
