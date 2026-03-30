
#!/usr/bin/env python3
"""Veracode SBOM Generator - Generate SBOMs from Veracode platform."""

import os
import re
import sys
import json
import time
import logging
import argparse
from datetime import datetime, timedelta, UTC
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set
from urllib.parse import urlparse, parse_qs

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
except ImportError:
    print("Error: Required packages not installed.")
    print("Please run: pip install requests veracode-api-signing")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

# Constants
UNSAFE_FILENAME_CHARS = re.compile(r'[/\\:*?"<>| ]')
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_BACKOFF_FACTOR = 1.0
RATE_LIMIT_DELAY = 0.2
PAGE_SIZE = 10


@dataclass
class SBOMResult:
    """Result of an SBOM generation attempt."""
    guid: str
    name: str
    sbom: Optional[Dict] = None
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.sbom is not None and bool(self.sbom)


class VeracodeSBOMGenerator:
    """Client for generating SBOMs from the Veracode platform."""

    REGIONS: Dict[str, str] = {
        "commercial": "https://api.veracode.com",
        "european": "https://api.veracode.eu",
        "federal": "https://api.veracode.us"
    }

    ENDPOINTS: Dict[str, str] = {
        "applications": "/appsec/v1/applications",
        "collections": "/appsec/v1/collections",
        "workspaces": "/srcclr/v3/workspaces",
    }

    def __init__(self, region: str = "commercial") -> None:
        self.base_url = self.REGIONS.get(region.lower(), self.REGIONS["commercial"])
        self.session = requests.Session()
        self.session.auth = RequestsAuthPluginVeracodeHMAC()
        self.session.headers.update({
            "User-Agent": "Veracode-SBOM-Generator/1.0",
            "Content-Type": "application/json"
        })

        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=RETRY_BACKOFF_FACTOR,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET"],
            raise_on_status=False
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self._last_request_time = 0.0

    def __enter__(self) -> "VeracodeSBOMGenerator":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.close()
        return False

    def close(self) -> None:
        """Close the HTTP session."""
        self.session.close()

    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """Make an authenticated API request with rate limiting and retries."""
        elapsed = time.time() - self._last_request_time
        if elapsed < RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY - elapsed)

        url = f"{self.base_url}{endpoint}"
        last_exception: Optional[Exception] = None

        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)
                self._last_request_time = time.time()

                if response.status_code == 429:
                    if attempt < MAX_RETRIES:
                        retry_after = int(response.headers.get("Retry-After", 60))
                        logger.warning("Rate limited. Waiting %d seconds...", retry_after)
                        time.sleep(retry_after)
                        continue
                    logger.error("Rate limit exceeded after retries.")
                    return {}

                response.raise_for_status()
                return response.json()

            except requests.exceptions.JSONDecodeError:
                logger.error("Invalid JSON response from: %s", endpoint)
                return {}
            except requests.exceptions.Timeout as e:
                last_exception = e
                if attempt < MAX_RETRIES:
                    wait_time = RETRY_BACKOFF_FACTOR * (2 ** attempt)
                    logger.warning("Timeout, retrying in %.1fs... (%d/%d)",
                                   wait_time, attempt + 1, MAX_RETRIES)
                    time.sleep(wait_time)
                    continue
            except requests.exceptions.ConnectionError as e:
                last_exception = e
                if attempt < MAX_RETRIES:
                    wait_time = RETRY_BACKOFF_FACTOR * (2 ** attempt)
                    logger.warning("Connection error, retrying in %.1fs... (%d/%d)",
                                   wait_time, attempt + 1, MAX_RETRIES)
                    time.sleep(wait_time)
                    continue
            except requests.exceptions.HTTPError as e:
                status = e.response.status_code if e.response is not None else "unknown"
                # Try to extract a human-readable detail from Veracode's error envelope
                detail = ""
                if e.response is not None:
                    try:
                        errors = e.response.json().get("_embedded", {}).get("errors", [])
                        if errors:
                            detail = errors[0].get("detail") or errors[0].get("title", "")
                    except Exception:
                        pass
                messages = {
                    401: "Authentication failed. Check your API credentials.",
                    403: "Access denied.",
                    404: detail or "Resource not found.",
                }
                logger.error("Error %s: %s", status, messages.get(status, detail or str(e)))
                return {}
            except requests.exceptions.RequestException as e:
                logger.error("Request failed: %s", e)
                return {}

        if last_exception:
            logger.error("Request failed after %d retries: %s", MAX_RETRIES, last_exception)
        return {}

    def _extract_embedded(self, result: Dict, key: str) -> List[Dict]:
        """Extract embedded items from HAL response."""
        if not result:
            return []
        return result.get("_embedded", {}).get(key, [])

    def _get_all_pages(self, endpoint: str, embedded_key: str,
                       params: Optional[Dict] = None) -> List[Dict]:
        """Fetch all pages using HAL _links.next or page object pagination."""
        all_items: List[Dict] = []
        current_params = params.copy() if params else {}
        current_endpoint = endpoint

        while True:
            result = self._make_request(current_endpoint, current_params)
            items = self._extract_embedded(result, embedded_key)

            if not items:
                break

            all_items.extend(items)

            next_link = result.get("_links", {}).get("next", {}).get("href")
            if next_link:
                parsed = urlparse(next_link)
                current_endpoint = parsed.path
                current_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                continue

            page_info = result.get("page", {})
            if page_info:
                current_page = page_info.get("number", 0)
                total_pages = page_info.get("total_pages", 1)
                if current_page < total_pages - 1:
                    current_params["page"] = current_page + 1
                    continue

            break

        return all_items

    def _get_sbom(self, target_guid: str, sbom_format: str, target_type: str = "application",
                  include_linked: bool = False, include_vulnerabilities: bool = True) -> Optional[Dict]:
        """Fetch SBOM for a target.

        Endpoint: /srcclr/sbom/v1/targets/{guid}/{format}

        Valid query params:
          type         — "application" (upload/policy scans) or "agent" (agent-based scans)
          linked       — "true" only when type=application and linked agent results are wanted
          vulnerability — "false" only when explicitly excluding; API default is true, so we
                          omit the param entirely when including vulns to avoid sending noise
        """
        endpoint = f"/srcclr/sbom/v1/targets/{target_guid}/{sbom_format}"
        params: Dict[str, str] = {"type": target_type}

        # Only send vulnerability=false when explicitly excluding.
        # The API default is true, so omitting it is equivalent — and avoids
        # any gateway behaviour that rejects redundant params.
        if not include_vulnerabilities:
            params["vulnerability"] = "false"

        # linked is only meaningful for application-type requests and only
        # when the caller explicitly wants linked agent-based results.
        if target_type == "application" and include_linked:
            params["linked"] = "true"

        result = self._make_request(endpoint, params)
        return result if result else None

    def get_applications(self, name_filter: Optional[str] = None, page_size: int = 100) -> List[Dict]:
        """Get applications with an SCA-eligible scan in the last 13 months."""
        cutoff = datetime.now(UTC) - timedelta(days=395)
        params: Dict = {
            "size": page_size,
            "modified_after": cutoff.strftime("%Y-%m-%d"),
        }
        if name_filter:
            params["name"] = name_filter
    
        apps = self._get_all_pages(self.ENDPOINTS["applications"], "applications", params)
    
        filtered: List[Dict] = []
        for app in apps:
            raw = app.get("last_completed_scan_date")
            if not raw:
                continue
            try:
                scan_dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                try:
                    scan_dt = datetime.strptime(raw[:10], "%Y-%m-%d").replace(tzinfo=UTC)
                except ValueError:
                    continue
    
            if scan_dt >= cutoff:
                filtered.append(app)
    
        return filtered

    def get_application_by_name(self, app_name: str) -> Optional[Dict]:
        """Find an application by exact name match (case-insensitive)."""
        apps = self.get_applications(name_filter=app_name)
        app_name_lower = app_name.lower()
        return next(
            (app for app in apps if app.get("profile", {}).get("name", "").lower() == app_name_lower),
            None
        )

    def generate_app_sbom(self, app_guid: str, sbom_format: str = "cyclonedx",
                          include_linked: bool = False,
                          include_vulnerabilities: bool = True) -> Optional[Dict]:
        """Generate SBOM for an application profile (upload/policy scan results)."""
        return self._get_sbom(app_guid, sbom_format, "application", include_linked, include_vulnerabilities)

    def get_collections(self) -> List[Dict]:
        """Get all collections."""
        return self._get_all_pages(self.ENDPOINTS["collections"], "collections")

    def get_collection_by_name(self, collection_name: str) -> Optional[Dict]:
        """Find a collection by exact name match (case-insensitive)."""
        name_lower = collection_name.lower()
        return next((c for c in self.get_collections() if c.get("name", "").lower() == name_lower), None)

    def get_collection_assets(self, collection_guid: str) -> List[Dict]:
        """Get all assets in a collection."""
        return self._get_all_pages(f"{self.ENDPOINTS['collections']}/{collection_guid}/assets", "assets")

    def generate_collection_sboms(self, collection_guid: str, sbom_format: str = "cyclonedx",
                                   include_linked: bool = False,
                                   include_vulnerabilities: bool = True) -> List[SBOMResult]:
        """Generate SBOMs for all applications in a collection."""
        assets = self.get_collection_assets(collection_guid)
        total = len(assets)
        logger.info("\nFound %d applications in collection", total)

        results: List[SBOMResult] = []
        for i, asset in enumerate(assets, 1):
            app_guid = asset.get("guid", "")
            app_name = asset.get("name", "Unknown")
            logger.info("   [%d/%d] Generating SBOM for: %s", i, total, app_name)
            sbom = self.generate_app_sbom(app_guid, sbom_format, include_linked, include_vulnerabilities)
            results.append(SBOMResult(guid=app_guid, name=app_name, sbom=sbom))
        return results

    def get_workspaces(self) -> List[Dict]:
        """Get all SCA workspaces."""
        return self._get_all_pages(self.ENDPOINTS["workspaces"], "workspaces")

    def get_workspace_by_name(self, workspace_name: str) -> Optional[Dict]:
        """Find a workspace by exact name match (case-insensitive)."""
        name_lower = workspace_name.lower()
        return next((ws for ws in self.get_workspaces() if ws.get("name", "").lower() == name_lower), None)

    @staticmethod
    def _workspace_guid(workspace: Dict) -> str:
        """Return the UUID for a workspace object.

        The srcclr /v3/workspaces response has two identifier fields:
          "id"   — legacy string slug (e.g. "my-workspace"), NOT for use in URLs
          "guid" — UUID required in all API path segments
        """
        return workspace.get("guid", "")

    @staticmethod
    def _project_guid(project: Dict) -> str:
        """Return the UUID for a project object.

        The srcclr /v3/workspaces/{guid}/projects response uses "id" for the
        project UUID (there is no separate "guid" key on project objects).
        """
        return project.get("id", "")

    def get_workspace_projects(self, workspace_guid: str) -> List[Dict]:
        """Get all projects in a workspace. Pass the workspace UUID ("guid" field)."""
        return self._get_all_pages(f"{self.ENDPOINTS['workspaces']}/{workspace_guid}/projects", "projects")

    def get_project_by_name(self, workspace_guid: str, project_name: str) -> Optional[Dict]:
        """Find a project by exact name match (case-insensitive)."""
        name_lower = project_name.lower()
        return next(
            (p for p in self.get_workspace_projects(workspace_guid) if p.get("name", "").lower() == name_lower),
            None
        )

    def generate_agent_sbom(self, project_guid: str, sbom_format: str = "cyclonedx",
                            include_vulnerabilities: bool = True) -> Optional[Dict]:
        """Generate SBOM for an agent-based scan project.

        Uses type=agent. The linked param is not applicable here.
        """
        return self._get_sbom(project_guid, sbom_format, "agent", False, include_vulnerabilities)

    def generate_workspace_sboms(self, workspace_guid: str, sbom_format: str = "cyclonedx",
                                  include_vulnerabilities: bool = True) -> List[SBOMResult]:
        """Generate SBOMs for all projects in a workspace."""
        projects = self.get_workspace_projects(workspace_guid)
        total = len(projects)
        logger.info("\nFound %d projects in workspace", total)

        results: List[SBOMResult] = []
        for i, project in enumerate(projects, 1):
            project_guid = self._project_guid(project)
            project_name = project.get("name", "Unknown")
            logger.info("   [%d/%d] Generating SBOM for: %s", i, total, project_name)
            sbom = self.generate_agent_sbom(project_guid, sbom_format, include_vulnerabilities)
            results.append(SBOMResult(guid=project_guid, name=project_name, sbom=sbom))
        return results


# UI Helper Functions

def clear_screen() -> None:
    """Clear the terminal screen."""
    print("\033[2J\033[H", end="", flush=True)


def print_error(msg: str) -> None:
    """Print a clearly visible error message."""
    print(f"\n{'!' * 60}")
    print(f"  ERROR: {msg}")
    print("!" * 60)


def print_success(msg: str) -> None:
    """Print a success confirmation message."""
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print("=" * 60)


def print_header() -> None:
    """Print the application header."""
    print("=" * 60)
    print("       VERACODE SBOM GENERATOR")
    print("=" * 60)
    print()


def print_menu() -> None:
    """Print the main menu."""
    print("\nMAIN MENU")
    print("-" * 40)
    print("  1. Application Profile SBOM")
    print("  2. Multiple Application SBOMs")
    print("  3. Collection SBOMs")
    print("  4. Agent-Based Project SBOM")
    print("  5. Workspace SBOMs (All Projects)")
    print("-" * 40)
    print("  0. Exit")
    print()


def select_format() -> str:
    """Prompt user to select SBOM format."""
    print("\nSELECT SBOM FORMAT")
    print("-" * 40)
    print("  1. CycloneDX (JSON)")
    print("  2. SPDX (JSON)")
    print()
    while True:
        choice = input("Enter choice [1-2]: ").strip()
        if choice == "1":
            return "cyclonedx"
        if choice == "2":
            return "spdx"
        print("Invalid choice. Please enter 1 or 2.")


def select_options() -> tuple:
    """Prompt user for SBOM generation options."""
    print("\nSBOM OPTIONS")
    print("-" * 40)
    include_linked = input("Include linked agent-based results? [y/N]: ").strip().lower() == 'y'
    include_vulns = input("Include vulnerabilities? [Y/n]: ").strip().lower() != 'n'
    return include_linked, include_vulns


def sanitize_filename(name: str) -> str:
    """Sanitize a string for use as a filename."""
    name = os.path.basename(name)
    return UNSAFE_FILENAME_CHARS.sub('_', name)


def save_sbom(sbom_data: Dict, filename: str, output_dir: str = ".") -> bool:
    """Save SBOM data to a JSON file."""
    try:
        os.makedirs(output_dir, exist_ok=True)
        safe_filename = sanitize_filename(filename)
        filepath = os.path.join(output_dir, safe_filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(sbom_data, f, indent=2)
        logger.info("   Saved: %s", filepath)
        return True
    except (OSError, IOError, TypeError, ValueError) as e:
        logger.error("   Failed to save %s: %s", filename, e)
        return False


def process_sbom_results(results: List[SBOMResult], output_dir: str) -> int:
    """Save all successful SBOM results and return count."""
    success_count = 0
    for r in results:
        if r.success:
            filename = f"{sanitize_filename(r.name)}_sbom.json"
            if save_sbom(r.sbom, filename, output_dir):
                success_count += 1
    return success_count


# Interactive Browser

@dataclass
class BrowserState:
    """State for the interactive browser."""
    items: List[Dict]
    filtered_items: List[Dict] = field(default_factory=list)
    selected: List[Dict] = field(default_factory=list)
    selected_ids: Set[str] = field(default_factory=set)
    filter_str: str = ""
    page: int = 0

    def __post_init__(self):
        if not self.filtered_items:
            self.filtered_items = self.items.copy()


class ItemBrowser:
    """Interactive browser for selecting items with filtering and pagination."""

    def __init__(self, items: List[Dict], item_type: str,
                 name_key: str = "name", id_key: str = "guid",
                 allow_multi: bool = False) -> None:
        self.items = items
        self.item_type = item_type
        self.name_key = name_key
        self.id_key = id_key
        self.allow_multi = allow_multi
        self.state = BrowserState(items=items)

    def get_name(self, item: Dict) -> str:
        if self.name_key == "profile":
            return item.get("profile", {}).get("name", "Unknown")
        return item.get(self.name_key, "Unknown")

    def get_id(self, item: Dict) -> str:
        return item.get(self.id_key, "")

    def get_subtitle(self, item: Dict) -> str:
        """Return a secondary display string for the item, e.g. last scan date."""
        raw = item.get("last_completed_scan_date", "")
        if not raw:
            return ""
        try:
            dt = datetime.strptime(raw[:10], "%Y-%m-%d")
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            return ""

    @property
    def total_pages(self) -> int:
        return max(1, (len(self.state.filtered_items) + PAGE_SIZE - 1) // PAGE_SIZE)

    @property
    def display_items(self) -> List[Dict]:
        start = self.state.page * PAGE_SIZE
        return self.state.filtered_items[start:start + PAGE_SIZE]

    @property
    def start_index(self) -> int:
        return self.state.page * PAGE_SIZE

    def display(self) -> None:
        s = self.state
        print(f"\n{self.item_type.upper()}S", end="")
        if s.filter_str:
            print(f" matching '{s.filter_str}'", end="")
        print(f" with SBOM available ({len(s.filtered_items)})")
        if self.item_type.lower() == "application":
            print("  (showing only apps with a scan in the last 13 months)")
        if self.allow_multi and s.selected:
            print(f"Selected: {len(s.selected)} item(s)")
        print("-" * 55)

        if not self.display_items:
            print("  No items to display.")
        else:
            for i, item in enumerate(self.display_items, self.start_index + 1):
                marker = " [*]" if self.get_id(item) in s.selected_ids else ""
                subtitle = self.get_subtitle(item)
                suffix = f"  (last scan: {subtitle})" if subtitle else ""
                print(f"  {i:3d}. {self.get_name(item)}{suffix}{marker}")

        if self.total_pages > 1:
            nav = []
            if s.page > 0:
                nav.append("[P]rev")
            if s.page < self.total_pages - 1:
                nav.append("[N]ext")
            print(f"\n  Page {s.page + 1}/{self.total_pages}  {' / '.join(nav)}")

        print()
        if self.allow_multi:
            print("  [#] Add by number (1 or 1,3,5)   [R] Review selected")
            print("  [A] Add all filtered             [D] Done - proceed")
            print(f"  [C] Clear filter                 [X] Clear selection" if s.filter_str else
                  "                                   [X] Clear selection")
        else:
            print("  [#] Select by number    [text] Filter by name")
            if s.filter_str:
                print("  [C] Clear filter")
        print("  [0] Cancel")

    def apply_filter(self, text: str) -> None:
        self.state.filter_str = text.lower()
        self.state.filtered_items = [
            item for item in self.items if self.state.filter_str in self.get_name(item).lower()
        ]
        self.state.page = 0
        if not self.state.filtered_items:
            print(f"  No matches for '{text}'")
            self.clear_filter()

    def clear_filter(self) -> None:
        self.state.filter_str = ""
        self.state.filtered_items = self.items.copy()
        self.state.page = 0

    def add_items(self, indices: List[int]) -> None:
        for idx in indices:
            if 1 <= idx <= len(self.state.filtered_items):
                item = self.state.filtered_items[idx - 1]
                item_id = self.get_id(item)
                if item_id not in self.state.selected_ids:
                    self.state.selected.append(item)
                    self.state.selected_ids.add(item_id)
                    print(f"  + {self.get_name(item)}")
                else:
                    print(f"  Already selected: {self.get_name(item)}")
            else:
                print(f"  Invalid: {idx}")
        if indices:
            print(f"  Total selected: {len(self.state.selected)}")

    def add_all_filtered(self) -> None:
        added = 0
        for item in self.state.filtered_items:
            item_id = self.get_id(item)
            if item_id not in self.state.selected_ids:
                self.state.selected.append(item)
                self.state.selected_ids.add(item_id)
                added += 1
        print(f"  Added {added} item(s). Total: {len(self.state.selected)}" if added else
              "  All filtered items already selected.")

    def review_selected(self) -> None:
        if not self.state.selected:
            print("  No items selected.")
            return

        review_page = 0
        while self.state.selected:
            total_pages = max(1, (len(self.state.selected) + PAGE_SIZE - 1) // PAGE_SIZE)
            start = review_page * PAGE_SIZE
            end = min(start + PAGE_SIZE, len(self.state.selected))

            print(f"\n=== SELECTED {self.item_type.upper()}S ({len(self.state.selected)} total) ===")
            print("-" * 55)
            for i, item in enumerate(self.state.selected[start:end], start + 1):
                print(f"  {i:3d}. {self.get_name(item)}")

            if total_pages > 1:
                nav = []
                if review_page > 0:
                    nav.append("[P]rev")
                if review_page < total_pages - 1:
                    nav.append("[N]ext")
                print(f"\n  Page {review_page + 1}/{total_pages}  {' / '.join(nav)}")

            print("\n  [#] Remove (1 or 1,3,5)  [Enter] Back to browse")
            choice = input("\n> ").strip()

            if choice == "":
                break
            if choice.upper() == "N" and review_page < total_pages - 1:
                review_page += 1
                continue
            if choice.upper() == "P" and review_page > 0:
                review_page -= 1
                continue

            try:
                to_remove = sorted(
                    set(int(x.strip()) - 1 for x in choice.split(",") if x.strip().isdigit()),
                    reverse=True
                )
                for idx in to_remove:
                    if 0 <= idx < len(self.state.selected):
                        removed = self.state.selected.pop(idx)
                        self.state.selected_ids.discard(self.get_id(removed))
                        print(f"  Removed: {self.get_name(removed)}")
                if self.state.selected:
                    print(f"  {len(self.state.selected)} item(s) remaining")
                    review_page = min(review_page, (len(self.state.selected) - 1) // PAGE_SIZE)
            except ValueError:
                print("  Invalid input.")

    def run(self) -> Optional[List[Dict]]:
        if not self.items:
            print(f"No {self.item_type}s found.")
            return None

        while True:
            self.display()
            choice = input("\n> ").strip()

            if not choice:
                continue

            cmd = choice.upper()

            if choice == "0":
                if self.allow_multi and self.state.selected:
                    if input(f"Discard {len(self.state.selected)} selected? [y/N]: ").strip().lower() != 'y':
                        continue
                return None

            if cmd == "N" and self.state.page < self.total_pages - 1:
                self.state.page += 1
                continue
            if cmd == "P" and self.state.page > 0:
                self.state.page -= 1
                continue
            if cmd == "C" and self.state.filter_str:
                self.clear_filter()
                continue

            if self.allow_multi:
                if cmd == "X":
                    self.state.selected.clear()
                    self.state.selected_ids.clear()
                    print("  Selection cleared.")
                    continue
                if cmd == "D":
                    return self.state.selected if self.state.selected else None
                if cmd == "A":
                    self.add_all_filtered()
                    continue
                if cmd == "R":
                    self.review_selected()
                    continue

            if any(c.isdigit() for c in choice):
                try:
                    nums = [int(x.strip()) for x in choice.replace(" ", ",").split(",") if x.strip().isdigit()]
                    if self.allow_multi:
                        self.add_items(nums)
                    else:
                        for num in nums:
                            if 1 <= num <= len(self.state.filtered_items):
                                return [self.state.filtered_items[num - 1]]
                        print("  Invalid selection.")
                    continue
                except ValueError:
                    pass

            self.apply_filter(choice)


def browse_and_select(items: List[Dict], item_type: str, name_key: str = "name",
                      id_key: str = "guid", allow_multi: bool = False) -> Optional[List[Dict]]:
    """Convenience function for interactive item selection."""
    return ItemBrowser(items, item_type, name_key, id_key, allow_multi).run()


# Main Application Modes

def interactive_mode(generator: VeracodeSBOMGenerator) -> None:
    """Run the interactive menu mode."""
    while True:
        clear_screen()
        print_header()
        print_menu()
        choice = input("Enter choice: ").strip()

        if choice == "0":
            print("\nGoodbye!")
            sys.exit(0)

        elif choice == "1":
            print("\nAPPLICATION PROFILE SBOM")
            print("-" * 40)
            print("Fetching applications (last 13 months)...")
            apps = generator.get_applications()

            selected = browse_and_select(apps, "application", name_key="profile", id_key="guid")
            if not selected:
                print("\nNo application selected.")
                input("\nPress Enter to continue...")
                continue

            app = selected[0]
            app_name = app.get("profile", {}).get("name", "Unknown")
            print(f"\nSelected: {app_name}")

            sbom_format = select_format()
            include_linked, include_vulns = select_options()

            print(f"\nGenerating {sbom_format.upper()} SBOM...")
            sbom = generator.generate_app_sbom(app.get("guid"), sbom_format, include_linked, include_vulns)

            if sbom:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filepath = f"sbom_output/{sanitize_filename(app_name)}_sbom_{timestamp}.json"
                if save_sbom(sbom, f"{sanitize_filename(app_name)}_sbom_{timestamp}.json", "sbom_output"):
                    print_success(f"SBOM saved: {filepath}")
            else:
                print_error("Failed to generate SBOM. See details above.")
            input("\nPress Enter to continue...")

        elif choice == "2":
            print("\nMULTIPLE APPLICATION SBOMS")
            print("-" * 40)
            print("Fetching applications (last 13 months)...")
            apps = generator.get_applications()

            selected = browse_and_select(apps, "application", name_key="profile", id_key="guid", allow_multi=True)
            if not selected:
                print("\nNo applications selected.")
                input("\nPress Enter to continue...")
                continue

            print(f"\nSelected {len(selected)} application(s)")
            sbom_format = select_format()
            include_linked, include_vulns = select_options()

            print(f"\nGenerating SBOMs for {len(selected)} applications...")
            print("-" * 40)
            success_count = 0
            failed: List[str] = []
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            for i, app in enumerate(selected, 1):
                app_name = app.get("profile", {}).get("name", "Unknown")
                print(f"\n[{i}/{len(selected)}] {app_name}")
                sbom = generator.generate_app_sbom(app.get("guid"), sbom_format, include_linked, include_vulns)
                if sbom and save_sbom(sbom, f"{sanitize_filename(app_name)}_sbom_{timestamp}.json", "sbom_output"):
                    success_count += 1
                else:
                    failed.append(app_name)

            print()
            if success_count == len(selected):
                print_success(f"All {success_count} SBOMs generated successfully.")
            else:
                print(f"\n{'=' * 60}")
                print(f"  Summary: {success_count}/{len(selected)} SBOMs generated.")
                if failed:
                    print(f"\n  Failed ({len(failed)}):")
                    for name in failed:
                        print(f"    - {name}")
                print("=" * 60)
            input("\nPress Enter to continue...")

        elif choice == "3":
            print("\nCOLLECTION SBOMS")
            print("-" * 40)
            print("Fetching collections...")
            collections = generator.get_collections()

            selected = browse_and_select(collections, "collection", name_key="name", id_key="guid")
            if not selected:
                print("\nNo collection selected.")
                input("\nPress Enter to continue...")
                continue

            collection = selected[0]
            collection_name = collection.get("name", "Unknown")
            print(f"\nSelected: {collection_name}")

            sbom_format = select_format()
            include_linked, include_vulns = select_options()
            print("\nGenerating SBOMs for collection...")

            results = generator.generate_collection_sboms(collection.get("guid"), sbom_format, include_linked, include_vulns)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"sbom_output/collection_{sanitize_filename(collection_name)}_{timestamp}"
            success_count = process_sbom_results(results, output_dir)
            failed_count = len(results) - success_count

            if success_count == len(results):
                print_success(f"All {success_count} SBOMs generated.  Output: {output_dir}")
            else:
                print(f"\n{'=' * 60}")
                print(f"  Summary: {success_count}/{len(results)} SBOMs generated.")
                if failed_count:
                    print(f"  {failed_count} failed — see errors above.")
                print(f"  Output: {output_dir}")
                print("=" * 60)
            input("\nPress Enter to continue...")

        elif choice == "4":
            print("\nAGENT-BASED PROJECT SBOM")
            print("-" * 40)
            print("Fetching workspaces...")
            workspaces = generator.get_workspaces()

            selected_ws = browse_and_select(workspaces, "workspace", name_key="name", id_key="guid")
            if not selected_ws:
                print("\nNo workspace selected.")
                input("\nPress Enter to continue...")
                continue

            workspace = selected_ws[0]
            workspace_name = workspace.get("name", "Unknown")
            ws_guid = VeracodeSBOMGenerator._workspace_guid(workspace)
            print(f"\nFetching projects for workspace: {workspace_name}")
            projects = generator.get_workspace_projects(ws_guid)

            selected_proj = browse_and_select(projects, "project", name_key="name", id_key="id")
            if not selected_proj:
                print("\nNo project selected.")
                input("\nPress Enter to continue...")
                continue

            project = selected_proj[0]
            project_name = project.get("name", "Unknown")
            proj_guid = VeracodeSBOMGenerator._project_guid(project)
            print(f"\nSelected: {project_name}")

            sbom_format = select_format()
            include_vulns = input("Include vulnerabilities? [Y/n]: ").strip().lower() != 'n'

            print(f"\nGenerating {sbom_format.upper()} SBOM for project: {project_name}")
            sbom = generator.generate_agent_sbom(proj_guid, sbom_format, include_vulns)

            if sbom:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{sanitize_filename(project_name)}_agent_sbom_{timestamp}.json"
                if save_sbom(sbom, filename, "sbom_output"):
                    print_success(f"SBOM saved: sbom_output/{filename}")
            else:
                print_error("Failed to generate SBOM. See details above.")
            input("\nPress Enter to continue...")

        elif choice == "5":
            print("\nWORKSPACE SBOMS (ALL PROJECTS)")
            print("-" * 40)
            print("Fetching workspaces...")
            workspaces = generator.get_workspaces()

            selected = browse_and_select(workspaces, "workspace", name_key="name", id_key="guid")
            if not selected:
                print("\nNo workspace selected.")
                input("\nPress Enter to continue...")
                continue

            workspace = selected[0]
            workspace_name = workspace.get("name", "Unknown")
            ws_guid = VeracodeSBOMGenerator._workspace_guid(workspace)
            print(f"\nSelected: {workspace_name}")

            sbom_format = select_format()
            include_vulns = input("Include vulnerabilities? [Y/n]: ").strip().lower() != 'n'

            print(f"\nGenerating SBOMs for all projects in workspace: {workspace_name}")
            results = generator.generate_workspace_sboms(ws_guid, sbom_format, include_vulns)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"sbom_output/workspace_{sanitize_filename(workspace_name)}_{timestamp}"
            success_count = process_sbom_results(results, output_dir)
            failed_count = len(results) - success_count

            if success_count == len(results):
                print_success(f"All {success_count} SBOMs generated.  Output: {output_dir}")
            else:
                print(f"\n{'=' * 60}")
                print(f"  Summary: {success_count}/{len(results)} SBOMs generated.")
                if failed_count:
                    print(f"  {failed_count} failed — see errors above.")
                print(f"  Output: {output_dir}")
                print("=" * 60)
            input("\nPress Enter to continue...")

        else:
            print_error("Invalid choice. Please enter 0-5.")
            input("\nPress Enter to continue...")


def command_line_mode(args: argparse.Namespace) -> None:
    """Run in command-line (non-interactive) mode."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output or "sbom_output"

    with VeracodeSBOMGenerator(region=args.region) as generator:
        if args.app:
            logger.info("Fetching application: %s", args.app)
            app = generator.get_application_by_name(args.app)
            if not app:
                logger.error("Error: Application '%s' not found.", args.app)
                sys.exit(1)

            app_name = app.get("profile", {}).get("name", args.app)
            logger.info("Generating %s SBOM for: %s", args.format.upper(), app_name)
            sbom = generator.generate_app_sbom(app.get("guid"), args.format, args.linked, not args.no_vulns)

            if sbom:
                save_sbom(sbom, f"{sanitize_filename(app_name)}_sbom_{timestamp}.json", output_dir)
            else:
                logger.error("Failed to generate SBOM.")
                sys.exit(1)

        elif args.collection:
            logger.info("Fetching collection: %s", args.collection)
            collection = generator.get_collection_by_name(args.collection)
            if not collection:
                logger.error("Error: Collection '%s' not found.", args.collection)
                sys.exit(1)

            collection_name = collection.get("name", args.collection)
            logger.info("Generating SBOMs for collection: %s", collection_name)
            results = generator.generate_collection_sboms(collection.get("guid"), args.format, args.linked, not args.no_vulns)

            col_output_dir = os.path.join(output_dir, f"collection_{sanitize_filename(collection_name)}_{timestamp}")
            success_count = process_sbom_results(results, col_output_dir)
            logger.info("\nSummary: %d/%d SBOMs generated", success_count, len(results))

        elif args.workspace and args.project:
            logger.info("Fetching workspace: %s", args.workspace)
            workspace = generator.get_workspace_by_name(args.workspace)
            if not workspace:
                logger.error("Error: Workspace '%s' not found.", args.workspace)
                sys.exit(1)

            ws_guid = VeracodeSBOMGenerator._workspace_guid(workspace)
            project = generator.get_project_by_name(ws_guid, args.project)
            if not project:
                logger.error("Error: Project '%s' not found in workspace.", args.project)
                sys.exit(1)

            project_name = project.get("name", args.project)
            proj_guid = VeracodeSBOMGenerator._project_guid(project)
            logger.info("Generating %s SBOM for project: %s", args.format.upper(), project_name)
            sbom = generator.generate_agent_sbom(proj_guid, args.format, not args.no_vulns)

            if sbom:
                save_sbom(sbom, f"{sanitize_filename(project_name)}_agent_sbom_{timestamp}.json", output_dir)
            else:
                logger.error("Failed to generate SBOM.")
                sys.exit(1)

        elif args.workspace:
            logger.info("Fetching workspace: %s", args.workspace)
            workspace = generator.get_workspace_by_name(args.workspace)
            if not workspace:
                logger.error("Error: Workspace '%s' not found.", args.workspace)
                sys.exit(1)

            workspace_name = workspace.get("name", args.workspace)
            ws_guid = VeracodeSBOMGenerator._workspace_guid(workspace)
            logger.info("Generating SBOMs for all projects in workspace: %s", workspace_name)
            results = generator.generate_workspace_sboms(ws_guid, args.format, not args.no_vulns)

            ws_output_dir = os.path.join(output_dir, f"workspace_{sanitize_filename(workspace_name)}_{timestamp}")
            success_count = process_sbom_results(results, ws_output_dir)
            logger.info("\nSummary: %d/%d SBOMs generated", success_count, len(results))

        else:
            logger.error("Error: No target specified. Use --app, --collection, or --workspace.")
            sys.exit(1)


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Veracode SBOM Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Interactive mode:     python script.py
  Single application:   python script.py --app "MyApp" --format cyclonedx
  Collection:           python script.py --collection "MyCollection" --format spdx
  Agent project:        python script.py --workspace "MyWorkspace" --project "MyProject"
  All workspace:        python script.py --workspace "MyWorkspace"
        """
    )

    target_group = parser.add_argument_group("Target Options")
    target_group.add_argument("--app", "-a", help="Application profile name")
    target_group.add_argument("--collection", "-c", help="Collection name")
    target_group.add_argument("--workspace", "-w", help="SCA workspace name")
    target_group.add_argument("--project", "-p", help="SCA project name (requires --workspace)")

    format_group = parser.add_argument_group("Format Options")
    format_group.add_argument("--format", "-f", choices=["cyclonedx", "spdx"], default="cyclonedx",
                              help="SBOM format (default: cyclonedx)")

    options_group = parser.add_argument_group("Additional Options")
    options_group.add_argument("--linked", "-l", action="store_true", help="Include linked agent-based scan results")
    options_group.add_argument("--no-vulns", action="store_true", help="Exclude vulnerability information")
    options_group.add_argument("--output", "-o", help="Output directory (default: sbom_output)")
    options_group.add_argument("--region", "-r", choices=["commercial", "european", "federal"],
                               default="commercial", help="Veracode region (default: commercial)")

    args = parser.parse_args()

    if not os.environ.get("VERACODE_API_KEY_ID") and not os.path.exists(os.path.expanduser("~/.veracode/credentials")):
        logger.warning("Warning: Veracode API credentials not found.")
        logger.warning("   Set VERACODE_API_KEY_ID and VERACODE_API_KEY_SECRET environment variables")
        logger.warning("   Or create ~/.veracode/credentials file\n")

    if any([args.app, args.collection, args.workspace]):
        command_line_mode(args)
    else:
        with VeracodeSBOMGenerator(region=args.region) as generator:
            interactive_mode(generator)


if __name__ == "__main__":
    main()
