#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from protocol_config import MAX_API_HINTS, MAX_DESCRIPTION_CHARS, MAX_PERMISSION_HINTS

# When Play/F-Droid APIs are empty or offline, still give planners concrete copy for known FOSS apps.
_WELL_KNOWN_PACKAGES: dict[str, dict[str, Any]] = {
    "org.fdroid.fdroid": {
        "category": "App store",
        "purpose": "Browse, search, and install open-source Android apps from F-Droid repositories.",
        "ux_type": "user-interactive",
        "key_user_flows": [
            "Browse Latest, Categories, Updates, and Nearby tabs",
            "Search for a package and open its detail page",
            "Use the Apps menu for QR scanner and Send F-Droid",
            "Open Settings from the bottom navigation",
        ],
        "behavioral_notes": (
            "F-Droid is an app catalog: primary UI is bottom tabs (Categories, Latest, Nearby, Updates, Settings) "
            "plus Search (FAB). Overflow Apps menu exposes QR and share. Detail screens list versions and install "
            "actions; offline or empty repos still allow local navigation."
        ),
    },
}


def _truncate(text: str, limit: int) -> str:
    value = (text or "").strip()
    return value[:limit]


def _fetch_json(url: str, timeout: int = 10) -> dict[str, Any] | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            return json.loads(body)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
        return None


def _infer_ux_type(text_blob: str, permissions: list[str]) -> str:
    text = text_blob.lower()
    perms = {p.upper() for p in permissions}
    if any(k in text for k in ("widget", "launcher", "todo", "notes", "chat", "map", "player", "calendar")):
        return "user-interactive"
    if {"ACCESS_BACKGROUND_LOCATION", "RECEIVE_BOOT_COMPLETED", "FOREGROUND_SERVICE"} & perms:
        return "background-service"
    return "hybrid"


def _infer_category(text_blob: str) -> str:
    text = text_blob.lower()
    if any(k in text for k in ("map", "location", "gps", "navigation")):
        return "Navigation"
    if any(k in text for k in ("note", "task", "calendar", "todo", "productivity")):
        return "Productivity"
    if any(k in text for k in ("chat", "messaging", "social", "mastodon", "fediverse")):
        return "Communication"
    if any(k in text for k in ("music", "video", "podcast", "media")):
        return "Media"
    if any(k in text for k in ("vpn", "privacy", "security", "password", "encrypt")):
        return "Security"
    return "Unknown"


def _infer_key_flows(text_blob: str) -> list[str]:
    text = text_blob.lower()
    flows: list[str] = []
    if any(k in text for k in ("login", "sign in", "account")):
        flows.append("authenticate user account")
    if any(k in text for k in ("search", "find")):
        flows.append("search and browse content")
    if any(k in text for k in ("map", "location", "route")):
        flows.append("view location or routing")
    if any(k in text for k in ("note", "task", "edit")):
        flows.append("create and edit user content")
    if any(k in text for k in ("sync", "upload", "download")):
        flows.append("synchronize remote data")
    return flows[:5]


def fetch_google_play_metadata(package_name: str) -> dict[str, Any] | None:
    # Uses a lightweight public endpoint exposed by the npm package.
    url = f"https://google-play-scraper-api.vercel.app/api/apps/{urllib.parse.quote(package_name)}"
    data = _fetch_json(url)
    if not data:
        return None
    title = str(data.get("title") or "")
    description = _truncate(str(data.get("description") or ""), MAX_DESCRIPTION_CHARS)
    genre = str(data.get("genre") or "Unknown")
    if not title and not description:
        return None
    combined = f"{title}. {description}"
    return {
        "app_name": title or package_name,
        "category": genre if genre != "Unknown" else _infer_category(combined),
        "purpose": description.split(".")[0][:160] if description else "No description available",
        "ux_type": _infer_ux_type(combined, []),
        "key_user_flows": _infer_key_flows(combined),
        "expected_permissions": [],
        "behavioral_notes": description,
        "metadata_source": "google_play",
        "context_confidence": "high",
        "provenance": {"source": "google_play", "url": url},
    }


def fetch_fdroid_metadata(package_name: str) -> dict[str, Any] | None:
    url = f"https://f-droid.org/api/v1/packages/{urllib.parse.quote(package_name)}"
    data = _fetch_json(url)
    if not data:
        return None
    summary = _truncate(str(data.get("summary") or ""), MAX_DESCRIPTION_CHARS)
    description = _truncate(str(data.get("description") or ""), MAX_DESCRIPTION_CHARS)
    category = "Unknown"
    categories = data.get("categories") or []
    if isinstance(categories, list) and categories:
        category = str(categories[0])
    app_name = str(data.get("name") or package_name)
    purpose = summary or (description.split(".")[0][:160] if description else "No description available")
    combined = f"{app_name}. {summary}. {description}"
    return {
        "app_name": app_name,
        "category": category if category != "Unknown" else _infer_category(combined),
        "purpose": purpose,
        "ux_type": _infer_ux_type(combined, []),
        "key_user_flows": _infer_key_flows(combined),
        "expected_permissions": [],
        "behavioral_notes": description or summary,
        "metadata_source": "fdroid",
        "context_confidence": "medium",
        "provenance": {"source": "fdroid", "url": url},
    }


def _extract_with_aapt(apk_path: Path) -> tuple[list[str], list[str], list[str], str]:
    permissions: list[str] = []
    components: list[str] = []
    api_hints: list[str] = []
    application_label = ""
    cmd = ["aapt", "dump", "badging", str(apk_path)]
    try:
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        for line in (result.stdout or "").splitlines():
            if "application-label:" in line:
                m = re.search(r"application-label:'([^']*)'", line)
                if m and m.group(1).strip():
                    application_label = m.group(1).strip()
            if "application:" in line and "label=" in line and not application_label:
                m = re.search(r"label='([^']*)'", line)
                if m and m.group(1).strip():
                    application_label = m.group(1).strip()
            if "uses-permission:" in line:
                m = re.search(r"name='([^']+)'", line)
                if m:
                    permissions.append(m.group(1).split(".")[-1])
            if "launchable-activity:" in line or "activity:" in line or "service:" in line:
                m = re.search(r"name='([^']+)'", line)
                if m:
                    comp = m.group(1).rsplit(".", 1)[-1]
                    components.append(comp)
            low = line.lower()
            for key in ("camera", "location", "bluetooth", "sms", "network", "crypto", "webview"):
                if key in low:
                    api_hints.append(key)
    except OSError:
        pass
    dedup_perms = sorted(set(permissions))[:MAX_PERMISSION_HINTS]
    dedup_comps = sorted(set(components))[:MAX_API_HINTS]
    dedup_api = sorted(set(api_hints))[:MAX_API_HINTS]
    return dedup_perms, dedup_comps, dedup_api, application_label


def build_apk_only_context(package_name: str, apk_path: Path) -> dict[str, Any]:
    permissions, components, api_hints, application_label = _extract_with_aapt(apk_path)
    display_name = application_label.strip() if application_label.strip() else package_name
    text_blob = " ".join([display_name, package_name, *components, *api_hints, *permissions])
    category = _infer_category(text_blob)
    ux_type = _infer_ux_type(text_blob, permissions)
    flows = _infer_key_flows(text_blob)
    notes = "APK-only inference from declared permissions/components"
    if api_hints:
        notes += f" API hints: {', '.join(api_hints[:10])}"
    if components:
        notes += f" Components: {', '.join(components[:10])}"
    purpose = f"Inferred {category.lower()} application behavior from APK metadata."
    return {
        "app_name": display_name,
        "category": category,
        "purpose": purpose,
        "ux_type": ux_type,
        "key_user_flows": flows,
        "expected_permissions": permissions[:MAX_PERMISSION_HINTS],
        "behavioral_notes": notes,
        "metadata_source": "apk_only",
        "context_confidence": "low",
        "provenance": {"source": "apk_only", "apk_path": str(apk_path)},
    }


def build_app_context(package_name: str, apk_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    attempts: list[str] = []
    ctx = fetch_google_play_metadata(package_name)
    attempts.append("google_play")
    if not ctx:
        attempts.append("fdroid")
        ctx = fetch_fdroid_metadata(package_name)
    if not ctx:
        attempts.append("apk_only")
        ctx = build_apk_only_context(package_name, apk_path)

    normalized = {
        "package_name": package_name,
        "app_name": str(ctx.get("app_name", package_name)),
        "category": str(ctx.get("category", "Unknown")),
        "purpose": _truncate(str(ctx.get("purpose", "")), MAX_DESCRIPTION_CHARS),
        "ux_type": str(ctx.get("ux_type", "hybrid")),
        "key_user_flows": list(ctx.get("key_user_flows", [])),
        "expected_permissions": list(ctx.get("expected_permissions", []))[:MAX_PERMISSION_HINTS],
        "behavioral_notes": _truncate(str(ctx.get("behavioral_notes", "")), MAX_DESCRIPTION_CHARS),
        "metadata_source": str(ctx.get("metadata_source", "unknown")),
        "context_confidence": str(ctx.get("context_confidence", "unknown")),
    }
    _augment_context_from_apk_and_catalog(normalized, package_name, apk_path)
    audit = {
        "attempted_sources": attempts,
        "selected_source": normalized["metadata_source"],
        "context_confidence": normalized["context_confidence"],
        "provenance": ctx.get("provenance", {}),
        "raw_excerpt": {
            "purpose": normalized["purpose"][:300],
            "behavioral_notes": normalized["behavioral_notes"][:300],
            "key_user_flows": normalized["key_user_flows"],
        },
    }
    return normalized, audit


def _augment_context_from_apk_and_catalog(
    normalized: dict[str, Any], package_name: str, apk_path: Path
) -> None:
    """Richer app_name from aapt label; fill weak fields from built-in catalog (offline-safe)."""
    _, _, _, label = _extract_with_aapt(apk_path)
    if label.strip() and str(normalized.get("app_name", "")).strip() in (
        "",
        package_name,
    ):
        normalized["app_name"] = label.strip()
    wk = _WELL_KNOWN_PACKAGES.get(package_name)
    if not wk:
        return
    purpose = str(normalized.get("purpose", "")).strip()
    if not purpose or "No description" in purpose or len(purpose) < 20:
        normalized["purpose"] = _truncate(str(wk.get("purpose", "")), MAX_DESCRIPTION_CHARS)
    if not str(normalized.get("behavioral_notes", "")).strip():
        normalized["behavioral_notes"] = _truncate(
            str(wk.get("behavioral_notes", "")), MAX_DESCRIPTION_CHARS
        )
    if not normalized.get("key_user_flows"):
        normalized["key_user_flows"] = list(wk.get("key_user_flows", []))
    if str(normalized.get("category", "")).strip() in ("", "Unknown"):
        normalized["category"] = str(wk.get("category", "Unknown"))
    if str(normalized.get("ux_type", "")).strip() == "hybrid" and wk.get("ux_type"):
        normalized["ux_type"] = str(wk["ux_type"])
