"""Canonical vault paths for the ABRG malware corpus (ContextDroid safety harness)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

# Sparse bundle lives outside the repo; never commit it (.gitignore: *.sparsebundle).
SPARSE_BUNDLE: Path = Path.home() / "Vaults" / "abrg_mw.sparsebundle"

VOLUME_NAME: str = "ABRG_MW"

# Only this module may reference /Volumes/... — enforced by gate_p1 grep test.
MOUNT_ROOT: Path = Path("/Volumes") / VOLUME_NAME

QUARANTINE_DIR: Path = MOUNT_ROOT / "quarantine"
STAGING_DIR: Path = MOUNT_ROOT / "staging"
MANIFEST_DIR: Path = MOUNT_ROOT / "manifest"
TRACES_DIR: Path = MOUNT_ROOT / "traces"
LOGS_DIR: Path = MOUNT_ROOT / "logs"

VAULT_SUBDIRS: tuple[str, ...] = (
    "quarantine",
    "staging",
    "manifest",
    "traces",
    "logs",
    "logs/sink",
)

# 7z accident-prevention convention (NOT the vault encryption secret).
QUARANTINE_7Z_PASSWORD: str = "infected"


class VaultNotMountedError(RuntimeError):
    """Raised when an operation requires the vault but it is not mounted."""


def is_mounted() -> bool:
    """Return True when the vault volume is mounted at MOUNT_ROOT."""
    return MOUNT_ROOT.is_dir() and os.path.ismount(MOUNT_ROOT)


def assert_mounted() -> Path:
    """Return MOUNT_ROOT or raise VaultNotMountedError with a clear message."""
    if not is_mounted():
        raise VaultNotMountedError(
            f"Vault not mounted at {MOUNT_ROOT}. Run: scripts/safety/vault.sh mount"
        )
    return MOUNT_ROOT


def ensure_layout() -> None:
    """Create standard vault subdirectories (vault must already be mounted)."""
    root = assert_mounted()
    for name in VAULT_SUBDIRS:
        (root / name).mkdir(parents=True, exist_ok=True)


def resolve_staging_path(dest: Path | str) -> Path:
    """Resolve dest under STAGING_DIR; reject paths outside staging."""
    staging = assert_mounted() / "staging"
    target = Path(dest)
    if not target.is_absolute():
        target = staging / target
    target = target.resolve()
    staging_resolved = staging.resolve()
    try:
        target.relative_to(staging_resolved)
    except ValueError as exc:
        raise ValueError(f"refusing destination outside staging: {target}") from exc
    return target


def quarantine_archive_path(sha256: str) -> Path:
    """Path to the sealed 7z for a sample hash."""
    digest = sha256.strip().lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError(f"invalid sha256: {sha256!r}")
    return assert_mounted() / "quarantine" / f"{digest}.7z"


def sync_managed_roots() -> tuple[Path, ...]:
    """Known macOS sync roots that must not contain the sparse bundle."""
    home = Path.home()
    return (
        home / "Documents",
        home / "Desktop",
        home / "Library" / "Mobile Documents",
        home / "Dropbox",
        home / "Google Drive",
        home / "Library" / "CloudStorage",
    )


def sparse_bundle_under_sync_root() -> bool:
    """True if SPARSE_BUNDLE resolves under a known sync-managed directory."""
    bundle = SPARSE_BUNDLE.resolve()
    for root in sync_managed_roots():
        if not root.exists():
            continue
        try:
            bundle.relative_to(root.resolve())
            return True
        except ValueError:
            continue
    return False


def mountpoint_device() -> str | None:
    """Best-effort device node for the mounted vault (for status checks)."""
    if not is_mounted():
        return None
    try:
        proc = subprocess.run(
            ["mount"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    needle = f" on {MOUNT_ROOT} "
    for line in (proc.stdout or "").splitlines():
        if needle in line:
            return line.split(" on ", 1)[0].strip()
    return None
