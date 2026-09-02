# Manifest schema (malware tier)

Tracked schema only — sample bytes and AndroZoo CSV dumps stay outside git
(see root `.gitignore`). Runtime files live on the vault manifest directory
once Phase 1 is complete (`vault_paths.MANIFEST_DIR`).

## `manifest.csv` columns (Phase 2)

`sha256, sha1, pkg_name, vercode, apk_size, dex_date, dex_size, vt_detection,
vt_scan_date, family, family_source, family_confidence, market, download_utc,
sha256_verified, sealed_path, status`

`status` ∈ `{selected, downloaded, verified, sealed, rejected}`.
