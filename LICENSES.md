# Third-Party Sources and Redistribution Notes

This file documents runtime data/metadata sources used by ContextDroid and the repository's redistribution boundaries.

## What ContextDroid Redistributes

- Source code in this repository only.
- No APK binaries are included.
- No private/internal datasets are included.
- No external metadata dumps are bundled by default.

## Runtime Metadata Sources

ContextDroid may query external metadata sources at runtime to build LLM context and support reproducible experiment runs.

### Google Play metadata (runtime query only)

- Used as the first metadata source in the fallback chain.
- Queried at runtime; not redistributed by this repository.
- Users are responsible for complying with Google Play and any API/tool terms they use.

### F-Droid API metadata (runtime query only)

- Used as fallback metadata source.
- Queried at runtime from public F-Droid endpoints.
- Not redistributed by this repository as a packaged metadata dataset.

### APK-only inference inputs

- Derived from APK static metadata available locally on the user's machine.
- Used when external metadata is unavailable.

## AndroZoo (optional user-side source)

- If users incorporate AndroZoo-derived inputs, usage must comply with their institutional/user agreement and terms.
- This repository does not redistribute AndroZoo APKs or proprietary metadata payloads.

## Produced Artifacts

- Generated dynamic traces and derived CSV/JSON outputs are produced locally under `logs/`.
- Users are responsible for legal/ethical handling and publication decisions for generated artifacts.
- Do not publish APK binaries unless allowed by upstream licenses/terms.

## Operator Responsibility

By running ContextDroid, you acknowledge responsibility for:

- complying with source-specific terms and licenses,
- operating in isolated/sandboxed environments,
- ensuring rights to process and share any resulting outputs.
