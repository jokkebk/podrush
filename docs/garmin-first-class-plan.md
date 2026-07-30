# First-class, optional Garmin support

## Outcome

Make direct Garmin podcast transfer a first-class Podrush workflow with its own
page and navigation entry, while keeping every Garmin-specific dependency and
side effect optional.

A user who never opens the Garmin page must be able to use feeds, conversion,
and publishing exactly as before. Opening the Garmin page must not download or
compile anything until the user explicitly asks Podrush to connect to a watch.

## User experience

1. Add a persistent **Garmin** item to the primary navigation.
2. Serve a dedicated `/garmin` page with:
   - a short explanation of direct USB transfer;
   - connection instructions;
   - an explicit **Connect to watch** action;
   - a clear note that Garmin Express, Apple Music, and Rosetta are unnecessary.
3. Do not scan USB or bootstrap native tooling on initial page load. The connect
   action is the boundary that permits the one-time source download and build.
4. Once connected, show:
   - watch model and storage usage;
   - converted Podrush MP3s not already present on the watch;
   - files currently in the watch's Podcasts folder;
   - selection-based send and remove actions;
   - refresh/reconnect controls and actionable error states.
5. Keep “Episodes / Publish” focused on converted-file and RSS management.
   Garmin remains one click away through the primary navigation.

## Architecture

Keep the feature compartmentalized behind three layers:

```text
Dedicated Garmin page and HTMX fragments
                 |
        Garmin HTTP handlers
                 |
    Garmin transport (`garmin.ts`)
                 |
  Native libmtp helper (`native/`)
```

- The page and handlers may depend on the Garmin transport.
- Feed, audio conversion, and podcast-publishing modules must not depend on it.
- Importing the transport must remain side-effect free.
- Downloading libusb/libmtp, compiling the helper, and touching USB must happen
  only after an explicit connect/send/remove request.
- Preserve `PODRUSH_GARMIN_MTP_HELPER` as a test/development override.
- Keep generated sources, libraries, and binaries under the ignored
  `media/.garmin-mtp/` cache; do not install anything system-wide.
- Continue to verify pinned dependency archives by SHA-256 and build for the
  current Mac architecture.

## Implementation tasks

- Add `serveGarminPage` and a `/garmin` route.
- Add the Garmin navigation item to the shared page shell.
- Add a static disconnected/intro renderer that does not trigger `/api/garmin`
  automatically.
- Reuse the connected watch panel for scan, send, delete, and refresh results.
- Remove the automatically loading Garmin panel from converted management.
- Adjust headings and copy so Garmin and publishing are distinct workflows.
- Keep unavailable/unsupported states contained within the Garmin page.
- Add tests for:
  - dedicated page/navigation rendering;
  - no automatic scan/bootstrap on initial page render;
  - connected, disconnected, escaping, duplicate, send, and remove UI states;
  - continued absence of Garmin Express and x86-only dependencies.
- Update the README with the dedicated route and explicit optionality.

## Acceptance criteria

- `/garmin` is reachable from every page through primary navigation.
- Loading `/`, `/converted`, or `/garmin` performs no USB operation and does not
  create `media/.garmin-mtp/`.
- Clicking **Connect to watch** is the first operation allowed to bootstrap the
  native helper and scan USB.
- A connected Garmin can list, receive, and delete podcast MP3s from the
  dedicated page.
- Garmin failures do not interfere with feeds, conversion, or RSS publishing.
- The app builds successfully and focused tests pass.
- The implementation remains native on Apple Silicon and has no Garmin Express,
  Apple Music, Rosetta, Homebrew, or administrator requirement.
