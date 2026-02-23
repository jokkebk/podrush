# Podrush

Minimal Bun + TypeScript + HTMX web app to download podcast episodes and create sped-up MP3s for Garmin (or any device).

## Prerequisites
- Bun
- `ffmpeg` in PATH (used for audio conversion)
- Optional: `.env` with `USER_AGENT`, `MAX_SLUG_LEN`, or `GOOGLE_API_KEY` (if you enable AI naming)

## Setup
```bash
bun install               # install dependencies
bun --hot run index.ts
```
Then open http://localhost:3000/feeds.

## Usage
- Add an RSS feed URL.
- Feeds auto-refresh in the background when they are stale (default: 24h).
- Use the `Refresh now` button to force an immediate background refresh.
- Click a speed button (1.1x–2.0x) to convert; existing conversions show as download links.
- Original downloads are cached under `media/original/`; converted files live in `media/converted/`.

## Storage & filenames
- SQLite database: `db.sqlite` (auto-created).
- Originals: `media/original/<date>-id<episode_id>-orig.mp3`.
- Converted: `media/converted/<date>-id<episode_id>-<speed>x.mp3` (UI discovers existing conversions by scanning this folder).

## Notes
- Conversion uses `ffmpeg -filter:a atempo=<speed>`.
- Feed refresh staleness is configurable with `FEED_REFRESH_MAX_AGE_HOURS` (or `REFRESH_MAX_AGE_HOURS`).
- HTMX provides the button-to-link swap; spinners indicate in-progress conversions.
