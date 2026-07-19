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
- The Episodes / Publish page can generate a static RSS feed from existing files in `media/converted/`.
- Configure `PODRUSH_PUBLIC_BASE_URL` and `PODRUSH_UPLOAD_TARGET` to mirror `media/converted/` to a static hosting path with `rsync --delete`.

## Storage & filenames
- SQLite database: `db.sqlite` (auto-created).
- Originals: `media/original/<date>-id<episode_id>-orig.mp3`.
- Converted: `media/converted/<date>-id<episode_id>-<speed>x.mp3` (UI discovers existing conversions by scanning this folder).
- Private feed: `media/converted/<PODRUSH_FEED_FILENAME>` (default `podrush-feed.xml`).

## Static private podcast feed
Set these environment variables before using the upload button:

```bash
PODRUSH_PUBLIC_BASE_URL=https://mydomain.com/data/podrush
PODRUSH_UPLOAD_TARGET=user@host:/path/to/data/podrush/
PODRUSH_FEED_FILENAME=podrush-feed.xml
```

The feed is regenerated from disk when the Episodes / Publish page loads and after convert/delete/retag actions. Every matching converted MP3 becomes a separate RSS item, and metadata comes from SQLite by parsing the episode id in the filename. Files deleted from disk disappear from the next generated feed.

Each item includes an `<itunes:duration>` (the source episode duration divided by the conversion speed, matching the actual MP3 length). The channel includes `<image>` / `<itunes:image>` cover art: `static/cover.png` is copied into `media/converted/` on every feed regeneration, so it is mirrored by rsync alongside the MP3s. Replace `static/cover.png` to customize the cover.

Upload uses `rsync -av --delete --exclude .DS_Store media/converted/ "$PODRUSH_UPLOAD_TARGET"` so the remote directory mirrors local converted files.

Spotify/Garmin note: this creates a normal static RSS feed for testing private podcast ingestion. Spotify's Garmin app supports offline podcast downloads, but arbitrary private RSS ingestion may not be supported directly by Spotify.

## Notes
- Conversion uses `ffmpeg -filter:a atempo=<speed>`.
- Feed refresh staleness is configurable with `FEED_REFRESH_MAX_AGE_HOURS` (or `REFRESH_MAX_AGE_HOURS`).
- HTMX provides the button-to-link swap; spinners indicate in-progress conversions.
