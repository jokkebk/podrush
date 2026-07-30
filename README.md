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
- The built-in "Custom uploads" feed accepts your own MP3s: open its page, use the upload form (title, publish date, speeds), and the file flows through the same conversion, tagging, and private-feed pipeline as regular episodes.
- Original downloads are cached under `media/original/`; converted files live in `media/converted/`.
- The Episodes / Publish page can generate a static RSS feed from existing files in `media/converted/`.
- On macOS, the optional [Garmin page](http://localhost:3000/garmin) can send converted MP3s straight to a connected Garmin music watch and remove podcast-tagged files from either its Podcasts folder or Garmin Express's nested Music layout. Garmin Express, Apple Music, and Rosetta are not required.
- Configure `PODRUSH_PUBLIC_BASE_URL` and `PODRUSH_UPLOAD_TARGET` to mirror `media/converted/` to a static hosting path with `rsync --delete`.

## Storage & filenames
- SQLite database: `db.sqlite` (auto-created).
- Originals: `media/original/<date>-id<episode_id>-orig.mp3`.
- Converted: `media/converted/<date>-id<episode_id>-<speed>x.mp3` (UI discovers existing conversions by scanning this folder).
- Private feed: `media/converted/<PODRUSH_FEED_FILENAME>` (default `podrush-feed.xml`).

## Static private podcast feed
Set these environment variables before using the upload button:

```bash
PODRUSH_PUBLIC_BASE_URL=https://podrush.example.com
PODRUSH_UPLOAD_TARGET=r2:my-bucket/
PODRUSH_FEED_FILENAME=podrush-feed.xml
```

The feed is regenerated from disk when the Episodes / Publish page loads and after convert/delete/retag actions. Every matching converted MP3 becomes a separate RSS item, and metadata comes from SQLite by parsing the episode id in the filename. Files deleted from disk disappear from the next generated feed.

Each item includes an `<itunes:duration>` (the source episode duration divided by the conversion speed, matching the actual MP3 length). The channel includes `<image>` / `<itunes:image>` cover art: `static/cover.png` is copied into `media/converted/` on every feed regeneration, so it is mirrored by rsync alongside the MP3s. Replace `static/cover.png` to customize the cover.

### Upload targets

The upload command is chosen from the shape of `PODRUSH_UPLOAD_TARGET`, so both object storage and a plain server work:

| Target looks like | Command used | Example |
| --- | --- | --- |
| `remote:path` (no `@`, no `/` right after the colon) | `rclone sync` | `r2:my-bucket/` |
| `user@host:/path` or `host:/path` | `rsync -av --delete` | `user@host:/srv/podrush/` |

Either way it is a **mirror**: files removed locally are removed remotely, which is what keeps the feed honest. `.DS_Store` and macOS AppleDouble files are excluded.

For an rclone target, configure the remote once with `rclone config` (for Cloudflare R2: storage `s3`, provider `Cloudflare`, `region = auto`, and the account's `https://<account-id>.r2.cloudflarestorage.com` endpoint). Two details matter:

- `--s3-no-check-bucket` is passed automatically, because an R2 API token scoped to specific buckets is not permitted the bucket-level check rclone would otherwise attempt.
- `robots.txt` is excluded from the mirror. If such an object lives in the bucket root it exists only remotely, so a root mirror would otherwise delete it on every upload.

Spotify/Garmin note: this creates a normal static RSS feed for testing private podcast ingestion. Spotify's Garmin app supports offline podcast downloads, but arbitrary private RSS ingestion may not be supported directly by Spotify.

## Notes
- Conversion uses `ffmpeg -filter:a atempo=<speed>`.
- Direct Garmin transfer is optional and currently targets macOS. Podrush does not scan USB, download dependencies, or build anything until **Connect to watch** is clicked on `/garmin`. The first connection downloads integrity-checked libusb 1.0.29 and libmtp 1.1.22 source releases, then builds a native local adapter in `media/.garmin-mtp/`. Xcode Command Line Tools (`clang` and `make`) and an internet connection are required for that one-time build. Later transfers use the cached native adapter. Only one MTP app can control the watch at a time.
- Feed refresh staleness is configurable with `FEED_REFRESH_MAX_AGE_HOURS` (or `REFRESH_MAX_AGE_HOURS`).
- HTMX provides the button-to-link swap; spinners indicate in-progress conversions.
