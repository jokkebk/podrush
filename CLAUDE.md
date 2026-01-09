# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Podrush is a podcast download manager and audio converter built with Bun + TypeScript + HTMX + SQLite. It downloads podcast episodes from RSS feeds and creates variable-speed MP3s (1.1x–2.0x) using ffmpeg, optimized for devices like Garmin watches.

## Commands

```bash
bun install              # Install dependencies
bun --hot run index.ts   # Run dev server with hot reload (http://localhost:3000/feeds)
bun test                 # Run tests
```

**System requirements:** ffmpeg and ffprobe must be in PATH for audio conversion and ID3 tag handling.

## Architecture

### Entry Points

- `index.ts` - Main server (~930 lines): routing, request handlers, HTML rendering, audio pipeline
- `feedService.ts` - Feed parsing and database operations
- `gemini_shorthand.ts` - Optional Google Gemini integration for AI-generated file naming

### Server & Routing

Uses Bun's native `serve()` API with declarative route definitions (bottom of index.ts). HTML-over-HTTP pattern with HTMX for interactivity - no JSON APIs, server returns HTML fragments that HTMX swaps in place.

### Database

SQLite via `bun:sqlite` (built-in). Auto-created `db.sqlite` with two tables:
- `feeds` - RSS feed metadata and shorthand names
- `episodes` - Episode data with audio URLs and local file paths

All queries use prepared statements declared at module top-level.

### Audio Pipeline

1. **Download**: Fetch original MP3 from feed → save to `media/original/`
2. **Convert**: Run ffmpeg with `atempo` filter → output to `media/converted/`
3. **Discover**: Scan `media/converted/` with regex matching `-id<N>-<speed>x.mp3` pattern

Key functions: `ensureOriginalAudio()`, `convertAudio()`, `listConvertedByEpisode()`, `buildFilenameBase()`

### Feed Parsing

`feedService.ts` handles RSS/Atom/JSON Feed formats via `feedsmith` library. Normalization functions extract episodes with audio URLs, durations, and publish dates. Feed refresh is automatic (6-hour stale threshold).

### UI

- HTML templates in `/html` directory (Pico CSS + HTMX)
- Server-side rendering with TypeScript template literals
- No client-side framework

### Data Storage

- `db.sqlite` - Episode and feed metadata (gitignored)
- `media/original/` - Downloaded original MP3s (gitignored)
- `media/converted/` - Speed-converted MP3s (gitignored)

## Environment Variables

See `.env.example`. Key optional settings:
- `GEMINI_API_KEY` / `GOOGLE_API_KEY` - Enable AI shorthand naming
- `GEMINI_MODEL` - AI model (default: gemini-2.5-flash)
- `USER_AGENT` - HTTP User-Agent for feed fetching
- `MAX_SLUG_LEN` - Max filename part length (default: 40)
