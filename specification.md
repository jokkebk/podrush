# **podrush – Minimal Web App Specification**

A lightweight personal web application for preparing **sped-up podcast audio** for Garmin watches.

## **1. Overview**

**podrush** enables:

1. Adding podcast RSS feeds
2. Automatically fetching and parsing episodes
3. Browsing feeds/episodes via a clean modern UI
4. One-click audio speed conversion using ffmpeg

The entire project must remain **compact**, **easy to understand**, and require **minimal setup**.

Target languages: **Python + JavaScript (htmx)**.

Run via a single command:

```
uv run uvicorn podrush.app:app --reload
```

## **2. Technology Stack**

### **Backend**

- **FastAPI** – minimal boilerplate, async I/O, built-in docs
- **SQLite** via Python sqlite3
- **RSS parsing:** feedparser
- **HTTP client:** httpx
- **Audio conversion:** ffmpeg via subprocess.run
- **Templates:** Jinja2
- **Static serving:** FastAPI StaticFiles

### **Frontend**

- **htmx** – minimal JavaScript, declarative interactions
- **Pico.css** – elegant and responsive styling with zero configuration
- **HTML templates** – server-rendered pages

No SPA, no JS build system.

## **3. Project Structure**

```
podrush/
  app.py                     # all backend logic
  db.sql                     # SQLite DB (auto-created)
  media/
    original/                # downloaded podcast audio
    converted/               # ffmpeg outputs
  templates/
    base.html
    feeds.html
    feed_detail.html
  static/
    favicon.ico (optional)
```

## **4. Database Schema (SQLite)**

### **feeds**

| **Column**   | **Type**     | **Notes** |
| ------------ | ------------ | --------- |
| id           | INTEGER PK   |           |
| url          | TEXT UNIQUE  |           |
| title        | TEXT         |           |
| description  | TEXT         |           |
| image_url    | TEXT         |           |
| last_checked | DATETIME UTC |           |

### **episodes**

| **Column**    | **Type**                     | **Notes**       |
| ------------- | ---------------------------- | --------------- |
| id            | INTEGER PK                   |                 |
| feed_id       | INTEGER REFERENCES feeds(id) |                 |
| guid          | TEXT                         | unique per feed |
| title         | TEXT                         |                 |
| description   | TEXT                         |                 |
| audio_url     | TEXT                         |                 |
| published_at  | DATETIME                     |                 |
| duration_secs | INTEGER NULL                 |                 |
| local_path    | TEXT NULL                    | when downloaded |

**Converted files are not stored in DB**, only generated on demand.

Path naming:

- Original: media/original/episode_<id>.mp3
- Converted: media/converted/episode_<id>_<speed>x.mp3

## **5. Backend Responsibilities**

### **Startup**

- Create DB file & tables if missing
- Ensure media folders exist
- Initialize templates & static mount

### **RSS Refresh Logic**

- refresh_feed_if_stale(feed, max_age_hours=6)
- refresh_feed(feed_id, url)
  - GET RSS using httpx
  - Parse via feedparser
  - Update feed metadata
  - Upsert episodes

Refresh happens automatically whenever a user views a feed.

## **6. Routes**

### **Navigation**

| **Method** | **Path**               | **Description**                |
| ---------- | ---------------------- | ------------------------------ |
| GET        | /                      | redirect → /feeds              |
| GET        | /feeds                 | list feeds, auto-refresh stale |
| POST       | /feeds                 | add new RSS feed               |
| GET        | /feeds/{feed_id}       | view feed + episodes           |
| POST       | /episodes/{id}/convert | convert audio at speed         |

### **Conversion Logic**

1. Fetch episode record
2. Ensure local audio is downloaded (if missing)
3. Build target filename
4. If converted file does not exist:



```
ffmpeg -i input.mp3 -filter:a atempo=1.5 output.mp3
```

5. Return an HTML snippet which replaces the button via htmx

→ produces a direct download link

## **7. Templates (HTML)**

### **base.html**

Includes:

- Pico.css CDN
- htmx CDN
- App header wrapper

### **feeds.html**

- Form to add RSS feed
- List of feeds with title + description

### **feed_detail.html**

- Shows feed metadata

- For each episode:

  

  - title, published date, description snippet
  - grid of speed buttons (1.1x, 1.25x, 1.5x, 1.75x, 2x)
  - each button is an htmx POST that swaps itself with a “download file” link

## **8. Example htmx Button**

```
<button
  hx-post="/episodes/{{ ep.id }}/convert"
  hx-vals='{"speed": "1.5"}'
  hx-target="this"
  hx-swap="outerHTML">
  1.5x
</button>
```

Server responds with:

```
<a href="/media/converted/episode_12_1.5x.mp3" download>
  Download 1.5x
</a>
```



## **9. pyproject.toml (minimal)**

```
[project]
name = "podrush"
version = "0.1.0"
dependencies = [
  "fastapi",
  "uvicorn[standard]",
  "jinja2",
  "httpx",
  "feedparser",
]
```

## **10. Running the App**

```
uv run uvicorn podrush.app:app --reload
```

Open:

```
http://127.0.0.1:8000
```

## **11. Design Principles**

- **Smallest codebase possible**
- **Readable Python and HTML**
- **Minimal dependencies**
- **Server-rendered pages + htmx = modern without complexity**
- **No massive error-handling required (personal-use)**
- **Easily extensible** (auth, multiuser, background tasks later)