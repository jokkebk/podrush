from __future__ import annotations

import sqlite3
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import feedparser
import httpx
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "db.sql"
MEDIA_DIR = BASE_DIR / "media"
ORIGINAL_DIR = MEDIA_DIR / "original"
CONVERTED_DIR = MEDIA_DIR / "converted"
USER_AGENT = "podrush/0.1"


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS feeds (
                id INTEGER PRIMARY KEY,
                url TEXT UNIQUE,
                title TEXT,
                description TEXT,
                image_url TEXT,
                last_checked TEXT
            );
            CREATE TABLE IF NOT EXISTS episodes (
                id INTEGER PRIMARY KEY,
                feed_id INTEGER REFERENCES feeds(id),
                guid TEXT,
                title TEXT,
                description TEXT,
                audio_url TEXT,
                published_at TEXT,
                duration_secs INTEGER,
                local_path TEXT,
                UNIQUE(feed_id, guid)
            );
            """
        )


def ensure_media_dirs() -> None:
    ORIGINAL_DIR.mkdir(parents=True, exist_ok=True)
    CONVERTED_DIR.mkdir(parents=True, exist_ok=True)


def parse_duration(raw: Any) -> int | None:
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return int(raw)
    if not isinstance(raw, str):
        return None
    parts = raw.split(":")
    try:
        if len(parts) == 3:
            hours, minutes, seconds = (int(p) for p in parts)
            return hours * 3600 + minutes * 60 + seconds
        if len(parts) == 2:
            minutes, seconds = (int(p) for p in parts)
            return minutes * 60 + seconds
        return int(raw)
    except ValueError:
        return None


def format_speed(speed: float) -> str:
    text = f"{speed:.2f}"
    return text.rstrip("0").rstrip(".")


def parse_published(entry: Any) -> str | None:
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if not parsed:
        return None
    dt = datetime(*parsed[:6], tzinfo=timezone.utc)
    return dt.isoformat()


def audio_from_entry(entry: Any) -> str | None:
    enclosures = entry.get("enclosures") or []
    if enclosures and "href" in enclosures[0]:
        return enclosures[0]["href"]
    if enclosures and "url" in enclosures[0]:
        return enclosures[0]["url"]
    return entry.get("link")


def refresh_feed_if_stale(feed: sqlite3.Row, max_age_hours: int = 6) -> None:
    last_checked = feed["last_checked"]
    if last_checked:
        try:
            checked_at = datetime.fromisoformat(last_checked)
            if checked_at > datetime.now(timezone.utc) - timedelta(hours=max_age_hours):
                return
        except ValueError:
            pass
    refresh_feed(feed["id"], feed["url"])


def refresh_feed(feed_id: int, url: str) -> None:
    try:
        response = httpx.get(
            url,
            timeout=15,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        response.raise_for_status()
    except Exception:
        return

    parsed = feedparser.parse(response.text)
    feed_meta = parsed.get("feed", {})
    title = feed_meta.get("title") or url
    description = feed_meta.get("subtitle") or feed_meta.get("description")
    image_url = None
    image_field = feed_meta.get("image") or {}
    if isinstance(image_field, dict):
        image_url = image_field.get("href")

    now_iso = datetime.now(timezone.utc).isoformat()
    entries = parsed.entries or []

    with get_db() as conn:
        conn.execute(
            "UPDATE feeds SET title = ?, description = ?, image_url = ?, last_checked = ? WHERE id = ?",
            (title, description, image_url, now_iso, feed_id),
        )

        for entry in entries:
            guid = (
                entry.get("id")
                or entry.get("guid")
                or entry.get("link")
                or entry.get("title")
            )
            audio_url = audio_from_entry(entry)
            if not guid or not audio_url:
                continue

            published_at = parse_published(entry)
            duration_secs = parse_duration(entry.get("itunes_duration"))
            conn.execute(
                """
                INSERT INTO episodes (feed_id, guid, title, description, audio_url, published_at, duration_secs)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(feed_id, guid) DO UPDATE SET
                    title = excluded.title,
                    description = excluded.description,
                    audio_url = excluded.audio_url,
                    published_at = excluded.published_at,
                    duration_secs = excluded.duration_secs
                """,
                (
                    feed_id,
                    guid,
                    entry.get("title"),
                    entry.get("summary"),
                    audio_url,
                    published_at,
                    duration_secs,
                ),
            )


async def ensure_original_audio(episode: sqlite3.Row) -> Path:
    target = ORIGINAL_DIR / f"episode_{episode['id']}.mp3"
    if target.exists():
        return target
    audio_url = episode["audio_url"]
    if not audio_url:
        raise HTTPException(status_code=400, detail="Missing audio URL for episode.")
    try:
        async with httpx.AsyncClient(
            follow_redirects=True, headers={"User-Agent": USER_AGENT}
        ) as client:
            async with client.stream("GET", audio_url, timeout=60) as resp:
                resp.raise_for_status()
                with target.open("wb") as f:
                    async for chunk in resp.aiter_bytes():
                        f.write(chunk)
    except Exception as exc:  # pragma: no cover - network issues are runtime concerns
        if target.exists():
            target.unlink(missing_ok=True)
        raise HTTPException(status_code=502, detail=f"Download failed: {exc}") from exc

    with get_db() as conn:
        conn.execute(
            "UPDATE episodes SET local_path = ? WHERE id = ?",
            (str(target), episode["id"]),
        )
    return target


def convert_audio(original: Path, target: Path, speed: float) -> None:
    if target.exists():
        return
    cmd = [
        "ffmpeg",
        "-i",
        str(original),
        "-filter:a",
        f"atempo={speed}",
        str(target),
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        raise HTTPException(
            status_code=500, detail=f"ffmpeg conversion failed: {exc.stderr}"
        ) from exc


app = FastAPI()

ensure_media_dirs()
init_db()

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
app.mount("/media", StaticFiles(directory=BASE_DIR / "media"), name="media")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.get("/", response_class=HTMLResponse)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/feeds")


@app.get("/feeds", response_class=HTMLResponse)
async def list_feeds(request: Request) -> HTMLResponse:
    with get_db() as conn:
        feeds = conn.execute("SELECT * FROM feeds ORDER BY id DESC").fetchall()

    for feed in feeds:
        refresh_feed_if_stale(feed)

    with get_db() as conn:
        refreshed = conn.execute("SELECT * FROM feeds ORDER BY id DESC").fetchall()

    return templates.TemplateResponse(
        "feeds.html",
        {"request": request, "feeds": refreshed},
    )


@app.post("/feeds")
async def add_feed(url: str = Form(...)) -> RedirectResponse:
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM feeds WHERE url = ?", (url,)).fetchone()
        if existing:
            feed_id = existing["id"]
        else:
            cursor = conn.execute(
                "INSERT INTO feeds (url, last_checked) VALUES (?, ?)",
                (url, None),
            )
            feed_id = cursor.lastrowid

    refresh_feed(feed_id, url)
    return RedirectResponse(url="/feeds", status_code=303)


@app.get("/feeds/{feed_id}", response_class=HTMLResponse)
async def feed_detail(feed_id: int, request: Request) -> HTMLResponse:
    with get_db() as conn:
        feed = conn.execute("SELECT * FROM feeds WHERE id = ?", (feed_id,)).fetchone()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    refresh_feed_if_stale(feed)

    with get_db() as conn:
        episodes = conn.execute(
            """
            SELECT * FROM episodes
            WHERE feed_id = ?
            ORDER BY published_at IS NULL, published_at DESC, id DESC
            """,
            (feed_id,),
        ).fetchall()

    speeds = [1.1, 1.25, 1.5, 1.75, 2.0]
    return templates.TemplateResponse(
        "feed_detail.html",
        {"request": request, "feed": feed, "episodes": episodes, "speeds": speeds},
    )


@app.post("/episodes/{episode_id}/convert", response_class=HTMLResponse)
async def convert_episode(episode_id: int, speed: str = Form(...)) -> HTMLResponse:
    try:
        speed_value = float(speed)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid speed value")
    if speed_value <= 0:
        raise HTTPException(status_code=400, detail="Speed must be positive")

    with get_db() as conn:
        episode = conn.execute(
            "SELECT * FROM episodes WHERE id = ?", (episode_id,)
        ).fetchone()
    if not episode:
        raise HTTPException(status_code=404, detail="Episode not found")

    original_path = await ensure_original_audio(episode)
    speed_label = format_speed(speed_value)
    converted_path = CONVERTED_DIR / f"episode_{episode_id}_{speed_label}x.mp3"
    convert_audio(original_path, converted_path, speed_value)

    html = (
        f'<a href="/media/converted/{converted_path.name}" download>'
        f"Download {speed_label}x"
        "</a>"
    )
    return HTMLResponse(content=html)
