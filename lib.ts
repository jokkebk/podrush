import { mkdirSync } from "fs";
import { join } from "path";
import { db, type FeedRow } from "./feedService";

export type { FeedRow };

// ─── Constants ────────────────────────────────────────────
export const MEDIA_DIR = "./media";
export const ORIGINAL_DIR = join(MEDIA_DIR, "original");
export const CONVERTED_DIR = join(MEDIA_DIR, "converted");
export const SPEEDS = [1.1, 1.25, 1.5];
export const MAX_AUDIO_SIZE = 500 * 1024 * 1024; // 500 MB
export const EPISODES_PER_PAGE = 20;
export const env = Bun.env;
export const USER_AGENT = env.USER_AGENT || "podrush/0.1";
export const hasGeminiKey = Boolean(env.GEMINI_API_KEY || env.GOOGLE_API_KEY);
export const log = (...args: unknown[]) =>
  console.info(new Date().toISOString(), "[podrush]", ...args);

// ─── Types ────────────────────────────────────────────────
export type EpisodeRow = {
  id: number;
  feed_id: number;
  guid: string;
  title: string | null;
  description: string | null;
  audio_url: string;
  published_at: string | null;
  duration_secs: number | null;
  local_path?: string | null;
  short_name?: string | null;
};

export type ConvertedEntry = {
  filename: string;
  path: string;
  episodeId?: number;
  speedLabel?: string;
  episodeTitle?: string | null;
  feedTitle?: string | null;
  publishedAt?: string | null;
};

// ─── Text utilities ───────────────────────────────────────
export const escapeHtml = (str: string): string =>
  str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");

export const plainText = (html: string): string =>
  html.replace(/<[^>]*>/g, " ").replace(/&[a-z]+;/g, " ").replace(/\s+/g, " ").trim();

export const sanitizeHtml = (html: string): string =>
  html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "")
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, "")
    .replace(/<\/?(iframe|object|embed|form|input|button|select|textarea|base|meta|link)\b[^>]*>/gi, "")
    .replace(/\s+on\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "")
    .replace(/\s+style\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "")
    .replace(/(href|src)\s*=\s*"javascript:[^"]*"/gi, '')
    .replace(/(href|src)\s*=\s*'javascript:[^']*'/gi, '');

export const descriptionDetails = (html: string): string => {
  if (!html) return "";
  const safe = sanitizeHtml(html);
  return `
    <div class="ep-description is-collapsed" data-ep-description>
      ${safe}
    </div>
    <button type="button" class="ep-description-toggle" data-ep-toggle hidden>Show more</button>`;
};

// ─── General utilities ────────────────────────────────────
export const fetchWithTimeout = async (
  url: string,
  options: RequestInit = {},
  timeoutMs: number = 30000
): Promise<Response> => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
};

export const slugify = (input: string, maxLen = 48) => {
  const normalized = input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, maxLen);
  return normalized || "item";
};

export const formatTimestamp = (value: string | null): string => {
  if (!value) return "never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const year = date.getFullYear();
  const month = (date.getMonth() + 1).toString().padStart(2, "0");
  const day = date.getDate().toString().padStart(2, "0");
  const hours = date.getHours().toString().padStart(2, "0");
  const minutes = date.getMinutes().toString().padStart(2, "0");
  return `${year}-${month}-${day} ${hours}:${minutes}`;
};

export const formatDuration = (seconds: number | null): string => {
  if (seconds === null || !Number.isFinite(seconds)) return "";
  const total = Math.max(0, Math.floor(seconds));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  if (hours > 0) return `${hours}:${minutes.toString().padStart(2, "0")}:${secs
    .toString()
    .padStart(2, "0")}`;
  return `${minutes}:${secs.toString().padStart(2, "0")}`;
};

export const formatSpeedLabel = (speed: number) => speed.toFixed(2).replace(/\.?0+$/, "");

export const formatId3Date = (value: string | null) => {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  const year = date.getUTCFullYear();
  const month = (date.getUTCMonth() + 1).toString().padStart(2, "0");
  const day = date.getUTCDate().toString().padStart(2, "0");
  return `${year}-${month}-${day}`;
};

export const episodeDateStamp = (episode: EpisodeRow): string | null => {
  if (!episode.published_at) return null;
  const date = new Date(episode.published_at);
  if (Number.isNaN(date.getTime())) return null;
  const year = date.getUTCFullYear();
  const month = (date.getUTCMonth() + 1).toString().padStart(2, "0");
  const day = date.getUTCDate().toString().padStart(2, "0");
  return `${year}${month}${day}`;
};

// ─── Response helpers ─────────────────────────────────────
export const htmlResponse = (body: string, status = 200) =>
  new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });

export const notFound = () =>
  new Response("Not found", { status: 404, headers: { "Content-Type": "text/plain" } });

export const logRequest = (request: Request) => {
  const { pathname } = new URL(request.url);
  log("Incoming request", { method: request.method, pathname });
};

export const getRouteParam = (request: Request, key: string) =>
  (request as Request & { params?: Record<string, string> }).params?.[key];

// ─── DB prepared statements ───────────────────────────────
export const selectFeeds = db.prepare(
  `SELECT id, url, title, description, image_url, last_checked, short_name
   FROM feeds ORDER BY id DESC`
);

export const selectFeedById = db.prepare(
  `SELECT id, url, title, description, image_url, last_checked, short_name
   FROM feeds WHERE id = ?`
);

export const selectEpisodesForFeed = db.prepare(
  `SELECT id, feed_id, guid, title, description, audio_url, published_at, duration_secs, local_path, short_name
   FROM episodes WHERE feed_id = ?
   ORDER BY published_at IS NULL, published_at DESC, id DESC`
);

export const selectEpisodeById = db.prepare(
  `SELECT id, feed_id, guid, title, description, audio_url, published_at, duration_secs, local_path, short_name
   FROM episodes WHERE id = ?`
);

export const selectEpisodeWithFeed = db.prepare(
  `SELECT
    episodes.id,
    episodes.title AS episode_title,
    episodes.published_at AS published_at,
    feeds.title AS feed_title
  FROM episodes
  JOIN feeds ON feeds.id = episodes.feed_id
  WHERE episodes.id = ?`
);

export const findFeedByUrl = db.prepare("SELECT id FROM feeds WHERE url = ?");
export const insertFeed = db.prepare("INSERT INTO feeds (url, last_checked) VALUES (?, NULL)");
export const updateFeedShortName = db.prepare("UPDATE feeds SET short_name = ? WHERE id = ?");
export const updateEpisodeShortName = db.prepare("UPDATE episodes SET short_name = ? WHERE id = ?");
export const updateEpisodeLocalPath = db.prepare("UPDATE episodes SET local_path = ? WHERE id = ?");

// ─── Race condition guards ────────────────────────────────
export const conversionsInProgress = new Set<string>();
export const feedShortNameInProgress = new Set<number>();
export const episodeShortNameInProgress = new Set<number>();

// ─── Directory init ───────────────────────────────────────
mkdirSync(ORIGINAL_DIR, { recursive: true });
mkdirSync(CONVERTED_DIR, { recursive: true });
