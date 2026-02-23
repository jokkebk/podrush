import { serve } from "bun";
import { mkdirSync, readdirSync, renameSync, statSync, unlinkSync } from "fs";
import { join, resolve } from "path";
import { db, refreshFeed, refreshFeedsIfStale, type FeedRow } from "./feedService";
import { generateGeminiShorthand } from "./gemini_shorthand";

const indexPage = Bun.file("./html/index.html");
const feedPage = Bun.file("./html/feed.html");
const convertedPage = Bun.file("./html/converted.html");

const MEDIA_DIR = "./media";
const ORIGINAL_DIR = join(MEDIA_DIR, "original");
const CONVERTED_DIR = join(MEDIA_DIR, "converted");
const SPEEDS = [1.1, 1.25, 1.5];
const MAX_AUDIO_SIZE = 500 * 1024 * 1024; // 500 MB
const EPISODES_PER_PAGE = 20;
// Bun automatically loads .env/.env.local into Bun.env
const env = Bun.env;
const USER_AGENT = env.USER_AGENT || "podrush/0.1";
const hasGeminiKey = Boolean(env.GEMINI_API_KEY || env.GOOGLE_API_KEY);
const log = (...args: unknown[]) => console.info(new Date().toISOString(), "[podrush]", ...args);

export const escapeHtml = (str: string): string =>
  str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");

const plainText = (html: string): string =>
  html.replace(/<[^>]*>/g, " ").replace(/&[a-z]+;/g, " ").replace(/\s+/g, " ").trim();

const sanitizeHtml = (html: string): string =>
  html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "")
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, "")
    .replace(/<\/?(iframe|object|embed|form|input|button|select|textarea|base|meta|link)\b[^>]*>/gi, "")
    .replace(/\s+on\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "")
    .replace(/\s+style\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "")
    .replace(/(href|src)\s*=\s*"javascript:[^"]*"/gi, '')
    .replace(/(href|src)\s*=\s*'javascript:[^']*'/gi, '');

const descriptionDetails = (html: string): string => {
  if (!html) return "";
  const safe = sanitizeHtml(html);
  return `
    <div class="ep-description is-collapsed" data-ep-description>
      ${safe}
    </div>
    <button type="button" class="ep-description-toggle" data-ep-toggle hidden>Show more</button>`;
};

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

mkdirSync(ORIGINAL_DIR, { recursive: true });
mkdirSync(CONVERTED_DIR, { recursive: true });

// Race condition guards
const conversionsInProgress = new Set<string>();
const feedShortNameInProgress = new Set<number>();
const episodeShortNameInProgress = new Set<number>();

const selectFeeds = db.prepare(
  `
  SELECT id, url, title, description, image_url, last_checked, short_name
  FROM feeds
  ORDER BY id DESC
`
);

const selectFeedById = db.prepare(
  `
  SELECT id, url, title, description, image_url, last_checked, short_name
  FROM feeds
  WHERE id = ?
`
);

const selectEpisodesForFeed = db.prepare(
  `
  SELECT id, feed_id, guid, title, description, audio_url, published_at, duration_secs, local_path, short_name
  FROM episodes
  WHERE feed_id = ?
  ORDER BY published_at IS NULL, published_at DESC, id DESC
`
);

const selectEpisodeById = db.prepare(
  `
  SELECT id, feed_id, guid, title, description, audio_url, published_at, duration_secs, local_path, short_name
  FROM episodes
  WHERE id = ?
`
);

const selectEpisodeWithFeed = db.prepare(
  `
  SELECT
    episodes.id,
    episodes.title AS episode_title,
    episodes.published_at AS published_at,
    feeds.title AS feed_title
  FROM episodes
  JOIN feeds ON feeds.id = episodes.feed_id
  WHERE episodes.id = ?
`
);

const findFeedByUrl = db.prepare("SELECT id FROM feeds WHERE url = ?");

const insertFeed = db.prepare("INSERT INTO feeds (url, last_checked) VALUES (?, NULL)");

const updateFeedShortName = db.prepare("UPDATE feeds SET short_name = ? WHERE id = ?");
const updateEpisodeShortName = db.prepare("UPDATE episodes SET short_name = ? WHERE id = ?");
const updateEpisodeLocalPath = db.prepare("UPDATE episodes SET local_path = ? WHERE id = ?");

const htmlResponse = (body: string, status = 200) =>
  new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });

const notFound = () =>
  new Response("Not found", { status: 404, headers: { "Content-Type": "text/plain" } });

const serveHtmlPage = (file: Blob) =>
  new Response(file, { headers: { "Content-Type": "text/html; charset=utf-8" } });

const logRequest = (request: Request) => {
  const { pathname } = new URL(request.url);
  log("Incoming request", { method: request.method, pathname });
};

const getRouteParam = (request: Request, key: string) =>
  (request as Request & { params?: Record<string, string> }).params?.[key];

type EpisodeRow = {
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

const slugify = (input: string, maxLen = 48) => {
  const normalized = input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, maxLen);
  return normalized || "item";
};

const aiShortName = async (kind: string, title: string, detail?: string) =>
  generateGeminiShorthand({ kind, title, detail, log });

const ensureFeedShortName = async (feed: FeedRow): Promise<string> => {
  if (feed.short_name) return feed.short_name;
  if (feedShortNameInProgress.has(feed.id)) {
    const baseTitle = feed.title || feed.url || "podcast";
    const maxLen = 24;
    return slugify(baseTitle, maxLen);  // Return fallback while in progress
  }

  feedShortNameInProgress.add(feed.id);
  try {
    const baseTitle = feed.title || feed.url || "podcast";
    const aiName = await aiShortName("podcast", baseTitle);
    const maxLen = aiName ? 32 : 24;
    const name = slugify(aiName || baseTitle, maxLen);
    updateFeedShortName.run(name, feed.id);
    feed.short_name = name;
    log("Feed shorthand set", { feedId: feed.id, name });
    return name;
  } finally {
    feedShortNameInProgress.delete(feed.id);
  }
};

const ensureEpisodeShortName = async (feed: FeedRow, episode: EpisodeRow): Promise<string> => {
  if (episode.short_name) return episode.short_name;
  if (episodeShortNameInProgress.has(episode.id)) {
    const epTitle = episode.title || "episode";
    const maxLen = 24;
    return slugify(epTitle, maxLen);  // Return fallback while in progress
  }

  episodeShortNameInProgress.add(episode.id);
  try {
    const epTitle = episode.title || "episode";
    const aiName = await aiShortName("podcast episode", epTitle, feed.title || feed.url || undefined);
    const maxLen = aiName ? 32 : 24;
    const name = slugify(aiName || epTitle, maxLen);
    updateEpisodeShortName.run(name, episode.id);
    episode.short_name = name;
    log("Episode shorthand set", { episodeId: episode.id, name });
    return name;
  } finally {
    episodeShortNameInProgress.delete(episode.id);
  }
};

const episodeDateStamp = (episode: EpisodeRow): string | null => {
  if (!episode.published_at) return null;
  const date = new Date(episode.published_at);
  if (Number.isNaN(date.getTime())) return null;
  const year = date.getUTCFullYear();
  const month = (date.getUTCMonth() + 1).toString().padStart(2, "0");
  const day = date.getUTCDate().toString().padStart(2, "0");
  return `${year}${month}${day}`;
};

const buildFilenameBase = async (feed: FeedRow, episode: EpisodeRow): Promise<string> => {
  const feedName = await ensureFeedShortName(feed);
  const episodeName = await ensureEpisodeShortName(feed, episode);
  const date = episodeDateStamp(episode);
  const parts = [date, feedName, episodeName, `id${episode.id}`].filter(Boolean);
  return parts.join("-");
};

const formatTimestamp = (value: string | null): string => {
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

const renderFeedShortNameForm = (feed: FeedRow, message = ""): string => {
  const shortName = escapeHtml(feed.short_name || "");
  const helper = message ? `<div class="short-name-message">${escapeHtml(message)}</div>` : "";
  return `
    <div class="short-name-block">
      <small>Short name</small>
      <form
        class="short-name-form"
        hx-post="/api/feeds/${feed.id}/short-name"
        hx-target="closest .short-name-block"
        hx-swap="outerHTML"
      >
        <input
          type="text"
          id="short-name-${feed.id}"
          name="short_name"
          value="${shortName}"
          maxlength="32"
          placeholder="short-name"
          aria-label="Short name"
        >
        <button type="submit" class="secondary">Save</button>
      </form>
      ${helper}
    </div>
  `;
};

function renderFeeds(feeds: FeedRow[]): string {
  if (!feeds.length) {
    return `
      <section class="grid feeds-grid" id="feeds-list">
        <p>No feeds yet. Add one to get started.</p>
      </section>
    `;
  }

  const cards = feeds
    .map((feed) => {
      const title = escapeHtml(feed.title || feed.url);
      const descHtml = feed.description || "";
      const description = escapeHtml(plainText(descHtml).slice(0, 200));
      const lastChecked = formatTimestamp(feed.last_checked);
      const shortNameForm = renderFeedShortNameForm(feed);
      return `
        <article class="feed-card">
          <header>
            <h3><a href="/feed/${feed.id}">${title}</a></h3>
            <details class="feed-description">
              <summary>
                <span class="feed-description-preview">${description}</span>
                <span class="feed-description-more">More</span>
              </summary>
              <div class="feed-description-full">${sanitizeHtml(descHtml)}</div>
            </details>
          </header>
          <footer>
            ${shortNameForm}
            <small title="${escapeHtml(feed.last_checked || "")}">Last checked: ${lastChecked}</small>
          </footer>
        </article>
      `;
    })
    .join("");

  return `<section class="grid feeds-grid" id="feeds-list">${cards}</section>`;
}

function getFeeds(): FeedRow[] {
  return selectFeeds.all() as FeedRow[];
}

const isFeedStale = (feed: FeedRow, maxAgeHours = 6) => {
  const thresholdMs = maxAgeHours * 60 * 60 * 1000;
  const now = Date.now();
  const lastCheckedMs = feed.last_checked ? Date.parse(feed.last_checked) : NaN;
  return Number.isNaN(lastCheckedMs) || now - lastCheckedMs > thresholdMs;
};

const formatDuration = (seconds: number | null): string => {
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

const formatSpeedLabel = (speed: number) => speed.toFixed(2).replace(/\.?0+$/, "");

const listConvertedByEpisode = (): Record<number, Record<string, string>> => {
  const mapping: Record<number, Record<string, string>> = {};
  let entries: string[] = [];
  try {
    entries = readdirSync(CONVERTED_DIR);
  } catch {
    return mapping;
  }
  for (const name of entries) {
    if (!name.toLowerCase().endsWith(".mp3")) continue;
    const fullPath = join(CONVERTED_DIR, name);
    try {
      if (!statSync(fullPath).isFile()) continue;
    } catch {
      continue;
    }
    const match = name.match(/-id(\d+)-([0-9.]+)x\.mp3$/);
    if (!match) continue;
    const episodeId = Number(match[1]);
    const speedLabel = formatSpeedLabel(Number(match[2]));
    mapping[episodeId] ||= {};
    mapping[episodeId][speedLabel] = `/media/converted/${name}`;
  }
  return mapping;
};

type ConvertedEntry = {
  filename: string;
  path: string;
  episodeId?: number;
  speedLabel?: string;
  episodeTitle?: string | null;
  feedTitle?: string | null;
  publishedAt?: string | null;
};

const parseConvertedFilename = (name: string) => {
  const match = name.match(/-id(\d+)-([0-9.]+)x\.mp3$/);
  if (!match) return null;
  return { episodeId: Number(match[1]), speed: Number(match[2]) };
};

const listConvertedFiles = (): ConvertedEntry[] => {
  let entries: string[] = [];
  try {
    entries = readdirSync(CONVERTED_DIR);
  } catch {
    return [];
  }
  const rows: ConvertedEntry[] = [];
  for (const name of entries) {
    const fullPath = join(CONVERTED_DIR, name);
    try {
      if (!statSync(fullPath).isFile()) continue;
    } catch {
      continue;
    }
    const parsed = parseConvertedFilename(name);
    if (!parsed || !Number.isFinite(parsed.episodeId)) {
      rows.push({ filename: name, path: fullPath });
      continue;
    }
    const speedLabel = formatSpeedLabel(parsed.speed);
    const details = selectEpisodeWithFeed.get(parsed.episodeId) as
      | { episode_title: string | null; feed_title: string | null; published_at: string | null }
      | undefined;
    rows.push({
      filename: name,
      path: fullPath,
      episodeId: parsed.episodeId,
      speedLabel,
      episodeTitle: details?.episode_title ?? null,
      feedTitle: details?.feed_title ?? null,
      publishedAt: details?.published_at ?? null,
    });
  }
  return rows;
};

const runProcess = async (cmd: string[], label: string) => {
  const proc = Bun.spawn(cmd, { stdout: "pipe", stderr: "pipe" });
  const exitCode = await proc.exited;
  const stdout = await new Response(proc.stdout).text();
  const stderr = await new Response(proc.stderr).text();
  if (exitCode !== 0) {
    throw new Error(`${label} failed (${exitCode}): ${stderr || stdout}`);
  }
  return stdout;
};

const readId3Tags = async (filePath: string): Promise<Record<string, string>> => {
  const output = await runProcess(
    ["ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", filePath],
    "ffprobe"
  );
  const data = JSON.parse(output) as { format?: { tags?: Record<string, string> } };
  const tags = data?.format?.tags || {};
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(tags)) {
    if (!value) continue;
    normalized[key.toLowerCase()] = value;
  }
  return normalized;
};

const formatId3Date = (value: string | null) => {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  const year = date.getUTCFullYear();
  const month = (date.getUTCMonth() + 1).toString().padStart(2, "0");
  const day = date.getUTCDate().toString().padStart(2, "0");
  return `${year}-${month}-${day}`;
};

const writeId3Tags = async (
  filePath: string,
  tags: {
    title?: string | null;
    artist?: string | null;
    album?: string | null;
    date?: string | null;
    genre?: string | null;
  }
) => {
  const tempPath = `${filePath}.tmp.mp3`;
  const args = [
    "ffmpeg",
    "-y",
    "-i",
    filePath,
    "-map",
    "0",
    "-c",
    "copy",
    "-map_metadata",
    "-1",
    "-id3v2_version",
    "3",
  ];
  if (tags.title) args.push("-metadata", `title=${tags.title}`);
  if (tags.artist) args.push("-metadata", `artist=${tags.artist}`);
  if (tags.album) args.push("-metadata", `album=${tags.album}`);
  if (tags.date) args.push("-metadata", `date=${tags.date}`);
  if (tags.genre) args.push("-metadata", `genre=${tags.genre}`);
  args.push(tempPath);

  try {
    await runProcess(args, "ffmpeg");
    renameSync(tempPath, filePath);
  } catch (err) {
    // Clean up temp file on error
    try {
      unlinkSync(tempPath);
    } catch {
      // Ignore cleanup errors
    }
    throw err;
  }
};

const renderTagList = (tags: Record<string, string>) => {
  const title = escapeHtml(tags.title || "");
  const artist = escapeHtml(tags.artist || tags.album_artist || "");
  const album = escapeHtml(tags.album || "");
  const date = escapeHtml(tags.date || tags.year || "");
  const genre = escapeHtml(tags.genre || "");
  const lines = [
    title && `<span><strong>Title:</strong> ${title}</span>`,
    artist && `<span><strong>Artist:</strong> ${artist}</span>`,
    album && `<span><strong>Album:</strong> ${album}</span>`,
    date && `<span><strong>Date:</strong> ${date}</span>`,
    genre && `<span><strong>Genre:</strong> ${genre}</span>`,
  ].filter(Boolean);
  if (!lines.length) return `<span class="muted">No tags</span>`;
  return lines.join("");
};

const renderDbTagList = (entry: ConvertedEntry) => {
  if (!entry.episodeId) return `<span class="muted">Unmatched file</span>`;
  const title = escapeHtml(entry.episodeTitle || "");
  const artist = escapeHtml(entry.feedTitle || "");
  const album = escapeHtml(entry.feedTitle || "");
  const date = escapeHtml(formatId3Date(entry.publishedAt) || "");
  const genre = "Podcast";
  const lines = [
    title && `<span><strong>Title:</strong> ${title}</span>`,
    artist && `<span><strong>Artist:</strong> ${artist}</span>`,
    album && `<span><strong>Album:</strong> ${album}</span>`,
    date && `<span><strong>Date:</strong> ${date}</span>`,
    `<span><strong>Genre:</strong> ${genre}</span>`,
  ].filter(Boolean);
  if (!lines.length) return `<span class="muted">No data</span>`;
  return lines.join("");
};

const tagsMatch = (entry: ConvertedEntry, fileTags: Record<string, string>): boolean => {
  if (!entry.episodeId) return true;
  const dbTitle = (entry.episodeTitle || "").trim();
  const dbArtist = (entry.feedTitle || "").trim();
  const dbDate = formatId3Date(entry.publishedAt) || "";
  const fileTitle = (fileTags.title || "").trim();
  const fileArtist = (fileTags.artist || fileTags.album_artist || "").trim();
  const fileDate = (fileTags.date || fileTags.year || "").trim();
  return dbTitle === fileTitle && dbArtist === fileArtist && dbDate === fileDate;
};

const renderConvertedRow = (entry: ConvertedEntry, tags: Record<string, string>, message = "") => {
  const fileLink = `/media/converted/${escapeHtml(entry.filename)}`;
  const speed = entry.speedLabel ? `${escapeHtml(entry.speedLabel)}x` : "Unknown";
  const synced = tagsMatch(entry, tags);
  const tagStatus = entry.episodeId
    ? (synced
        ? `<span class="tag-status tag-status--ok">&#10003; Tags synced</span>`
        : `<span class="tag-status tag-status--warn">&#9888; Tags differ</span>`)
    : "";
  const actions = entry.episodeId
    ? `
      <form
        hx-post="/api/converted/retag"
        hx-target="closest tr"
        hx-swap="outerHTML"
        class="inline-form"
      >
        <input type="hidden" name="filename" value="${escapeHtml(entry.filename)}">
        <button type="submit" class="secondary">Copy from podcast data</button>
      </form>
      <form
        hx-post="/api/converted/delete"
        hx-target="closest tr"
        hx-swap="outerHTML"
        class="inline-form"
        data-confirm="Delete this converted file?"
      >
        <input type="hidden" name="filename" value="${escapeHtml(entry.filename)}">
        <button type="submit" class="contrast">Delete file</button>
      </form>
    `
    : `<span class="muted">No match</span>`;
  const statusMsg = message ? `<div class="muted">${escapeHtml(message)}</div>` : "";
  return `
    <tr>
      <td>
        <div><a href="${fileLink}" download>${escapeHtml(entry.filename)}</a></div>
        <div class="muted">${speed}</div>
      </td>
      <td class="tag-list">${renderDbTagList(entry)}${tagStatus}</td>
      <td>
        ${actions}
        ${statusMsg}
      </td>
    </tr>
  `;
};

const renderConvertedTable = async (entries: ConvertedEntry[], messageByFile = new Map<string, string>()) => {
  if (!entries.length) {
    return `
      <section id="converted-list">
        <p>No converted files found.</p>
      </section>
    `;
  }
  const rows = await Promise.all(
    entries.map(async (entry) => {
      let tags: Record<string, string> = {};
      try {
        tags = await readId3Tags(entry.path);
      } catch (err) {
        tags = {};
      }
      const message = messageByFile.get(entry.filename) || "";
      return renderConvertedRow(entry, tags, message);
    })
  );
  return `
    <section id="converted-list">
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>File</th>
              <th>Episode / Tags</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${rows.join("")}
          </tbody>
        </table>
      </div>
    </section>
  `;
};

const ensureOriginalAudio = async (feed: FeedRow, episode: EpisodeRow): Promise<string> => {
  if (episode.local_path) {
    const existing = Bun.file(episode.local_path);
    if (await existing.exists()) {
      log("Reusing existing original audio", { episodeId: episode.id, path: episode.local_path });
      return episode.local_path;
    }
  }

  const base = await buildFilenameBase(feed, episode);
  const targetPath = join(ORIGINAL_DIR, `${base}-orig.mp3`);
  const targetFile = Bun.file(targetPath);
  if (await targetFile.exists()) {
    updateEpisodeLocalPath.run(targetPath, episode.id);
    log("Found downloaded audio on disk", { episodeId: episode.id, path: targetPath });
    return targetPath;
  }

  log("Downloading episode audio", { episodeId: episode.id, url: episode.audio_url });
  const response = await fetchWithTimeout(
    episode.audio_url,
    {
      redirect: "follow",
      headers: { "User-Agent": USER_AGENT },
    },
    60000  // 60 second timeout for audio downloads
  );
  if (!response.ok) {
    throw new Error(`Failed to download audio (${response.status})`);
  }

  // Check download size limit
  const contentLength = parseInt(response.headers.get("content-length") || "0", 10);
  if (contentLength > MAX_AUDIO_SIZE) {
    throw new Error(`Audio file too large: ${contentLength} bytes (max ${MAX_AUDIO_SIZE})`);
  }

  const buffer = await response.arrayBuffer();
  await Bun.write(targetPath, buffer);
  updateEpisodeLocalPath.run(targetPath, episode.id);
  log("Downloaded audio saved", { episodeId: episode.id, path: targetPath });
  return targetPath;
};

const convertAudio = async (originalPath: string, targetPath: string, speed: number) => {
  const targetFile = Bun.file(targetPath);
  if (await targetFile.exists()) {
    log("Conversion already exists", { targetPath, speed });
    return;
  }

  // Check if conversion is in progress
  if (conversionsInProgress.has(targetPath)) {
    log("Conversion already in progress", { targetPath, speed });
    return;
  }

  conversionsInProgress.add(targetPath);
  try {
    log("Starting conversion", { originalPath, targetPath, speed });
    const proc = Bun.spawn(
      [
        "ffmpeg",
        "-i",
        originalPath,
        "-filter:a",
        `atempo=${speed}`,
        "-metadata",
        "genre=Podcast",
        targetPath,
      ],
      {
        stdout: "ignore",
        stderr: "pipe",
      }
    );
    const exitCode = await proc.exited;
    if (exitCode !== 0) {
      const errorText = await new Response(proc.stderr).text();
      throw new Error(`ffmpeg failed: ${errorText}`);
    }
    log("Conversion complete", { targetPath, speed });
  } finally {
    conversionsInProgress.delete(targetPath);
  }
};

function renderEpisodeList(
  feedId: number,
  episodes: EpisodeRow[],
  conversions: Record<number, Record<string, string>>,
  offset: number
): string {
  const page = episodes.slice(offset, offset + EPISODES_PER_PAGE);
  const hasMore = episodes.length > offset + EPISODES_PER_PAGE;

  const articles = page
    .map((ep) => {
      const duration = formatDuration(ep.duration_secs);
      const published = escapeHtml(formatTimestamp(ep.published_at));
      const epConversions = conversions[ep.id] || {};
      const buttons = SPEEDS.map((speed) => {
        const label = formatSpeedLabel(speed);
        const existing = epConversions[label];
        if (existing) {
          return `<a class="contrast" href="${escapeHtml(existing)}" download>Download ${label}x</a>`;
        }
        return `
            <button
              hx-post="/api/episodes/${ep.id}/convert"
              hx-vals='{"speed": "${speed}"}'
              hx-target="this"
              hx-swap="outerHTML">
              Convert ${label}x
            </button>
        `;
      }).join("");
      return `
        <article>
          <header>
            <h3>${escapeHtml(ep.title || "Untitled episode")}${duration ? ` <small>(${duration})</small>` : ""}</h3>
            <p><small>${published}</small></p>
          </header>
          ${descriptionDetails(ep.description || "")}
          <div class="convert-buttons">${buttons}</div>
        </article>
      `;
    })
    .join("");

  const loadMore = hasMore
    ? `<div class="load-more">
        <button class="secondary"
          hx-get="/api/feed/${feedId}?offset=${offset + EPISODES_PER_PAGE}"
          hx-target="closest .load-more"
          hx-swap="outerHTML"
          hx-indicator=".load-more-spinner">
          Load more episodes
          <span class="htmx-indicator load-more-spinner"><span class="spinner" aria-label="Loading"></span></span>
        </button>
      </div>`
    : "";

  return articles + loadMore;
}

function renderFeedDetail(
  feed: FeedRow,
  episodes: EpisodeRow[],
  conversions: Record<number, Record<string, string>>
) {
  const header = `
    <header>
      <p><a href="/">&larr; Back to feeds</a></p>
      <h1>${escapeHtml(feed.title || feed.url)}</h1>
      <div>${sanitizeHtml(feed.description || "")}</div>
    </header>
  `;

  if (!episodes.length) {
    return `<section>${header}<p>No episodes yet for this feed.</p></section>`;
  }

  return `<section>${header}${renderEpisodeList(feed.id, episodes, conversions, 0)}</section>`;
}

async function getFeedDetail(feedId: number): Promise<{
  feed: FeedRow;
  episodes: EpisodeRow[];
  conversions: Record<number, Record<string, string>>;
} | null> {
  const feed = selectFeedById.get(feedId) as FeedRow | undefined;
  if (!feed) return null;

  if (isFeedStale(feed)) {
    await refreshFeed(feed);
  }

  const refreshedFeed = selectFeedById.get(feedId) as FeedRow | undefined;
  if (!refreshedFeed) return null;
  const episodes = selectEpisodesForFeed.all(feedId) as EpisodeRow[];
  const conversions = listConvertedByEpisode();
  return { feed: refreshedFeed, episodes, conversions };
}

async function addFeed(request: Request) {
  const form = await request.formData();
  const rawUrl = form.get("url");
  const url = typeof rawUrl === "string" ? rawUrl.trim() : "";
  if (!url) {
    return htmlResponse("<p>Missing URL</p>", 400);
  }

  // Validate URL protocol
  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return htmlResponse("<p>Only HTTP and HTTPS URLs are supported</p>", 400);
    }
  } catch {
    return htmlResponse("<p>Invalid URL format</p>", 400);
  }

  const existing = findFeedByUrl.get(url);
  let feedId = existing?.id as number | undefined;
  if (!existing) {
    const result = insertFeed.run(url);
    feedId = Number(result.lastInsertRowid);
    log("Feed added", { feedId, url });
  }

  if (feedId) {
    // Fetch metadata and episodes right after adding.
    await refreshFeed({ id: feedId, url });
    const feed = selectFeedById.get(feedId) as FeedRow | undefined;
    if (feed) {
      await ensureFeedShortName(feed);
    }
  }

  const feeds = getFeeds();
  return htmlResponse(renderFeeds(feeds));
}

const serveIndex = (request: Request) => {
  logRequest(request);
  return serveHtmlPage(indexPage);
};

const serveFeedHtml = (request: Request) => {
  logRequest(request);
  return serveHtmlPage(feedPage);
};

const serveConvertedHtml = (request: Request) => {
  logRequest(request);
  return serveHtmlPage(convertedPage);
};

const listFeeds = async (request: Request) => {
  logRequest(request);
  const feeds = getFeeds();
  await refreshFeedsIfStale(feeds);
  const refreshed = getFeeds();
  return htmlResponse(renderFeeds(refreshed));
};

const createFeed = (request: Request) => {
  logRequest(request);
  return addFeed(request);
};

const updateFeedShortNameHandler = async (request: Request) => {
  logRequest(request);
  const feedId = Number(getRouteParam(request, "id"));
  if (!Number.isFinite(feedId)) return htmlResponse("<span>Invalid feed</span>", 400);

  const form = await request.formData();
  const rawName = form.get("short_name");
  const proposed = typeof rawName === "string" ? rawName.trim() : "";
  const feed = selectFeedById.get(feedId) as FeedRow | undefined;
  if (!feed) return notFound();

  if (!proposed) {
    return htmlResponse(renderFeedShortNameForm(feed, "Short name required"), 400);
  }

  const name = slugify(proposed, 32);
  updateFeedShortName.run(name, feedId);
  feed.short_name = name;
  return htmlResponse(renderFeedShortNameForm(feed, "Saved"));
};

const feedDetail = async (request: Request) => {
  logRequest(request);
  const feedId = Number(getRouteParam(request, "id"));
  if (!Number.isFinite(feedId)) return notFound();
  const data = await getFeedDetail(feedId);
  if (!data) return notFound();

  const url = new URL(request.url);
  const offsetParam = url.searchParams.get("offset");
  if (offsetParam !== null) {
    const offset = Math.max(0, Number(offsetParam) || 0);
    return htmlResponse(renderEpisodeList(feedId, data.episodes, data.conversions, offset));
  }

  return htmlResponse(renderFeedDetail(data.feed, data.episodes, data.conversions));
};

const listConverted = async (request: Request) => {
  logRequest(request);
  const entries = listConvertedFiles().filter((entry) =>
    entry.filename.toLowerCase().endsWith(".mp3")
  );
  const html = await renderConvertedTable(entries);
  return htmlResponse(html);
};

const retagConverted = async (request: Request) => {
  logRequest(request);
  const form = await request.formData();
  const rawFilename = form.get("filename");
  const filename = typeof rawFilename === "string" ? rawFilename : "";
  if (!filename) return htmlResponse("<tr><td colspan='4'>Missing filename</td></tr>", 400);
  if (filename.includes("/") || filename.includes("\\")) {
    return htmlResponse("<tr><td colspan='4'>Invalid filename</td></tr>", 400);
  }

  const parsed = parseConvertedFilename(filename);
  if (!parsed || !Number.isFinite(parsed.episodeId)) {
    return htmlResponse("<tr><td colspan='4'>Unmatched filename</td></tr>", 400);
  }

  const entry = listConvertedFiles().find((item) => item.filename === filename);
  if (!entry?.episodeId) {
    return htmlResponse("<tr><td colspan='4'>File not found</td></tr>", 404);
  }

  const details = selectEpisodeWithFeed.get(entry.episodeId) as
    | { episode_title: string | null; feed_title: string | null; published_at: string | null }
    | undefined;
  if (!details) {
    return htmlResponse("<tr><td colspan='4'>Missing episode data</td></tr>", 404);
  }

  const tags = {
    title: details.episode_title || undefined,
    artist: details.feed_title || undefined,
    album: details.feed_title || undefined,
    date: formatId3Date(details.published_at) || undefined,
    genre: "Podcast",
  };

  try {
    await writeId3Tags(entry.path, tags);
    const updatedTags = await readId3Tags(entry.path);
    return htmlResponse(renderConvertedRow(entry, updatedTags, "Updated"));
  } catch (err) {
    console.error("Tag update failed", err);
    const currentTags = await readId3Tags(entry.path).catch(() => ({}));
    return htmlResponse(renderConvertedRow(entry, currentTags, "Failed to update"), 500);
  }
};

const deleteConverted = async (request: Request) => {
  logRequest(request);
  const form = await request.formData();
  const rawFilename = form.get("filename");
  const filename = typeof rawFilename === "string" ? rawFilename : "";
  if (!filename) return htmlResponse("<tr><td colspan='4'>Missing filename</td></tr>", 400);
  if (filename.includes("/") || filename.includes("\\")) {
    return htmlResponse("<tr><td colspan='4'>Invalid filename</td></tr>", 400);
  }
  if (!filename.toLowerCase().endsWith(".mp3")) {
    return htmlResponse("<tr><td colspan='4'>Invalid file</td></tr>", 400);
  }

  const entry = listConvertedFiles().find((item) => item.filename === filename);
  if (!entry) {
    return htmlResponse("<tr><td colspan='4'>File not found</td></tr>", 404);
  }

  try {
    const file = Bun.file(entry.path);
    if (await file.exists()) {
      await file.delete();
    }
    return htmlResponse("<tr><td colspan='4'>Deleted</td></tr>");
  } catch (err) {
    console.error("Delete failed", err);
    return htmlResponse("<tr><td colspan='4'>Delete failed</td></tr>", 500);
  }
};

const convertEpisode = async (request: Request) => {
  logRequest(request);
  const episodeId = Number(getRouteParam(request, "id"));
  if (!Number.isFinite(episodeId)) return htmlResponse("<span>Invalid episode</span>", 400);

  const speedForm = await request.formData();
  const rawSpeed = speedForm.get("speed");
  const speed = Number.parseFloat(typeof rawSpeed === "string" ? rawSpeed : "1.5");
  if (!Number.isFinite(speed) || speed <= 0) {
    return htmlResponse("<span>Invalid speed</span>", 400);
  }

  const episode = selectEpisodeById.get(episodeId) as EpisodeRow | undefined;
  if (!episode) return notFound();
  const feed = selectFeedById.get(episode.feed_id) as FeedRow | undefined;
  if (!feed) return notFound();

  try {
    const originalPath = await ensureOriginalAudio(feed, episode);
    const base = await buildFilenameBase(feed, episode);
    const speedLabel = formatSpeedLabel(speed);
    const targetPath = join(CONVERTED_DIR, `${base}-${speedLabel}x.mp3`);
    await convertAudio(originalPath, targetPath, speed);
    await writeId3Tags(targetPath, {
      title: episode.title || undefined,
      artist: feed.title || undefined,
      album: feed.title || undefined,
      date: formatId3Date(episode.published_at) || undefined,
      genre: "Podcast",
    });
    const filename = targetPath.split(/[/\\\\]/).pop();
    const html = `<a class="contrast" href="/media/converted/${filename}" download>Download ${speedLabel}x</a>`;
    return htmlResponse(html);
  } catch (err) {
    console.error("Conversion failed", err);
    return htmlResponse("<span>Conversion failed</span>", 500);
  }
};

const serveMediaFile = async (request: Request) => {
  logRequest(request);
  const { pathname } = new URL(request.url);
  const safePath = resolve("." + pathname);
  const mediaRoot = resolve(MEDIA_DIR);

  // Prevent path traversal
  if (!safePath.startsWith(mediaRoot)) {
    return notFound();
  }

  const file = Bun.file(safePath);
  if (await file.exists()) {
    const contentType = pathname.endsWith(".mp3") ? "audio/mpeg" : "application/octet-stream";
    return new Response(file, { headers: { "Content-Type": contentType } });
  }
  return notFound();
};

const contentTypeForPath = (pathname: string): string => {
  if (pathname.endsWith(".css")) return "text/css; charset=utf-8";
  if (pathname.endsWith(".js")) return "application/javascript; charset=utf-8";
  if (pathname.endsWith(".svg")) return "image/svg+xml";
  if (pathname.endsWith(".png")) return "image/png";
  if (pathname.endsWith(".jpg") || pathname.endsWith(".jpeg")) return "image/jpeg";
  if (pathname.endsWith(".webp")) return "image/webp";
  if (pathname.endsWith(".ico")) return "image/x-icon";
  if (pathname.endsWith(".json")) return "application/json; charset=utf-8";
  return "application/octet-stream";
};

const serveStaticFile = async (request: Request) => {
  logRequest(request);
  const { pathname } = new URL(request.url);
  const safePath = resolve("." + pathname);
  const staticRoot = resolve("./static");
  if (safePath !== staticRoot && !safePath.startsWith(staticRoot + "/")) {
    return notFound();
  }

  const file = Bun.file(safePath);
  if (!(await file.exists())) return notFound();
  return new Response(file, {
    headers: { "Content-Type": contentTypeForPath(pathname.toLowerCase()) },
  });
};

const serveFavicon = async (request: Request) => {
  logRequest(request);
  const file = Bun.file("./static/favicon.ico");
  if (await file.exists()) {
    return new Response(file, { headers: { "Content-Type": "image/x-icon" } });
  }
  return notFound();
};

const fallbackNotFound = (request: Request) => {
  logRequest(request);
  return notFound();
};

// Only start the server if not in test mode
if (import.meta.main) {
  serve({
    routes: {
      "/": { GET: serveIndex },
      "/feed/:id": { GET: serveFeedHtml },
      "/converted": { GET: serveConvertedHtml },
      "/api/feeds": { GET: listFeeds, POST: createFeed },
      "/api/feeds/:id/short-name": { POST: updateFeedShortNameHandler },
      "/api/feed/:id": { GET: feedDetail },
      "/api/converted": { GET: listConverted },
      "/api/converted/retag": { POST: retagConverted },
      "/api/converted/delete": { POST: deleteConverted },
      "/api/episodes/:id/convert": { POST: convertEpisode },
      "/static/*": { GET: serveStaticFile },
      "/media/*": { GET: serveMediaFile },
      "/favicon.ico": { GET: serveFavicon },
      "/*": fallbackNotFound,
    },
  });
  log("Server starting", {
    mediaDir: MEDIA_DIR,
    converted: CONVERTED_DIR,
    original: ORIGINAL_DIR,
    geminiKeyPresent: hasGeminiKey,
    geminiModel: env.GEMINI_MODEL || "gemini-2.5-flash",
  });
}
