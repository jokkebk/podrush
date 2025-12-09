import { serve } from "bun";
import { mkdirSync, readdirSync, statSync } from "fs";
import { join } from "path";
import { db, refreshFeed, refreshFeedsIfStale, type FeedRow } from "./feedService";
import { generateGeminiShorthand } from "./gemini_shorthand";

const indexPage = Bun.file("./html/index.html");
const feedPage = Bun.file("./html/feed.html");

const MEDIA_DIR = "./media";
const ORIGINAL_DIR = join(MEDIA_DIR, "original");
const CONVERTED_DIR = join(MEDIA_DIR, "converted");
const SPEEDS = [1.1, 1.25, 1.5];
// Bun automatically loads .env/.env.local into Bun.env
const env = Bun.env;
const USER_AGENT = env.USER_AGENT || "podrush/0.1";
const hasGeminiKey = Boolean(env.GEMINI_API_KEY || env.GOOGLE_API_KEY);
const log = (...args: unknown[]) => console.info(new Date().toISOString(), "[podrush]", ...args);

mkdirSync(ORIGINAL_DIR, { recursive: true });
mkdirSync(CONVERTED_DIR, { recursive: true });

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
  const baseTitle = feed.title || feed.url || "podcast";
  const aiName = await aiShortName("podcast", baseTitle);
  const maxLen = aiName ? 32 : 24;
  const name = slugify(aiName || baseTitle, maxLen);
  updateFeedShortName.run(name, feed.id);
  feed.short_name = name;
  log("Feed shorthand set", { feedId: feed.id, name });
  return name;
};

const ensureEpisodeShortName = async (feed: FeedRow, episode: EpisodeRow): Promise<string> => {
  if (episode.short_name) return episode.short_name;
  const epTitle = episode.title || "episode";
  const aiName = await aiShortName("podcast episode", epTitle, feed.title || feed.url || undefined);
  const maxLen = aiName ? 32 : 24;
  const name = slugify(aiName || epTitle, maxLen);
  updateEpisodeShortName.run(name, episode.id);
  episode.short_name = name;
  log("Episode shorthand set", { episodeId: episode.id, name });
  return name;
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

function renderFeeds(feeds: FeedRow[]): string {
  if (!feeds.length) {
    return `
      <section class="grid" id="feeds-list">
        <p>No feeds yet. Add one to get started.</p>
      </section>
    `;
  }

  const cards = feeds
    .map((feed) => {
      const title = feed.title || feed.url;
      const description = feed.description || "";
      const lastChecked = feed.last_checked || "never";
      return `
        <article>
          <header>
            <h3><a href="/feed/${feed.id}">${title}</a></h3>
            <p>${description}</p>
          </header>
          <footer>
            <small>Last checked: ${lastChecked}</small>
          </footer>
        </article>
      `;
    })
    .join("");

  return `<section class="grid" id="feeds-list">${cards}</section>`;
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
  const response = await fetch(episode.audio_url, {
    redirect: "follow",
    headers: { "User-Agent": USER_AGENT },
  });
  if (!response.ok) {
    throw new Error(`Failed to download audio (${response.status})`);
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

  log("Starting conversion", { originalPath, targetPath, speed });
  const proc = Bun.spawn(["ffmpeg", "-i", originalPath, "-filter:a", `atempo=${speed}`, targetPath], {
    stdout: "ignore",
    stderr: "pipe",
  });
  const exitCode = await proc.exited;
  if (exitCode !== 0) {
    const errorText = await new Response(proc.stderr).text();
    throw new Error(`ffmpeg failed: ${errorText}`);
  }
  log("Conversion complete", { targetPath, speed });
};

function renderFeedDetail(
  feed: FeedRow,
  episodes: EpisodeRow[],
  conversions: Record<number, Record<string, string>>
) {
  const header = `
    <header>
      <p><a href="/">&larr; Back to feeds</a></p>
      <h1>${feed.title || feed.url}</h1>
      <p>${feed.description || ""}</p>
    </header>
  `;

  if (!episodes.length) {
    return `<section>${header}<p>No episodes yet for this feed.</p></section>`;
  }

  const list = episodes
    .map((ep) => {
      const duration = formatDuration(ep.duration_secs);
      const published = ep.published_at || "";
      const epConversions = conversions[ep.id] || {};
      const buttons = SPEEDS.map((speed) => {
        const label = formatSpeedLabel(speed);
        const existing = epConversions[label];
        if (existing) {
          return `<a class="contrast" href="${existing}" download>Download ${label}x</a>`;
        }
        return `
          <div>
            <button
              hx-post="/api/episodes/${ep.id}/convert"
              hx-vals='{"speed": "${speed}"}'
              hx-target="this"
              hx-swap="outerHTML">
              Convert ${label}x
            </button>
          </div>
        `;
      }).join("");
      return `
        <article>
          <header>
            <h3>${ep.title || "Untitled episode"}${duration ? ` <small>(${duration})</small>` : ""}</h3>
            <p><small>${published}</small></p>
          </header>
          <div>${ep.description || ""}</div>
          <div class="grid">${buttons}</div>
        </article>
      `;
    })
    .join("");

  return `<section>${header}${list}</section>`;
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

const feedDetail = async (request: Request) => {
  logRequest(request);
  const feedId = Number(getRouteParam(request, "id"));
  if (!Number.isFinite(feedId)) return notFound();
  const data = await getFeedDetail(feedId);
  if (!data) return notFound();
  return htmlResponse(renderFeedDetail(data.feed, data.episodes, data.conversions));
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
  const file = Bun.file("." + pathname);
  if (await file.exists()) {
    const contentType = pathname.endsWith(".mp3") ? "audio/mpeg" : "application/octet-stream";
    return new Response(file, { headers: { "Content-Type": contentType } });
  }
  return notFound();
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

serve({
  routes: {
    "/": serveIndex,
    "/feed/:id": serveFeedHtml,
    "/api/feeds": { GET: listFeeds, POST: createFeed },
    "/api/feed/:id": feedDetail,
    "/api/episodes/:id/convert": { POST: convertEpisode },
    "/media/*": serveMediaFile,
    "/favicon.ico": serveFavicon,
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
