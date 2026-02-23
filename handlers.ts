import { join, resolve } from "path";
import { readdirSync, statSync } from "fs";
import { refreshFeed, refreshFeedsIfStale, type FeedRow } from "./feedService";
import {
  MEDIA_DIR, CONVERTED_DIR, log,
  htmlResponse, notFound, logRequest, getRouteParam,
  selectFeeds, selectFeedById, selectEpisodesForFeed, selectEpisodeById,
  selectEpisodeWithFeed, findFeedByUrl, insertFeed, updateFeedShortName,
  formatSpeedLabel, formatId3Date, slugify,
  type EpisodeRow, type ConvertedEntry,
} from "./lib";
import {
  ensureFeedShortName, ensureOriginalAudio, buildFilenameBase, convertAudio,
  readId3Tags, writeId3Tags,
} from "./audio";
import {
  renderFeeds, renderFeedShortNameForm, renderEpisodeList, renderFeedDetail,
  renderConvertedRow, renderConvertedTable,
} from "./renderers";
import { serveFeedsPage, serveFeedDetailPage, serveConvertedPage } from "./layout";

// ─── Data helpers ─────────────────────────────────────────
function getFeeds(): FeedRow[] {
  return selectFeeds.all() as FeedRow[];
}

const isFeedStale = (feed: FeedRow, maxAgeHours = 6) => {
  const thresholdMs = maxAgeHours * 60 * 60 * 1000;
  const now = Date.now();
  const lastCheckedMs = feed.last_checked ? Date.parse(feed.last_checked) : NaN;
  return Number.isNaN(lastCheckedMs) || now - lastCheckedMs > thresholdMs;
};

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

// ─── Route handlers ───────────────────────────────────────
async function addFeed(request: Request) {
  const form = await request.formData();
  const rawUrl = form.get("url");
  const url = typeof rawUrl === "string" ? rawUrl.trim() : "";
  if (!url) {
    return htmlResponse("<p>Missing URL</p>", 400);
  }

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
    await refreshFeed({ id: feedId, url });
    const feed = selectFeedById.get(feedId) as FeedRow | undefined;
    if (feed) {
      await ensureFeedShortName(feed);
    }
  }

  const feeds = getFeeds();
  return htmlResponse(renderFeeds(feeds));
}

export const serveIndex = (request: Request) => {
  logRequest(request);
  return serveFeedsPage();
};

export const serveFeedHtml = (request: Request) => {
  logRequest(request);
  return serveFeedDetailPage();
};

export const serveConvertedHtml = (request: Request) => {
  logRequest(request);
  return serveConvertedPage();
};

export const listFeeds = async (request: Request) => {
  logRequest(request);
  const feeds = getFeeds();
  await refreshFeedsIfStale(feeds);
  const refreshed = getFeeds();
  return htmlResponse(renderFeeds(refreshed));
};

export const createFeed = (request: Request) => {
  logRequest(request);
  return addFeed(request);
};

export const updateFeedShortNameHandler = async (request: Request) => {
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

export const feedDetail = async (request: Request) => {
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

export const listConverted = async (request: Request) => {
  logRequest(request);
  const entries = listConvertedFiles().filter((entry) =>
    entry.filename.toLowerCase().endsWith(".mp3")
  );
  const html = await renderConvertedTable(entries);
  return htmlResponse(html);
};

export const retagConverted = async (request: Request) => {
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

export const deleteConverted = async (request: Request) => {
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

export const convertEpisode = async (request: Request) => {
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

// ─── Static file serving ──────────────────────────────────
export const serveMediaFile = async (request: Request) => {
  logRequest(request);
  const { pathname } = new URL(request.url);
  const safePath = resolve("." + pathname);
  const mediaRoot = resolve(MEDIA_DIR);

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

export const serveStaticFile = async (request: Request) => {
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

export const serveFavicon = async (request: Request) => {
  logRequest(request);
  const file = Bun.file("./static/favicon.ico");
  if (await file.exists()) {
    return new Response(file, { headers: { "Content-Type": "image/x-icon" } });
  }
  return notFound();
};

export const fallbackNotFound = (request: Request) => {
  logRequest(request);
  return notFound();
};
