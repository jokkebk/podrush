import { Database } from "bun:sqlite";
import { parseFeed } from "feedsmith";

export type FeedRow = {
  id: number;
  url: string;
  title: string | null;
  description: string | null;
  image_url: string | null;
  last_checked: string | null;
  short_name?: string | null;
};

type EpisodeUpsert = {
  guid: string;
  title: string | null;
  description: string | null;
  audio_url: string;
  published_at: string | null;
  duration_secs: number | null;
  short_name?: string | null;
};

export const db = new Database("db.sqlite");

const updateFeedStmt = db.prepare(
  `
  UPDATE feeds
  SET title = ?, description = ?, image_url = ?, last_checked = ?
  WHERE id = ?
`
);

const upsertEpisodeStmt = db.prepare(
  `
  INSERT INTO episodes (feed_id, guid, title, description, audio_url, published_at, duration_secs)
  VALUES (?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(feed_id, guid) DO UPDATE SET
    title = excluded.title,
    description = excluded.description,
    audio_url = excluded.audio_url,
    published_at = excluded.published_at,
    duration_secs = excluded.duration_secs
`
);

const USER_AGENT = process.env.USER_AGENT || "podrush/0.1";
const REFRESH_MAX_AGE_HOURS = 6;

const parseDuration = (raw: unknown): number | null => {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === "number" && Number.isFinite(raw)) return Math.max(0, Math.trunc(raw));
  if (typeof raw !== "string") return null;
  const parts = raw.split(":").map((p) => parseInt(p, 10));
  if (parts.some((n) => Number.isNaN(n))) {
    const asNumber = Number.parseInt(raw, 10);
    return Number.isNaN(asNumber) ? null : asNumber;
  }
  if (parts.length === 3) {
    const [hours, minutes, seconds] = parts;
    return hours * 3600 + minutes * 60 + seconds;
  }
  if (parts.length === 2) {
    const [minutes, seconds] = parts;
    return minutes * 60 + seconds;
  }
  return parts[0] ?? null;
};

const toIsoString = (value: unknown): string | null => {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value as string | number);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
};

const pickAudioFromEnclosures = (enclosures?: Array<{ url?: string; type?: string }>): string | null => {
  if (!enclosures?.length) return null;
  const audio = enclosures.find((e) => e.type?.startsWith("audio")) || enclosures[0];
  return audio?.url || null;
};

const pickAudioFromLinks = (
  links?: Array<{ href?: string; rel?: string; type?: string }>
): string | null => {
  if (!links?.length) return null;
  const enclosure = links.find((l) => l.rel === "enclosure" || l.type?.startsWith("audio"));
  const candidate = enclosure || links[0];
  return candidate?.href || null;
};

const normalizeRss = (feed: any) => {
  const items = Array.isArray(feed.items) ? feed.items : [];
  const episodes: EpisodeUpsert[] = [];

  for (const item of items) {
    const guid =
      (typeof item.guid === "string" ? item.guid : item.guid?.value) ||
      item.link ||
      item.title;
    const audioUrl =
      pickAudioFromEnclosures(item.enclosures) ||
      item.itunes?.enclosure?.url ||
      item.podcast?.enclosure?.url ||
      item.link;
    if (!guid || !audioUrl) continue;

    const publishedAt =
      toIsoString(item.pubDate) ||
      toIsoString(item.dc?.date) ||
      toIsoString(item.dcterms?.date);

    const durationSecs =
      parseDuration(item.itunes?.duration) ||
      parseDuration(item.podcast?.duration) ||
      parseDuration(item.media?.duration);

    const description =
      item.description ||
      item.content?.encoded ||
      item.content ||
      item.summary ||
      null;

    episodes.push({
      guid,
      title: item.title || null,
      description,
      audio_url: audioUrl,
      published_at: publishedAt,
      duration_secs: durationSecs,
    });
  }

  return {
    title: feed.title || null,
    description: feed.description || feed.subtitle || feed.summary || null,
    image_url: feed.image?.url || feed.itunes?.image || feed.podcast?.image || null,
    episodes,
  };
};

const normalizeAtom = (feed: any) => {
  const items = Array.isArray(feed.entries) ? feed.entries : [];
  const episodes: EpisodeUpsert[] = [];

  for (const entry of items) {
    const guid = entry.id || entry.link || entry.title;
    const audioUrl =
      pickAudioFromLinks(entry.links) ||
      entry.media?.content?.url ||
      entry.media?.group?.url ||
      entry.link;
    if (!guid || !audioUrl) continue;

    const publishedAt = toIsoString(entry.published) || toIsoString(entry.updated);
    const durationSecs = parseDuration(entry.itunes?.duration);
    const description = entry.summary || entry.content || null;

    episodes.push({
      guid,
      title: entry.title || null,
      description,
      audio_url: audioUrl,
      published_at: publishedAt,
      duration_secs: durationSecs,
    });
  }

  return {
    title: feed.title || null,
    description: feed.subtitle || feed.summary || null,
    image_url: feed.icon || feed.logo || feed.itunes?.image || null,
    episodes,
  };
};

const normalizeJson = (feed: any) => {
  const items = Array.isArray(feed.items) ? feed.items : [];
  const episodes: EpisodeUpsert[] = [];

  for (const item of items) {
    const guid = item.id || item.url || item.external_url || item.title;
    const attachment =
      item.attachments?.find((a: any) => a.mime_type?.startsWith("audio")) ||
      item.attachments?.[0];
    const audioUrl = attachment?.url || item.external_url || item.url;
    if (!guid || !audioUrl) continue;

    const publishedAt = toIsoString(item.date_published) || toIsoString(item.date_modified);
    const durationSecs = parseDuration(attachment?.duration_in_seconds);
    const description = item.summary || item.content_text || item.content_html || null;

    episodes.push({
      guid,
      title: item.title || null,
      description,
      audio_url: audioUrl,
      published_at: publishedAt,
      duration_secs: durationSecs,
    });
  }

  return {
    title: feed.title || null,
    description: feed.description || feed.user_comment || null,
    image_url: feed.icon || feed.favicon || null,
    episodes,
  };
};

const normalizeParsedFeed = (format: string, feed: any) => {
  if (format === "atom") return normalizeAtom(feed);
  if (format === "json") return normalizeJson(feed);
  // Treat RDF the same as RSS for our purposes.
  return normalizeRss(feed);
};

export async function refreshFeed(feed: FeedRow | { id: number; url: string }) {
  let response: Response;
  try {
    response = await fetch(feed.url, {
      redirect: "follow",
      headers: { "User-Agent": USER_AGENT },
    });
  } catch (err) {
    console.error("Failed to fetch feed", feed.url, err);
    return;
  }
  if (!response.ok) return;

  const body = await response.text();
  let parsed;
  try {
    parsed = parseFeed(body);
  } catch (err) {
    console.error("Failed to parse feed", feed.url, err);
    return;
  }

  const normalized = normalizeParsedFeed(parsed.format, parsed.feed);
  const nowIso = new Date().toISOString();

  updateFeedStmt.run(
    normalized.title || feed.url,
    normalized.description,
    normalized.image_url,
    nowIso,
    feed.id
  );

  const upsertBatch = db.transaction((episodes: EpisodeUpsert[]) => {
    for (const episode of episodes) {
      upsertEpisodeStmt.run(
        feed.id,
        episode.guid,
        episode.title,
        episode.description,
        episode.audio_url,
        episode.published_at,
        episode.duration_secs
      );
    }
  });

  upsertBatch(normalized.episodes);
}

export async function refreshFeedsIfStale(feeds: FeedRow[], maxAgeHours = REFRESH_MAX_AGE_HOURS) {
  const thresholdMs = maxAgeHours * 60 * 60 * 1000;
  const now = Date.now();
  for (const feed of feeds) {
    const lastCheckedMs = feed.last_checked ? Date.parse(feed.last_checked) : NaN;
    const isStale = Number.isNaN(lastCheckedMs) || now - lastCheckedMs > thresholdMs;
    if (isStale) {
      await refreshFeed(feed);
    }
  }
}
