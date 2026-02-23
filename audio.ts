import { join } from "path";
import { renameSync, unlinkSync } from "fs";
import { generateGeminiShorthand } from "./gemini_shorthand";
import { type FeedRow } from "./feedService";
import {
  ORIGINAL_DIR, MAX_AUDIO_SIZE, USER_AGENT,
  log, slugify, episodeDateStamp,
  updateFeedShortName, updateEpisodeShortName, updateEpisodeLocalPath,
  conversionsInProgress, feedShortNameInProgress, episodeShortNameInProgress,
  fetchWithTimeout, type EpisodeRow,
} from "./lib";

// ─── Shorthand naming ─────────────────────────────────────
const aiShortName = async (kind: string, title: string, detail?: string) =>
  generateGeminiShorthand({ kind, title, detail, log });

export const ensureFeedShortName = async (feed: FeedRow): Promise<string> => {
  if (feed.short_name) return feed.short_name;
  if (feedShortNameInProgress.has(feed.id)) {
    return slugify(feed.title || feed.url || "podcast", 24);
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

export const ensureEpisodeShortName = async (feed: FeedRow, episode: EpisodeRow): Promise<string> => {
  if (episode.short_name) return episode.short_name;
  if (episodeShortNameInProgress.has(episode.id)) {
    return slugify(episode.title || "episode", 24);
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

export const buildFilenameBase = async (feed: FeedRow, episode: EpisodeRow): Promise<string> => {
  const feedName = await ensureFeedShortName(feed);
  const episodeName = await ensureEpisodeShortName(feed, episode);
  const date = episodeDateStamp(episode);
  const parts = [date, feedName, episodeName, `id${episode.id}`].filter(Boolean);
  return parts.join("-");
};

// ─── Process ──────────────────────────────────────────────
export const runProcess = async (cmd: string[], label: string) => {
  const proc = Bun.spawn(cmd, { stdout: "pipe", stderr: "pipe" });
  const exitCode = await proc.exited;
  const stdout = await new Response(proc.stdout).text();
  const stderr = await new Response(proc.stderr).text();
  if (exitCode !== 0) {
    throw new Error(`${label} failed (${exitCode}): ${stderr || stdout}`);
  }
  return stdout;
};

// ─── ID3 tags ─────────────────────────────────────────────
export const readId3Tags = async (filePath: string): Promise<Record<string, string>> => {
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

export const writeId3Tags = async (
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
    "ffmpeg", "-y", "-i", filePath,
    "-map", "0", "-c", "copy",
    "-map_metadata", "-1", "-id3v2_version", "3",
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
    try { unlinkSync(tempPath); } catch { /* ignore cleanup errors */ }
    throw err;
  }
};

// ─── Audio pipeline ───────────────────────────────────────
export const ensureOriginalAudio = async (feed: FeedRow, episode: EpisodeRow): Promise<string> => {
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
    { redirect: "follow", headers: { "User-Agent": USER_AGENT } },
    60000
  );
  if (!response.ok) {
    throw new Error(`Failed to download audio (${response.status})`);
  }

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

export const convertAudio = async (originalPath: string, targetPath: string, speed: number) => {
  const targetFile = Bun.file(targetPath);
  if (await targetFile.exists()) {
    log("Conversion already exists", { targetPath, speed });
    return;
  }

  if (conversionsInProgress.has(targetPath)) {
    log("Conversion already in progress", { targetPath, speed });
    return;
  }

  conversionsInProgress.add(targetPath);
  try {
    log("Starting conversion", { originalPath, targetPath, speed });
    const proc = Bun.spawn(
      [
        "ffmpeg", "-i", originalPath,
        "-filter:a", `atempo=${speed}`,
        "-metadata", "genre=Podcast",
        targetPath,
      ],
      { stdout: "ignore", stderr: "pipe" }
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
