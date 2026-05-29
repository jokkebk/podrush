import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { db } from "../feedService";
import {
  buildPodcastFeedItems,
  buildPublicFileUrl,
  buildRsyncArgs,
  generatePodcastFeed,
  listConvertedPodcastFiles,
  parseConvertedPodcastFilename,
  renderPodcastRss,
  uploadConvertedMedia,
  xmlEscape,
  type PodcastEpisodeMetadata,
} from "../podcastFeed";

const tempDir = () => mkdtempSync(join(tmpdir(), "podrush-feed-test-"));

const writeMp3 = (dir: string, filename: string, body = "fake mp3") => {
  const path = join(dir, filename);
  writeFileSync(path, body);
  return path;
};

const metadata = (episodeId: number): PodcastEpisodeMetadata => ({
  id: episodeId,
  episode_title: `Episode ${episodeId} & friends`,
  episode_description: "<p>Useful <strong>notes</strong> & links</p>",
  published_at: "2026-03-20T12:00:00.000Z",
  duration_secs: 123,
  feed_title: "Test Feed",
  feed_description: "Feed description",
  feed_image_url: null,
});

describe("podcast feed generation", () => {
  test("parses converted filenames and rejects unmatched files", () => {
    expect(parseConvertedPodcastFilename("20260320-feed-episode-id3496-1.25x.mp3")).toEqual({
      episodeId: 3496,
      speed: 1.25,
      speedLabel: "1.25",
    });
    expect(parseConvertedPodcastFilename("manual-upload.mp3")).toBeNull();
    expect(parseConvertedPodcastFilename("episode-id12-fast.mp3")).toBeNull();
  });

  test("escapes XML and builds encoded public file URLs", () => {
    expect(xmlEscape(`A & B < "C" 'D'`)).toBe("A &amp; B &lt; &quot;C&quot; &apos;D&apos;");
    expect(buildPublicFileUrl("https://example.com/data/podrush/", "one two&id.mp3")).toBe(
      "https://example.com/data/podrush/one%20two%26id.mp3"
    );
  });

  test("scans MP3 files, sorts publishable files, and tracks unmatched files", () => {
    const dir = tempDir();
    try {
      writeMp3(dir, "manual.mp3");
      writeMp3(dir, "20260319-feed-other-id11-1.1x.mp3");
      writeMp3(dir, "20260320-feed-episode-id10-1.5x.mp3");
      writeFileSync(join(dir, "notes.txt"), "ignored");

      const { files, skippedFiles } = listConvertedPodcastFiles(dir);
      expect(files.map((file) => file.episodeId).sort((a, b) => a - b)).toEqual([10, 11]);
      expect(skippedFiles).toEqual(["manual.mp3"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("renders one RSS item per matched file and skips missing metadata", () => {
    const now = new Date("2026-03-21T12:00:00.000Z");
    const items = buildPodcastFeedItems(
      [
        {
          filename: "20260320-feed-episode-id10-1.5x.mp3",
          path: "/tmp/one.mp3",
          episodeId: 10,
          speed: 1.5,
          speedLabel: "1.5",
          size: 42,
          mtime: now,
        },
        {
          filename: "20260320-feed-missing-id99-1.5x.mp3",
          path: "/tmp/two.mp3",
          episodeId: 99,
          speed: 1.5,
          speedLabel: "1.5",
          size: 42,
          mtime: now,
        },
      ],
      "https://example.com/data/podrush",
      (episodeId) => (episodeId === 10 ? metadata(episodeId) : null)
    );

    expect(items).toHaveLength(1);
    expect(items[0]?.title).toBe("Episode 10 & friends (1.5x)");
    expect(items[0]?.enclosureUrl).toBe(
      "https://example.com/data/podrush/20260320-feed-episode-id10-1.5x.mp3"
    );

    const rss = renderPodcastRss(items, {
      feedTitle: "Private & Feed",
      feedDescription: "Escaped <description>",
      publicBaseUrl: "https://example.com/data/podrush",
      feedFilename: "podrush-feed.xml",
    });
    expect(rss).toContain("<title>Private &amp; Feed</title>");
    expect(rss).toContain("Episode 10 &amp; friends (1.5x)");
    expect(rss).toContain('type="audio/mpeg"');
    expect(rss).not.toContain("id99");
  });

  test("writes static RSS from fixture DB metadata and reconciles disk deletions", () => {
    const dir = tempDir();
    const oldFilename = Bun.env.PODRUSH_FEED_FILENAME;
    const oldBase = Bun.env.PODRUSH_PUBLIC_BASE_URL;
    Bun.env.PODRUSH_FEED_FILENAME = "test-feed.xml";
    Bun.env.PODRUSH_PUBLIC_BASE_URL = "https://example.com/data/podrush";

    try {
      const feedResult = db
        .prepare("INSERT INTO feeds (url, title, description, last_checked) VALUES (?, ?, ?, ?)")
        .run(`https://example.com/test-${Date.now()}.xml`, "Fixture Feed", "Fixture", new Date().toISOString());
      const feedId = Number(feedResult.lastInsertRowid);
      const episodeResult = db
        .prepare(
          `INSERT INTO episodes
            (feed_id, guid, title, description, audio_url, published_at, duration_secs)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          feedId,
          `guid-${Date.now()}`,
          "Fixture Episode",
          "Fixture description",
          "https://example.com/audio.mp3",
          "2026-03-20T12:00:00.000Z",
          600
        );
      const episodeId = Number(episodeResult.lastInsertRowid);
      const filename = `20260320-fixture-episode-id${episodeId}-1.5x.mp3`;
      writeMp3(dir, filename, "fixture audio");
      writeMp3(dir, "unmatched.mp3", "unmatched");

      const first = generatePodcastFeed("test", dir);
      expect(first.itemCount).toBe(1);
      expect(first.unmatchedCount).toBe(1);
      let rss = readFileSync(join(dir, "test-feed.xml"), "utf8");
      expect(rss).toContain("Fixture Episode (1.5x)");
      expect(rss).toContain(filename);

      unlinkSync(join(dir, filename));
      const second = generatePodcastFeed("test", dir);
      expect(second.itemCount).toBe(0);
      rss = readFileSync(join(dir, "test-feed.xml"), "utf8");
      expect(rss).not.toContain("Fixture Episode");
    } finally {
      if (oldFilename === undefined) {
        delete Bun.env.PODRUSH_FEED_FILENAME;
      } else {
        Bun.env.PODRUSH_FEED_FILENAME = oldFilename;
      }
      if (oldBase === undefined) {
        delete Bun.env.PODRUSH_PUBLIC_BASE_URL;
      } else {
        Bun.env.PODRUSH_PUBLIC_BASE_URL = oldBase;
      }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("constructs rsync mirror command and supports mocked upload", async () => {
    expect(buildRsyncArgs("media/converted", "user@host:/data/podrush/")).toEqual([
      "rsync",
      "-av",
      "--delete",
      "--exclude",
      ".DS_Store",
      "media/converted/",
      "user@host:/data/podrush/",
    ]);

    const oldTarget = Bun.env.PODRUSH_UPLOAD_TARGET;
    Bun.env.PODRUSH_UPLOAD_TARGET = "user@host:/data/podrush/";
    try {
      const seen: string[][] = [];
      const status = await uploadConvertedMedia(
        {
          feedPath: "media/converted/test-feed.xml",
          feedFilename: "test-feed.xml",
          publicFeedUrl: "https://example.com/data/podrush/test-feed.xml",
          publicBaseUrl: "https://example.com/data/podrush",
          configuredPublicBaseUrl: true,
          uploadTarget: "user@host:/data/podrush/",
          configuredUploadTarget: true,
          generatedAt: new Date().toISOString(),
          itemCount: 1,
          unmatchedCount: 0,
          matchedFileCount: 1,
          skippedFiles: [],
        },
        (args) => {
          seen.push(args);
          return {
            exited: Promise.resolve(0),
            stdout: "sent 123 bytes",
            stderr: "",
          };
        }
      );

      expect(seen[0]).toEqual(buildRsyncArgs("media/converted", "user@host:/data/podrush/"));
      expect(status.message).toBe("Upload completed.");
      expect(status.uploadSummary).toContain("Command: rsync -av --delete");
      expect(status.uploadSummary).toContain("Exit code: 0");
      expect(status.uploadSummary).toContain("sent 123 bytes");
    } finally {
      if (oldTarget === undefined) {
        delete Bun.env.PODRUSH_UPLOAD_TARGET;
      } else {
        Bun.env.PODRUSH_UPLOAD_TARGET = oldTarget;
      }
    }
  });
});
