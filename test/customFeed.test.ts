import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import {
  CUSTOM_FEED_TITLE,
  CUSTOM_FEED_URL,
  db,
  ensureCustomFeed,
  isFeedStale,
  refreshFeed,
} from "../feedService";
import { probeAudioDurationSecs } from "../audio";
import { uploadCustomEpisode } from "../handlers";

describe("custom uploads feed", () => {
  test("ensureCustomFeed creates the sentinel feed once", () => {
    const first = ensureCustomFeed();
    expect(first.url).toBe(CUSTOM_FEED_URL);
    expect(first.title).toBe(CUSTOM_FEED_TITLE);

    const second = ensureCustomFeed();
    expect(second.id).toBe(first.id);

    const count = db
      .prepare("SELECT COUNT(*) AS n FROM feeds WHERE url = ?")
      .get(CUSTOM_FEED_URL) as { n: number };
    expect(count.n).toBe(1);
  });

  test("custom feed is never considered stale", () => {
    const feed = ensureCustomFeed();
    expect(isFeedStale({ ...feed, last_checked: null })).toBe(false);
    expect(isFeedStale({ ...feed, last_checked: "2020-01-01T00:00:00.000Z" })).toBe(false);
  });

  test("refreshFeed skips the custom feed without fetching", async () => {
    const feed = ensureCustomFeed();
    const knownChecked = "2026-01-02T03:04:05.000Z";
    db.prepare("UPDATE feeds SET last_checked = ? WHERE id = ?").run(knownChecked, feed.id);

    await refreshFeed(feed);

    const after = db
      .prepare("SELECT title, last_checked FROM feeds WHERE id = ?")
      .get(feed.id) as { title: string; last_checked: string };
    // A fetch attempt would fail and mark the feed checked; a skip leaves the row untouched.
    expect(after.title).toBe(CUSTOM_FEED_TITLE);
    expect(after.last_checked).toBe(knownChecked);
  });

  test("probeAudioDurationSecs reads duration from a generated mp3", async () => {
    const dir = mkdtempSync(join(tmpdir(), "podrush-probe-test-"));
    try {
      const path = join(dir, "tone.mp3");
      const proc = Bun.spawn(
        ["ffmpeg", "-y", "-v", "error", "-f", "lavfi", "-i", "sine=frequency=440:duration=2", path],
        { stdout: "pipe", stderr: "pipe" }
      );
      expect(await proc.exited).toBe(0);

      const duration = await probeAudioDurationSecs(path);
      expect(duration).not.toBeNull();
      // MP3 encoder padding makes the result slightly longer than 2 seconds.
      expect(duration!).toBeGreaterThanOrEqual(2);
      expect(duration!).toBeLessThanOrEqual(3);

      expect(await probeAudioDurationSecs(join(dir, "missing.mp3"))).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("upload handler rejects missing file and non-mp3 uploads", async () => {
    const emptyForm = new FormData();
    const missing = await uploadCustomEpisode(
      new Request("http://localhost/api/custom/episodes", { method: "POST", body: emptyForm })
    );
    expect(missing.status).toBe(400);

    const badForm = new FormData();
    badForm.set("file", new File(["not audio"], "notes.txt", { type: "text/plain" }));
    const wrongType = await uploadCustomEpisode(
      new Request("http://localhost/api/custom/episodes", { method: "POST", body: badForm })
    );
    expect(wrongType.status).toBe(400);
  });
});
