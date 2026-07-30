import { describe, expect, test } from "bun:test";
import { renderGarminIntro, renderGarminPanel } from "../renderers";
import type { ConvertedEntry } from "../lib";
import { readFileSync } from "fs";
import {
  serveConvertedPage, serveFeedDetailPage, serveFeedsPage, serveGarminPage,
} from "../layout";

const localEntry: ConvertedEntry = {
  filename: "2026-07-30-podcast-episode-id1-1.25x.mp3",
  path: "./media/converted/2026-07-30-podcast-episode-id1-1.25x.mp3",
  episodeId: 1,
  speedLabel: "1.25",
  episodeTitle: "A useful episode",
  feedTitle: "A podcast",
  publishedAt: "2026-07-30",
};

describe("Garmin transfer UI", () => {
  test("adds the dedicated Garmin page to the shared navigation", async () => {
    const pages = await Promise.all([
      serveFeedsPage().text(),
      serveFeedDetailPage().text(),
      serveConvertedPage().text(),
      serveGarminPage().text(),
    ]);

    for (const html of pages) {
      expect(html).toContain('<a href="/garmin">Garmin</a>');
    }
    expect(pages[2]).toContain("Review converted files and publish");
    expect(pages[2]).not.toContain("garmin-panel");
  });

  test("renders a side-effect-free introduction with an explicit connect action", async () => {
    const intro = renderGarminIntro();
    const page = await serveGarminPage().text();

    expect(page).toContain("<h1>Garmin</h1>");
    expect(intro).toContain("Connect to watch");
    expect(intro).toContain('hx-get="/api/garmin"');
    expect(intro).not.toContain('hx-trigger="load"');
    expect(page).not.toContain('hx-trigger="load"');
    expect(page).toContain("Garmin Express, Apple Music");
    expect(page).toContain("first connect");
  });

  test("uses pinned open-source MTP dependencies without Garmin Express", () => {
    const source = readFileSync(new URL("../garmin.ts", import.meta.url), "utf8");
    const helperSource = readFileSync(
      new URL("../native/garmin-mtp.c", import.meta.url),
      "utf8"
    );
    expect(source).toContain('version: "1.0.29"');
    expect(source).toContain('version: "1.1.22"');
    expect(source).not.toContain("/Applications/Garmin Express.app");
    expect(source).not.toContain("-arch\", \"x86_64");
    expect(helperSource).toContain('strcasecmp(track->genre, "Podcast")');
    expect(helperSource).toContain('watch->music_id, "Music", 1');
  });

  test("shows local files missing from a connected watch", () => {
    const html = renderGarminPanel({
      connected: true,
      manufacturer: "Garmin",
      model: "EPIX",
      storage: { id: 1, description: "Internal", capacity: 1024 ** 3, free: 512 ** 2 },
      files: [],
      message: "Watch contents refreshed.",
    }, [localEntry]);

    expect(html).toContain("Garmin EPIX");
    expect(html).toContain('name="filename"');
    expect(html).toContain("A useful episode");
    expect(html).toContain("Send selected");
    expect(html).toContain('hx-post="/api/garmin/send"');
    expect(html).toContain("Refresh watch");
  });

  test("shows watch files as removable and does not offer duplicates to send", () => {
    const html = renderGarminPanel({
      connected: true,
      model: "EPIX",
      storage: { id: 1, description: "Internal", capacity: 1000, free: 500 },
      files: [{
        id: 42,
        name: localEntry.filename,
        size: 12_000_000,
        type: 2,
        location: "Music",
      }],
    }, [localEntry]);

    expect(html).toContain('name="object_id" value="42"');
    expect(html).toContain('hx-post="/api/garmin/delete"');
    expect(html).toContain("Remove selected");
    expect(html).toContain("11.4 MB · Music");
    expect(html).toContain("Every local converted MP3 is already on the watch.");
    expect(html).not.toContain(`name="filename" value="${localEntry.filename}"`);
  });

  test("escapes device errors and remote filenames", () => {
    const disconnected = renderGarminPanel({
      connected: false,
      error: "<script>alert(1)</script>",
    }, []);
    expect(disconnected).toContain("&lt;script&gt;");
    expect(disconnected).not.toContain("<script>");
    expect(disconnected).toContain("Reconnect");

    const connected = renderGarminPanel({
      connected: true,
      files: [{ id: 9, name: "<img src=x>.mp3", size: 1, type: 2 }],
    }, []);
    expect(connected).toContain("&lt;img src=x&gt;.mp3");
    expect(connected).not.toContain("<img src=x>");
  });
});
