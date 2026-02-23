import { serve } from "bun";
import { MEDIA_DIR, CONVERTED_DIR, ORIGINAL_DIR, hasGeminiKey, env, log } from "./lib";
import {
  serveIndex, serveFeedHtml, serveConvertedHtml,
  listFeeds, refreshFeedsNow, createFeed, updateFeedShortNameHandler,
  feedDetail, listConverted, retagConverted, deleteConverted,
  convertEpisode, serveMediaFile, serveStaticFile, serveFavicon,
  fallbackNotFound,
} from "./handlers";

// Re-export for feedService.ts dynamic import and test compatibility
export { escapeHtml, fetchWithTimeout } from "./lib";

if (import.meta.main) {
  const configuredPort = Number(env.PORT || "3000");
  const port = Number.isFinite(configuredPort) && configuredPort > 0
    ? Math.trunc(configuredPort)
    : 3000;
  serve({
    port,
    routes: {
      "/": { GET: serveIndex },
      "/feed/:id": { GET: serveFeedHtml },
      "/converted": { GET: serveConvertedHtml },
      "/api/feeds": { GET: listFeeds, POST: createFeed },
      "/api/feeds/refresh": { POST: refreshFeedsNow },
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
    port,
    mediaDir: MEDIA_DIR,
    converted: CONVERTED_DIR,
    original: ORIGINAL_DIR,
    geminiKeyPresent: hasGeminiKey,
    geminiModel: env.GEMINI_MODEL || "gemini-2.5-flash",
  });
}
