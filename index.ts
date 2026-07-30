import { serve } from "bun";
import { MEDIA_DIR, CONVERTED_DIR, ORIGINAL_DIR, hasGeminiKey, env, log } from "./lib";
import { ensureCustomFeed } from "./feedService";
import {
  serveIndex, serveFeedHtml, serveConvertedHtml, serveGarminHtml,
  listFeeds, refreshFeedsNow, createFeed, updateFeedShortNameHandler,
  feedDetail, listConverted, retagConverted, deleteConverted,
  regeneratePodcastFeedHandler, uploadPodcastFeedHandler,
  garminStatus, garminSend, garminDelete,
  convertEpisode, uploadCustomEpisode, serveMediaFile, serveStaticFile, serveFavicon,
  fallbackNotFound,
} from "./handlers";

// Re-export for feedService.ts dynamic import and test compatibility
export { escapeHtml, fetchWithTimeout } from "./lib";

if (import.meta.main) {
  const configuredPort = Number(env.PORT || "3000");
  const port = Number.isFinite(configuredPort) && configuredPort > 0
    ? Math.trunc(configuredPort)
    : 3000;
  const customFeed = ensureCustomFeed();
  log("Custom uploads feed ready", { feedId: customFeed.id });
  serve({
    port,
    // Bun defaults to a 10 second idle timeout, which is far too short for the
    // long synchronous handlers here: a full podcast mirror to object storage
    // moves hundreds of megabytes and takes minutes, and conversions are not
    // quick either. The request holds an idle connection for the whole job, so
    // the socket closed mid-upload and the UI reported failure even though the
    // spawned mirror ran to completion in the background.
    //
    // 255 is Bun's maximum. It covers a full re-upload on a normal connection
    // and every incremental sync after it, but it is a ceiling rather than a
    // real fix: the durable answer is to start the job, return immediately, and
    // let the page poll for status.
    idleTimeout: 255,
    routes: {
      "/": { GET: serveIndex },
      "/feed/:id": { GET: serveFeedHtml },
      "/converted": { GET: serveConvertedHtml },
      "/garmin": { GET: serveGarminHtml },
      "/api/feeds": { GET: listFeeds, POST: createFeed },
      "/api/feeds/refresh": { POST: refreshFeedsNow },
      "/api/feeds/:id/short-name": { POST: updateFeedShortNameHandler },
      "/api/feed/:id": { GET: feedDetail },
      "/api/converted": { GET: listConverted },
      "/api/converted/retag": { POST: retagConverted },
      "/api/converted/delete": { POST: deleteConverted },
      "/api/podcast-feed/regenerate": { POST: regeneratePodcastFeedHandler },
      "/api/podcast-feed/upload": { POST: uploadPodcastFeedHandler },
      "/api/garmin": { GET: garminStatus },
      "/api/garmin/send": { POST: garminSend },
      "/api/garmin/delete": { POST: garminDelete },
      "/api/episodes/:id/convert": { POST: convertEpisode },
      "/api/custom/episodes": { POST: uploadCustomEpisode },
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
