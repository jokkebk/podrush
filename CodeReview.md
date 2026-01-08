# Code Review Fixes

This document contains high-priority fixes identified during code review. Work through each item in order, marking them complete as you go.

## Instructions

For each fix:
1. Read the relevant code section first
2. Implement the fix
3. Mark the checkbox when complete

---

## 1. Path Traversal Vulnerability in Media Serving

**File:** `index.ts` lines 880-889

**Problem:** The `serveMediaFile` function uses `"." + pathname` directly, allowing requests like `/media/../../../etc/passwd` to read arbitrary files.

**Fix:** Validate that the resolved path stays within the media directory:

```typescript
import { resolve } from "path";

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
```

- [x] Complete

---

## 2. XSS Prevention - Add HTML Escaping

**File:** `index.ts`

**Problem:** RSS feed content (titles, descriptions) is rendered directly into HTML without escaping. A malicious podcast could inject JavaScript.

**Fix:** Add an `escapeHtml` utility function near the top of the file (after imports) and use it wherever RSS content is rendered:

```typescript
const escapeHtml = (str: string): string =>
  str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
```

Then find and update all locations where feed/episode data is rendered into HTML. Key locations to check:
- `renderFeedCard` function - feed title, description
- `renderEpisodeRow` function - episode title, description
- Any other place where `feed.title`, `feed.description`, `ep.title`, `ep.description` appear in template literals

Example fix:
```typescript
// Before
<h3>${feed.title}</h3>

// After
<h3>${escapeHtml(feed.title || "")}</h3>
```

- [x] Complete

---

## 3. URL Protocol Validation

**File:** `index.ts` in the `addFeed` function (around line 676-703)

**Problem:** Feed URLs aren't validated for protocol. Could accept `file://`, `javascript:`, etc.

**Fix:** Add validation after the URL is extracted from the form:

```typescript
// After: const url = typeof rawUrl === "string" ? rawUrl.trim() : "";
// Add:
try {
  const parsed = new URL(url);
  if (!["http:", "https:"].includes(parsed.protocol)) {
    return htmlResponse("<p>Only HTTP and HTTPS URLs are supported</p>", 400);
  }
} catch {
  return htmlResponse("<p>Invalid URL format</p>", 400);
}
```

- [x] Complete

---

## 4. Race Condition Guard for Audio Conversions

**File:** `index.ts`

**Problem:** Two simultaneous conversion requests for the same file both check `exists()`, both get false, both start ffmpeg.

**Fix:** Add a Set to track in-progress conversions. Near the top of the file (with other constants):

```typescript
const conversionsInProgress = new Set<string>();
```

Then modify `convertAudio` function (around line 569-599):

```typescript
const convertAudio = async (originalPath: string, targetPath: string, speed: number) => {
  // Check if already converted
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
    // ... existing ffmpeg conversion logic ...
  } finally {
    conversionsInProgress.delete(targetPath);
  }
};
```

- [x] Complete

---

## 5. Race Condition Guard for Gemini API Calls

**File:** `index.ts`

**Problem:** Concurrent requests can both see `short_name` as null and both call Gemini API.

**Fix:** Add Sets to track in-progress shortname generations near the top:

```typescript
const feedShortNameInProgress = new Set<number>();
const episodeShortNameInProgress = new Set<number>();
```

Modify `ensureFeedShortName` (around line 123):

```typescript
const ensureFeedShortName = async (feed: FeedRow): Promise<string> => {
  if (feed.short_name) return feed.short_name;
  if (feedShortNameInProgress.has(feed.id)) {
    return slugify(feed.title || "feed", maxLen);  // Return fallback while in progress
  }

  feedShortNameInProgress.add(feed.id);
  try {
    // ... existing logic to generate and save shortname ...
  } finally {
    feedShortNameInProgress.delete(feed.id);
  }
};
```

Apply the same pattern to `ensureEpisodeShortName` (around line 135).

- [x] Complete

---

## 6. HTTP Timeouts for External Requests

**Files:** `index.ts` and `feedService.ts`

**Problem:** External fetches can hang indefinitely.

**Fix:** Create a helper function and use it for all external fetches:

```typescript
const fetchWithTimeout = async (
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
```

Update fetch calls in:
- `index.ts` `ensureOriginalAudio` function (around line 536-567) - audio downloads, use longer timeout (60000ms)
- `feedService.ts` `refreshFeed` function (around line 248) - feed fetches

- [x] Complete

---

## 7. Temp File Cleanup on Error

**File:** `index.ts` in `writeId3Tags` function (around line 384-415)

**Problem:** If ffmpeg fails, the `.tmp.mp3` file is left behind.

**Fix:** Wrap in try/finally and clean up:

```typescript
import { unlinkSync } from "fs";

const writeId3Tags = async (filePath: string, tags: { ... }) => {
  const tempPath = `${filePath}.tmp.mp3`;
  const args = [ /* ... existing args ... */ ];

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
```

- [ ] Complete

---

## 8. Download Size Limit for Audio Files

**File:** `index.ts` in `ensureOriginalAudio` function (around line 536-567)

**Problem:** No limit on download size - a malicious feed could cause memory/disk exhaustion.

**Fix:** Add a size check before downloading:

```typescript
const MAX_AUDIO_SIZE = 500 * 1024 * 1024; // 500 MB

// In ensureOriginalAudio, after the fetch:
const contentLength = parseInt(response.headers.get("content-length") || "0", 10);
if (contentLength > MAX_AUDIO_SIZE) {
  throw new Error(`Audio file too large: ${contentLength} bytes (max ${MAX_AUDIO_SIZE})`);
}
```

Note: This only works when the server provides Content-Length. For extra safety, you could also track bytes while streaming, but that's a more invasive change.

- [x] Complete

---

## Testing

After completing all fixes, manually test:

1. **Path traversal:** Try accessing `http://localhost:3000/media/../index.ts` - should return 404
2. **XSS:** Add a feed with `<script>alert('xss')</script>` in the title (mock RSS) - should show escaped text
3. **URL validation:** Try adding a feed with `file:///etc/passwd` - should be rejected
4. **Conversion race:** Rapidly click the same convert button twice - should not error
5. **Timeouts:** Test with a slow/unreachable feed URL - should timeout gracefully

---

## Notes

- Import `resolve` from `"path"` if not already imported
- Import `unlinkSync` from `"fs"` if not already imported
- The `fetchWithTimeout` helper can be placed near other utility functions at the top of the file
- Constants like `MAX_AUDIO_SIZE` should go with other constants near the top
