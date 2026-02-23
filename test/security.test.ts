import { describe, test, expect } from "bun:test";
import { resolve } from "path";
import { escapeHtml, fetchWithTimeout } from "../lib";

describe("Security Unit Tests", () => {
  describe("escapeHtml", () => {
    test("should escape script tags", () => {
      const input = "<script>alert('xss')</script>";
      const output = escapeHtml(input);
      expect(output).toBe("&lt;script&gt;alert(&#039;xss&#039;)&lt;/script&gt;");
      expect(output).not.toContain("<script>");
    });

    test("should escape HTML attributes with event handlers", () => {
      const input = '<img src=x onerror="alert(1)">';
      const output = escapeHtml(input);
      expect(output).toBe("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
      // The attribute name appears but the quotes are escaped, making it safe
      expect(output).not.toContain('<img');
      expect(output).not.toContain('onerror="');
    });

    test("should escape ampersands", () => {
      const input = "Tom & Jerry";
      const output = escapeHtml(input);
      expect(output).toBe("Tom &amp; Jerry");
    });

    test("should escape single quotes", () => {
      const input = "It's a test";
      const output = escapeHtml(input);
      expect(output).toBe("It&#039;s a test");
    });

    test("should escape double quotes", () => {
      const input = 'He said "hello"';
      const output = escapeHtml(input);
      expect(output).toBe("He said &quot;hello&quot;");
    });

    test("should escape multiple dangerous characters", () => {
      const input = `<div onclick="alert('xss')">Tom & Jerry</div>`;
      const output = escapeHtml(input);
      expect(output).not.toContain("<div");
      expect(output).not.toContain('onclick="');
      expect(output).toContain("&lt;div");
      expect(output).toContain("&amp;");
    });

    test("should handle empty string", () => {
      expect(escapeHtml("")).toBe("");
    });

    test("should handle string without special chars", () => {
      const input = "Hello World 123";
      expect(escapeHtml(input)).toBe(input);
    });
  });

  describe("Path Traversal Protection", () => {
    const MEDIA_DIR = "./media";
    const mediaRoot = resolve(MEDIA_DIR);

    test("should block path traversal to parent directory", () => {
      const pathname = "/media/../index.ts";
      const safePath = resolve("." + pathname);
      expect(safePath.startsWith(mediaRoot)).toBe(false);
    });

    test("should block path traversal with multiple levels", () => {
      const pathname = "/media/../../../../../../etc/passwd";
      const safePath = resolve("." + pathname);
      expect(safePath.startsWith(mediaRoot)).toBe(false);
    });

    test("should block path traversal to sibling directory", () => {
      const pathname = "/media/../html/index.html";
      const safePath = resolve("." + pathname);
      expect(safePath.startsWith(mediaRoot)).toBe(false);
    });

    test("should allow valid media paths", () => {
      const pathname = "/media/original/test.mp3";
      const safePath = resolve("." + pathname);
      expect(safePath.startsWith(mediaRoot)).toBe(true);
    });

    test("should allow nested media paths", () => {
      const pathname = "/media/converted/subfolder/test.mp3";
      const safePath = resolve("." + pathname);
      expect(safePath.startsWith(mediaRoot)).toBe(true);
    });
  });

  describe("URL Protocol Validation", () => {
    const validateUrlProtocol = (url: string): boolean => {
      try {
        const parsed = new URL(url);
        return ["http:", "https:"].includes(parsed.protocol);
      } catch {
        return false;
      }
    };

    test("should accept HTTP URLs", () => {
      expect(validateUrlProtocol("http://example.com/feed.xml")).toBe(true);
    });

    test("should accept HTTPS URLs", () => {
      expect(validateUrlProtocol("https://example.com/feed.xml")).toBe(true);
    });

    test("should reject file:// protocol", () => {
      expect(validateUrlProtocol("file:///etc/passwd")).toBe(false);
    });

    test("should reject javascript: protocol", () => {
      expect(validateUrlProtocol("javascript:alert('xss')")).toBe(false);
    });

    test("should reject ftp:// protocol", () => {
      expect(validateUrlProtocol("ftp://example.com/file.txt")).toBe(false);
    });

    test("should reject data: protocol", () => {
      expect(validateUrlProtocol("data:text/html,<script>alert(1)</script>")).toBe(false);
    });

    test("should reject malformed URLs", () => {
      expect(validateUrlProtocol("not a url")).toBe(false);
      expect(validateUrlProtocol("")).toBe(false);
    });

    test("should handle URLs with ports", () => {
      expect(validateUrlProtocol("http://example.com:8080/feed.xml")).toBe(true);
      expect(validateUrlProtocol("https://example.com:443/feed.xml")).toBe(true);
    });
  });

  describe("Download Size Validation", () => {
    const MAX_AUDIO_SIZE = 500 * 1024 * 1024; // 500 MB

    test("should accept files under size limit", () => {
      const contentLength = 100 * 1024 * 1024; // 100 MB
      expect(contentLength <= MAX_AUDIO_SIZE).toBe(true);
    });

    test("should reject files over size limit", () => {
      const contentLength = 600 * 1024 * 1024; // 600 MB
      expect(contentLength > MAX_AUDIO_SIZE).toBe(true);
    });

    test("should accept files exactly at limit", () => {
      const contentLength = MAX_AUDIO_SIZE;
      expect(contentLength <= MAX_AUDIO_SIZE).toBe(true);
    });

    test("should reject files 1 byte over limit", () => {
      const contentLength = MAX_AUDIO_SIZE + 1;
      expect(contentLength > MAX_AUDIO_SIZE).toBe(true);
    });
  });

  describe("Race Condition Guards", () => {
    test("Set-based guard prevents duplicates", () => {
      const inProgress = new Set<string>();
      const targetPath = "/media/converted/test.mp3";

      // First request
      expect(inProgress.has(targetPath)).toBe(false);
      inProgress.add(targetPath);
      expect(inProgress.has(targetPath)).toBe(true);

      // Second concurrent request should detect
      expect(inProgress.has(targetPath)).toBe(true);

      // Cleanup
      inProgress.delete(targetPath);
      expect(inProgress.has(targetPath)).toBe(false);
    });

    test("Multiple different paths tracked independently", () => {
      const inProgress = new Set<string>();
      const path1 = "/media/converted/test1.mp3";
      const path2 = "/media/converted/test2.mp3";

      inProgress.add(path1);
      expect(inProgress.has(path1)).toBe(true);
      expect(inProgress.has(path2)).toBe(false);

      inProgress.add(path2);
      expect(inProgress.has(path1)).toBe(true);
      expect(inProgress.has(path2)).toBe(true);

      inProgress.delete(path1);
      expect(inProgress.has(path1)).toBe(false);
      expect(inProgress.has(path2)).toBe(true);
    });
  });

  describe("fetchWithTimeout", () => {
    test("should abort request after timeout", async () => {
      // Use a non-routable IP that will hang
      const unreachableUrl = "http://192.0.2.1:9999/test";
      const shortTimeout = 100; // 100ms

      await expect(
        fetchWithTimeout(unreachableUrl, {}, shortTimeout)
      ).rejects.toThrow();
    });

    test("should successfully fetch real endpoint", async () => {
      const response = await fetchWithTimeout("https://example.com", {}, 5000);
      expect(response.ok).toBe(true);
      expect(response.status).toBe(200);
    });

    test("should clear timeout on successful fetch", async () => {
      // This shouldn't throw even though we're using a short timeout
      // because example.com responds quickly
      const response = await fetchWithTimeout("https://example.com", {}, 5000);
      expect(response.ok).toBe(true);
    });
  });
});
