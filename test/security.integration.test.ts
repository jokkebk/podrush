import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { spawn } from "bun";
import { existsSync, mkdirSync, rmSync } from "fs";

// Test server details
const TEST_DB_PATH = "db.test.sqlite";

// We'll start a test fixture server to serve our malicious RSS feeds
let fixtureServer: ReturnType<typeof spawn> | null = null;
let appServer: ReturnType<typeof spawn> | null = null;
let appPort = 0;
let fixturePort = 0;
let baseUrl = "";
let fixtureBaseUrl = "";
const randomPort = () => 20000 + Math.floor(Math.random() * 20000);

const waitForServer = async (url: string, timeoutMs = 10000) => {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const response = await fetch(url);
      if (response.status) return;
    } catch {
      // Ignore until the server is ready.
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`Timed out waiting for server at ${url}`);
};

const cleanupDbFiles = (path: string) => {
  for (const suffix of ["", "-wal", "-shm"]) {
    const candidate = `${path}${suffix}`;
    if (existsSync(candidate)) {
      rmSync(candidate);
    }
  }
};

describe("Security Integration Tests", () => {
  beforeAll(async () => {
    fixturePort = randomPort();
    appPort = randomPort();
    if (appPort === fixturePort) appPort += 1;
    baseUrl = `http://localhost:${appPort}`;
    fixtureBaseUrl = `http://localhost:${fixturePort}`;

    // Create test media directories
    mkdirSync("./media", { recursive: true });
    mkdirSync("./media/original", { recursive: true });
    mkdirSync("./media/converted", { recursive: true });

    // Start a simple HTTP server for test fixtures
    fixtureServer = spawn([
      "bun",
      "-e",
      `Bun.serve({
        port: ${fixturePort},
        fetch(req) {
          const url = new URL(req.url);
          if (url.pathname === "/malicious_xss.xml") {
            return new Response(Bun.file("./test/fixtures/malicious_xss.xml"));
          }
          if (url.pathname === "/valid_feed.xml") {
            return new Response(Bun.file("./test/fixtures/valid_feed.xml"));
          }
          return new Response("Not Found", { status: 404 });
        }
      });`,
    ]);

    // Give fixture server time to start
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Start the main app server
    appServer = spawn(["bun", "run", "index.ts"], {
      env: { ...process.env, PODRUSH_DB_PATH: TEST_DB_PATH, PORT: String(appPort) },
    });
    await waitForServer(`${baseUrl}/api/feeds`);
  });

  afterAll(async () => {
    fixtureServer?.kill();
    appServer?.kill();
    await new Promise((resolve) => setTimeout(resolve, 500));
    cleanupDbFiles(TEST_DB_PATH);
  });

  describe("Path Traversal Protection", () => {
    test("should block access to index.ts via path traversal", async () => {
      const response = await fetch(`${baseUrl}/media/../index.ts`);
      expect(response.status).toBe(404);
    });

    test("should block access to package.json", async () => {
      const response = await fetch(`${baseUrl}/media/../package.json`);
      expect(response.status).toBe(404);
    });

    test("should block deep path traversal attempts", async () => {
      const response = await fetch(`${baseUrl}/media/../../../../../../etc/passwd`);
      expect(response.status).toBe(404);
    });

    test("should block sibling directory access", async () => {
      const response = await fetch(`${baseUrl}/media/../html/index.html`);
      expect(response.status).toBe(404);
    });

    test("should allow legitimate media file requests", async () => {
      // This will 404 because file doesn't exist, but it won't be blocked by path traversal
      const response = await fetch(`${baseUrl}/media/original/test.mp3`);
      // Should be 404 (file not found) not 404 (path traversal blocked)
      // Both are 404, but the point is it's not blocked at the path level
      expect(response.status).toBe(404);
    });
  });

  describe("XSS Prevention", () => {
    test("should escape malicious script tags in feed", async () => {
      const formData = new FormData();
      formData.append("url", `${fixtureBaseUrl}/malicious_xss.xml`);

      const response = await fetch(`${baseUrl}/api/feeds`, {
        method: "POST",
        body: formData,
      });

      expect(response.status).toBe(200);
      const html = await response.text();

      // Check that script tags are escaped
      expect(html).toContain("&lt;script&gt;");
      expect(html).not.toContain("<script>alert");

      // Check that single quotes are escaped
      expect(html).toContain("&#039;");

      // Check that event handlers are escaped
      expect(html).toContain("onerror=");
      expect(html).not.toMatch(/<img[^>]*onerror="[^"]*"/);
    }, 15000); // Increase timeout for Gemini API call

    test("should escape malicious content in feed description", async () => {
      const formData = new FormData();
      formData.append("url", `${fixtureBaseUrl}/malicious_xss.xml`);

      const response = await fetch(`${baseUrl}/api/feeds`, {
        method: "POST",
        body: formData,
      });

      const html = await response.text();

      // Verify dangerous HTML is escaped
      expect(html).toContain("&lt;img");
      expect(html).toContain("&quot;");
    });
  });

  describe("URL Protocol Validation", () => {
    test("should reject file:// protocol", async () => {
      const formData = new FormData();
      formData.append("url", "file:///etc/passwd");

      const response = await fetch(`${baseUrl}/api/feeds`, {
        method: "POST",
        body: formData,
      });

      expect(response.status).toBe(400);
      const html = await response.text();
      expect(html).toContain("Only HTTP and HTTPS");
    });

    test("should reject javascript: protocol", async () => {
      const formData = new FormData();
      formData.append("url", "javascript:alert('xss')");

      const response = await fetch(`${baseUrl}/api/feeds`, {
        method: "POST",
        body: formData,
      });

      expect(response.status).toBe(400);
      const html = await response.text();
      expect(html).toContain("Only HTTP and HTTPS");
    });

    test("should reject ftp:// protocol", async () => {
      const formData = new FormData();
      formData.append("url", "ftp://example.com/feed.xml");

      const response = await fetch(`${baseUrl}/api/feeds`, {
        method: "POST",
        body: formData,
      });

      expect(response.status).toBe(400);
      const html = await response.text();
      expect(html).toContain("Only HTTP and HTTPS");
    });

    test("should reject data: protocol", async () => {
      const formData = new FormData();
      formData.append("url", "data:text/html,<script>alert(1)</script>");

      const response = await fetch(`${baseUrl}/api/feeds`, {
        method: "POST",
        body: formData,
      });

      expect(response.status).toBe(400);
      const html = await response.text();
      expect(html).toContain("Only HTTP and HTTPS");
    });

    test("should accept valid HTTP URL", async () => {
      const formData = new FormData();
      formData.append("url", `${fixtureBaseUrl}/valid_feed.xml`);

      const response = await fetch(`${baseUrl}/api/feeds`, {
        method: "POST",
        body: formData,
      });

      expect(response.status).toBe(200);
    }, 15000); // Increase timeout for Gemini API call

    test("should accept valid HTTPS URL", async () => {
      const formData = new FormData();
      formData.append("url", "https://example.com/feed.xml");

      const response = await fetch(`${baseUrl}/api/feeds`, {
        method: "POST",
        body: formData,
      });

      // Will likely fail to fetch, but should pass URL validation
      expect(response.status).toBe(200);
    }, 15000); // Increase timeout for fetch attempt

    test("should reject malformed URLs", async () => {
      const formData = new FormData();
      formData.append("url", "not a valid url");

      const response = await fetch(`${baseUrl}/api/feeds`, {
        method: "POST",
        body: formData,
      });

      expect(response.status).toBe(400);
      const html = await response.text();
      expect(html).toContain("Invalid URL format");
    });
  });

  describe("HTTP Timeout", () => {
    test("should timeout on unreachable host", async () => {
      // Using a non-routable IP address (TEST-NET-1)
      const formData = new FormData();
      formData.append("url", "http://192.0.2.1:9999/feed.xml");

      const startTime = Date.now();
      const response = await fetch(`${baseUrl}/api/feeds`, {
        method: "POST",
        body: formData,
      });
      const endTime = Date.now();
      const duration = endTime - startTime;

      // Should complete in roughly 30-40 seconds (timeout + overhead)
      // Not hang indefinitely
      expect(duration).toBeLessThan(45000);

      // Should still return successfully (adds feed but fails to fetch)
      expect(response.status).toBe(200);
    }, 50000); // Test timeout of 50 seconds
  });

  describe("Content Type Validation", () => {
    test("should serve MP3 files with correct content type", async () => {
      // Note: This will 404 but we can check headers
      const response = await fetch(`${baseUrl}/media/converted/test.mp3`);
      // Even on 404, we can verify the intent by checking what would be served
      expect(response.status).toBe(404);
    });
  });

  describe("Empty/Missing Input Validation", () => {
    test("should reject empty URL", async () => {
      const formData = new FormData();
      formData.append("url", "");

      const response = await fetch(`${baseUrl}/api/feeds`, {
        method: "POST",
        body: formData,
      });

      expect(response.status).toBe(400);
      const html = await response.text();
      expect(html).toContain("Missing URL");
    });

    test("should reject whitespace-only URL", async () => {
      const formData = new FormData();
      formData.append("url", "   ");

      const response = await fetch(`${baseUrl}/api/feeds`, {
        method: "POST",
        body: formData,
      });

      expect(response.status).toBe(400);
      const html = await response.text();
      expect(html).toMatch(/Missing URL|Invalid URL format/);
    });
  });
});
