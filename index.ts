import { db, refreshFeed, refreshFeedsIfStale, type FeedRow } from "./feedService";

const indexPage = Bun.file("./html/index.html");

const selectFeeds = db.prepare(
  `
  SELECT id, url, title, description, image_url, last_checked
  FROM feeds
  ORDER BY id DESC
`
);

const findFeedByUrl = db.prepare("SELECT id FROM feeds WHERE url = ?");

const insertFeed = db.prepare("INSERT INTO feeds (url, last_checked) VALUES (?, NULL)");

const htmlResponse = (body: string, status = 200) =>
  new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });

const notFound = () =>
  new Response("Not found", { status: 404, headers: { "Content-Type": "text/plain" } });

function renderFeeds(feeds: FeedRow[]): string {
  if (!feeds.length) {
    return `
      <section class="grid" id="feeds-list">
        <p>No feeds yet. Add one to get started.</p>
      </section>
    `;
  }

  const cards = feeds
    .map((feed) => {
      const title = feed.title || feed.url;
      const description = feed.description || "";
      const lastChecked = feed.last_checked || "never";
      return `
        <article>
          <header>
            <h3><a href="/feed/${feed.id}">${title}</a></h3>
            <p>${description}</p>
          </header>
          <footer>
            <small>Last checked: ${lastChecked}</small>
          </footer>
        </article>
      `;
    })
    .join("");

  return `<section class="grid" id="feeds-list">${cards}</section>`;
}

function getFeeds(): FeedRow[] {
  return selectFeeds.all() as FeedRow[];
}

async function addFeed(request: Request) {
  const form = await request.formData();
  const rawUrl = form.get("url");
  const url = typeof rawUrl === "string" ? rawUrl.trim() : "";
  if (!url) {
    return htmlResponse("<p>Missing URL</p>", 400);
  }

  const existing = findFeedByUrl.get(url);
  let feedId = existing?.id as number | undefined;
  if (!existing) {
    const result = insertFeed.run(url);
    feedId = Number(result.lastInsertRowid);
  }

  if (feedId) {
    // Fetch metadata and episodes right after adding.
    await refreshFeed({ id: feedId, url });
  }

  const feeds = getFeeds();
  return htmlResponse(renderFeeds(feeds));
}

Bun.serve({
  async fetch(request) {
    const { pathname } = new URL(request.url);

    if (request.method === "GET" && pathname === "/") {
      return new Response(indexPage, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (request.method === "GET" && pathname === "/api/feeds") {
      const feeds = getFeeds();
      await refreshFeedsIfStale(feeds);
      const refreshed = getFeeds();
      return htmlResponse(renderFeeds(refreshed));
    }

    if (request.method === "POST" && pathname === "/api/feeds") {
      return addFeed(request);
    }

    if (pathname === "/favicon.ico") {
      const file = Bun.file("./static/favicon.ico");
      if (await file.exists()) {
        return new Response(file, { headers: { "Content-Type": "image/x-icon" } });
      }
    }

    return notFound();
  },
});
