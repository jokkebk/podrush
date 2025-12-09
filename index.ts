import { Database } from "bun:sqlite";

type Feed = {
  id: number;
  url: string;
  title: string | null;
  description: string | null;
  last_checked: string | null;
};

const db = new Database("db.sqlite");
const indexPage = Bun.file("./html/index.html");

const selectFeeds = db.prepare(
  `
  SELECT id, url, title, description, last_checked
  FROM feeds
  ORDER BY id DESC
`
);

const findFeedByUrl = db.prepare("SELECT id FROM feeds WHERE url = ?");

const insertFeed = db.prepare(
  // TODO: refresh feed metadata/episodes after inserting the URL
  "INSERT INTO feeds (url, last_checked) VALUES (?, NULL)"
);

const htmlResponse = (body: string, status = 200) =>
  new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });

const notFound = () =>
  new Response("Not found", { status: 404, headers: { "Content-Type": "text/plain" } });

function renderFeeds(feeds: Feed[]): string {
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

function getFeeds(): Feed[] {
  return selectFeeds.all() as Feed[];
}

async function addFeed(request: Request) {
  const form = await request.formData();
  const rawUrl = form.get("url");
  const url = typeof rawUrl === "string" ? rawUrl.trim() : "";
  if (!url) {
    return htmlResponse("<p>Missing URL</p>", 400);
  }

  const existing = findFeedByUrl.get(url);
  if (!existing) {
    insertFeed.run(url);
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
      return htmlResponse(renderFeeds(feeds));
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
