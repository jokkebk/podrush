const pageShell = (main: string): string => `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>podrush</title>
    <link rel="stylesheet" href="/static/app.css">
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
    <script src="/static/app.js" defer></script>
  </head>
  <body>
    <header class="app-header">
      <div class="container">
        <nav class="app-nav">
          <ul>
            <li><a href="/">podrush</a></li>
          </ul>
          <ul>
            <li><a href="/">Feeds</a></li>
            <li><a href="/converted">Converted</a></li>
          </ul>
        </nav>
      </div>
    </header>

    <main class="container app-main">
${main}
    </main>
  </body>
</html>`;

const feedsContent = `      <hgroup>
        <h1>Feeds</h1>
        <p>Add podcasts and keep them fresh automatically.</p>
      </hgroup>

      <details class="add-feed-details">
        <summary>+ Add podcast feed</summary>
        <form
          hx-post="/api/feeds"
          hx-target="#feeds-list"
          hx-swap="outerHTML"
          hx-indicator="#feed-loading"
        >
          <label for="url">RSS feed URL</label>
          <input type="url" id="url" name="url" placeholder="https://example.com/feed.xml" required>
          <button type="submit">Add feed</button>
          <span class="htmx-indicator" id="feed-loading">
            <span class="spinner" aria-label="Loading"></span>
          </span>
        </form>
      </details>

      <div
        id="feeds-list"
        hx-get="/api/feeds"
        hx-trigger="load"
        hx-swap="outerHTML"
      >
        Loading feeds\u2026
      </div>`;

const feedDetailContent = `      <div
        id="feed-detail"
        data-feed-detail
        hx-target="#feed-detail"
        hx-swap="innerHTML"
      >
        Loading feed\u2026
      </div>`;

const convertedContent = `      <hgroup>
        <h1>Converted</h1>
        <p>Review converted files and fix MP3 metadata using podcast data.</p>
      </hgroup>

      <div
        id="converted-list"
        hx-get="/api/converted"
        hx-trigger="load"
        hx-swap="outerHTML"
      >
        Loading converted files\u2026
      </div>`;

const htmlHeaders = { "Content-Type": "text/html; charset=utf-8" };

export const serveFeedsPage = () =>
  new Response(pageShell(feedsContent), { headers: htmlHeaders });

export const serveFeedDetailPage = () =>
  new Response(pageShell(feedDetailContent), { headers: htmlHeaders });

export const serveConvertedPage = () =>
  new Response(pageShell(convertedContent), { headers: htmlHeaders });
