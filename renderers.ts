import { type FeedRow, isCustomFeedUrl } from "./feedService";
import {
  escapeHtml, plainText, sanitizeHtml, descriptionDetails,
  formatTimestamp, formatDuration, formatSpeedLabel, formatId3Date,
  SPEEDS, EPISODES_PER_PAGE,
  type EpisodeRow, type ConvertedEntry,
} from "./lib";
import { readId3Tags } from "./audio";
import { type PodcastFeedStatus } from "./podcastFeed";

export const renderFeedShortNameForm = (feed: FeedRow, message = ""): string => {
  const shortName = escapeHtml(feed.short_name || "");
  const helper = message ? `<div class="short-name-message">${escapeHtml(message)}</div>` : "";
  return `
    <div class="short-name-block">
      <small>Short name</small>
      <form
        class="short-name-form"
        hx-post="/api/feeds/${feed.id}/short-name"
        hx-target="closest .short-name-block"
        hx-swap="outerHTML"
      >
        <input
          type="text"
          id="short-name-${feed.id}"
          name="short_name"
          value="${shortName}"
          maxlength="32"
          placeholder="short-name"
          aria-label="Short name"
        >
        <button type="submit" class="secondary">Save</button>
      </form>
      ${helper}
    </div>
  `;
};

type RenderFeedsOptions = {
  notice?: string;
  refreshInProgress?: boolean;
  hasStaleFeeds?: boolean;
  refreshMaxAgeHours?: number;
};

export function renderFeeds(feeds: FeedRow[], options: RenderFeedsOptions = {}): string {
  const {
    notice = "",
    refreshInProgress = false,
    hasStaleFeeds = false,
    refreshMaxAgeHours = 24,
  } = options;
  const refreshWindow =
    refreshMaxAgeHours % 24 === 0
      ? `${refreshMaxAgeHours / 24} day${refreshMaxAgeHours === 24 ? "" : "s"}`
      : `${refreshMaxAgeHours} hours`;
  const refreshState = refreshInProgress
    ? "Refreshing feeds in background."
    : hasStaleFeeds
      ? `Some feeds are older than ${refreshWindow}.`
      : `All feeds checked within ${refreshWindow}.`;
  const noticeHtml = notice
    ? `<div class="feeds-refresh-notice">${escapeHtml(notice)}</div>`
    : "";
  const toolbar = `
    <div class="feeds-toolbar">
      <div class="feeds-toolbar-copy">
        <small>Auto refresh runs in background.</small>
        <small>${escapeHtml(refreshState)}</small>
        ${noticeHtml}
      </div>
      <form
        class="feeds-refresh-form"
        hx-post="/api/feeds/refresh"
        hx-target="#feeds-list"
        hx-swap="outerHTML"
        hx-indicator="#feeds-refresh-indicator"
      >
        <button type="submit" class="secondary">Refresh now</button>
        <span class="htmx-indicator" id="feeds-refresh-indicator">
          <span class="spinner" aria-label="Loading"></span>
        </span>
      </form>
    </div>
  `;

  if (!feeds.length) {
    return `
      <section id="feeds-list">
        ${toolbar}
        <div class="grid feeds-grid">
          <p>No feeds yet. Add one to get started.</p>
        </div>
      </section>
    `;
  }

  const cards = feeds
    .map((feed) => {
      const title = escapeHtml(feed.title || feed.url);
      const descHtml = feed.description || "";
      const description = escapeHtml(plainText(descHtml).slice(0, 200));
      const lastChecked = formatTimestamp(feed.last_checked);
      const shortNameForm = renderFeedShortNameForm(feed);
      return `
        <article class="feed-card">
          <header>
            <h3><a href="/feed/${feed.id}">${title}</a></h3>
            <details class="feed-description">
              <summary>
                <span class="feed-description-preview">${description}</span>
                <span class="feed-description-more">More</span>
              </summary>
              <div class="feed-description-full">${sanitizeHtml(descHtml)}</div>
            </details>
          </header>
          <footer>
            ${shortNameForm}
            <small title="${escapeHtml(feed.last_checked || "")}">Last checked: ${lastChecked}</small>
          </footer>
        </article>
      `;
    })
    .join("");

  return `
    <section id="feeds-list">
      ${toolbar}
      <div class="grid feeds-grid">${cards}</div>
    </section>
  `;
}

export function renderEpisodeList(
  feedId: number,
  episodes: EpisodeRow[],
  conversions: Record<number, Record<string, string>>,
  offset: number
): string {
  const page = episodes.slice(offset, offset + EPISODES_PER_PAGE);
  const hasMore = episodes.length > offset + EPISODES_PER_PAGE;

  const articles = page
    .map((ep) => {
      const duration = formatDuration(ep.duration_secs);
      const published = escapeHtml(formatTimestamp(ep.published_at));
      const epConversions = conversions[ep.id] || {};
      const buttons = SPEEDS.map((speed) => {
        const label = formatSpeedLabel(speed);
        const existing = epConversions[label];
        if (existing) {
          return `<a class="contrast" href="${escapeHtml(existing)}" download>Download ${label}x</a>`;
        }
        return `
            <button
              hx-post="/api/episodes/${ep.id}/convert"
              hx-vals='{"speed": "${speed}"}'
              hx-target="this"
              hx-indicator="this"
              hx-swap="outerHTML">
              <span class="convert-label">Convert ${label}x</span>
              <span class="htmx-indicator convert-working">
                <span class="spinner" aria-label="Converting"></span>
                <span>Converting...</span>
              </span>
            </button>
        `;
      }).join("");
      return `
        <article>
          <header>
            <h3>${escapeHtml(ep.title || "Untitled episode")}${duration ? ` <small>(${duration})</small>` : ""}</h3>
            <p><small>${published}</small></p>
          </header>
          ${descriptionDetails(ep.description || "")}
          <div class="convert-buttons">${buttons}</div>
        </article>
      `;
    })
    .join("");

  const loadMore = hasMore
    ? `<div class="load-more">
        <button class="secondary"
          hx-get="/api/feed/${feedId}?offset=${offset + EPISODES_PER_PAGE}"
          hx-target="closest .load-more"
          hx-swap="outerHTML"
          hx-indicator=".load-more-spinner">
          Load more episodes
          <span class="htmx-indicator load-more-spinner"><span class="spinner" aria-label="Loading"></span></span>
        </button>
      </div>`
    : "";

  return articles + loadMore;
}

export const renderCustomUploadForm = (): string => {
  const today = new Date().toISOString().slice(0, 10);
  const speedCheckboxes = SPEEDS.map((speed) => {
    const label = formatSpeedLabel(speed);
    const checked = speed === 1.25 ? " checked" : "";
    return `<label><input type="checkbox" name="speeds" value="${label}"${checked}> ${label}x</label>`;
  }).join("");
  return `
    <details class="add-feed-details custom-upload">
      <summary>+ Upload custom MP3</summary>
      <form
        hx-post="/api/custom/episodes"
        hx-encoding="multipart/form-data"
        hx-target="#feed-detail"
        hx-swap="innerHTML"
        hx-indicator="#custom-upload-indicator"
      >
        <label for="custom-file">MP3 file</label>
        <input type="file" id="custom-file" name="file" accept="audio/mpeg,.mp3" required>
        <label for="custom-title">Title (defaults to filename)</label>
        <input type="text" id="custom-title" name="title" maxlength="120" placeholder="Episode title">
        <label for="custom-date">Publish date</label>
        <input type="date" id="custom-date" name="published_at" value="${today}">
        <fieldset class="custom-upload-speeds">
          <legend>Convert to speeds</legend>
          ${speedCheckboxes}
        </fieldset>
        <button type="submit">Upload</button>
        <span class="htmx-indicator" id="custom-upload-indicator">
          <span class="spinner" aria-label="Uploading"></span>
        </span>
      </form>
    </details>
  `;
};

export function renderFeedDetail(
  feed: FeedRow,
  episodes: EpisodeRow[],
  conversions: Record<number, Record<string, string>>
) {
  const header = `
    <header>
      <p><a href="/">&larr; Back to feeds</a></p>
      <h1>${escapeHtml(feed.title || feed.url)}</h1>
      <div>${sanitizeHtml(feed.description || "")}</div>
    </header>
  `;
  const uploadForm = isCustomFeedUrl(feed.url) ? renderCustomUploadForm() : "";

  if (!episodes.length) {
    return `<section>${header}${uploadForm}<p>No episodes yet for this feed.</p></section>`;
  }

  return `<section>${header}${uploadForm}${renderEpisodeList(feed.id, episodes, conversions, 0)}</section>`;
}

const renderTagList = (tags: Record<string, string>) => {
  const title = escapeHtml(tags.title || "");
  const artist = escapeHtml(tags.artist || tags.album_artist || "");
  const album = escapeHtml(tags.album || "");
  const date = escapeHtml(tags.date || tags.year || "");
  const genre = escapeHtml(tags.genre || "");
  const lines = [
    title && `<span><strong>Title:</strong> ${title}</span>`,
    artist && `<span><strong>Artist:</strong> ${artist}</span>`,
    album && `<span><strong>Album:</strong> ${album}</span>`,
    date && `<span><strong>Date:</strong> ${date}</span>`,
    genre && `<span><strong>Genre:</strong> ${genre}</span>`,
  ].filter(Boolean);
  if (!lines.length) return `<span class="muted">No tags</span>`;
  return lines.join("");
};

const renderDbTagList = (entry: ConvertedEntry) => {
  if (!entry.episodeId) return `<span class="muted">Unmatched file</span>`;
  const title = escapeHtml(entry.episodeTitle || "");
  const artist = escapeHtml(entry.feedTitle || "");
  const album = escapeHtml(entry.feedTitle || "");
  const date = escapeHtml(formatId3Date(entry.publishedAt ?? null) || "");
  const genre = "Podcast";
  const lines = [
    title && `<span><strong>Title:</strong> ${title}</span>`,
    artist && `<span><strong>Artist:</strong> ${artist}</span>`,
    album && `<span><strong>Album:</strong> ${album}</span>`,
    date && `<span><strong>Date:</strong> ${date}</span>`,
    `<span><strong>Genre:</strong> ${genre}</span>`,
  ].filter(Boolean);
  if (!lines.length) return `<span class="muted">No data</span>`;
  return lines.join("");
};

export const tagsMatch = (entry: ConvertedEntry, fileTags: Record<string, string>): boolean => {
  if (!entry.episodeId) return true;
  const dbTitle = (entry.episodeTitle || "").trim();
  const dbArtist = (entry.feedTitle || "").trim();
  const dbDate = formatId3Date(entry.publishedAt ?? null) || "";
  const fileTitle = (fileTags.title || "").trim();
  const fileArtist = (fileTags.artist || fileTags.album_artist || "").trim();
  const fileDate = (fileTags.date || fileTags.year || "").trim();
  return dbTitle === fileTitle && dbArtist === fileArtist && dbDate === fileDate;
};

export const renderConvertedRow = (entry: ConvertedEntry, tags: Record<string, string>, message = "") => {
  const fileLink = `/media/converted/${escapeHtml(entry.filename)}`;
  const speed = entry.speedLabel ? `${escapeHtml(entry.speedLabel)}x` : "Unknown";
  const synced = tagsMatch(entry, tags);
  const tagStatus = entry.episodeId
    ? (synced
        ? `<span class="tag-status tag-status--ok">&#10003; Tags synced</span>`
        : `<span class="tag-status tag-status--warn">&#9888; Tags differ</span>`)
    : "";
  const actions = entry.episodeId
    ? `
      <form
        hx-post="/api/converted/retag"
        hx-target="closest tr"
        hx-swap="outerHTML"
        class="inline-form"
      >
        <input type="hidden" name="filename" value="${escapeHtml(entry.filename)}">
        <button type="submit" class="secondary">Copy from podcast data</button>
      </form>
      <form
        hx-post="/api/converted/delete"
        hx-target="closest tr"
        hx-swap="outerHTML"
        class="inline-form"
        data-confirm="Delete this converted file?"
      >
        <input type="hidden" name="filename" value="${escapeHtml(entry.filename)}">
        <button type="submit" class="contrast">Delete file</button>
      </form>
    `
    : `<span class="muted">No match</span>`;
  const statusMsg = message ? `<div class="muted">${escapeHtml(message)}</div>` : "";
  return `
    <tr>
      <td>
        <div><a href="${fileLink}" download>${escapeHtml(entry.filename)}</a></div>
        <div class="muted">${speed}</div>
      </td>
      <td class="tag-list">${renderDbTagList(entry)}${tagStatus}</td>
      <td>
        ${actions}
        ${statusMsg}
      </td>
    </tr>
  `;
};

export const renderConvertedTable = async (entries: ConvertedEntry[], messageByFile = new Map<string, string>()) => {
  if (!entries.length) {
    return `<p>No converted files found.</p>`;
  }
  const rows = await Promise.all(
    entries.map(async (entry) => {
      let tags: Record<string, string> = {};
      try {
        tags = await readId3Tags(entry.path);
      } catch {
        tags = {};
      }
      const message = messageByFile.get(entry.filename) || "";
      return renderConvertedRow(entry, tags, message);
    })
  );
  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>File</th>
            <th>Episode / Tags</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          ${rows.join("")}
        </tbody>
      </table>
    </div>
  `;
};

export const renderPodcastPublishPanel = (status: PodcastFeedStatus): string => {
  const publicFeedUrl = status.configuredPublicBaseUrl
    ? `<a href="${escapeHtml(status.publicFeedUrl)}">${escapeHtml(status.publicFeedUrl)}</a>`
    : `<span class="muted">Set PODRUSH_PUBLIC_BASE_URL to produce public enclosure URLs.</span>`;
  const uploadTarget = status.configuredUploadTarget
    ? escapeHtml(status.uploadTarget)
    : "Set PODRUSH_UPLOAD_TARGET to enable upload.";
  const uploadDisabled = status.configuredUploadTarget ? "" : " disabled";
  const skipped = status.skippedFiles.length
    ? `<details class="publish-skipped">
        <summary>${status.skippedFiles.length} unmatched file${status.skippedFiles.length === 1 ? "" : "s"}</summary>
        <ul>${status.skippedFiles.map((name) => `<li>${escapeHtml(name)}</li>`).join("")}</ul>
      </details>`
    : "";
  const uploadSummary = status.uploadSummary
    ? `<pre class="publish-output">${escapeHtml(status.uploadSummary)}</pre>`
    : "";

  return `
    <div class="publish-panel">
      <div class="publish-summary">
        <div>
          <small>RSS file</small>
          <strong>${escapeHtml(status.feedFilename)}</strong>
          <span class="muted">${escapeHtml(status.feedPath)}</span>
        </div>
        <div>
          <small>Public feed URL</small>
          ${publicFeedUrl}
        </div>
        <div>
          <small>Items</small>
          <strong>${status.itemCount}</strong>
          <span class="muted">${status.unmatchedCount} unmatched</span>
        </div>
        <div>
          <small>Upload target</small>
          <span>${uploadTarget}</span>
        </div>
      </div>

      <div class="publish-actions">
        <form
          hx-post="/api/podcast-feed/regenerate"
          hx-target="#converted-list"
          hx-swap="outerHTML"
          hx-indicator="#publish-regenerate-indicator"
          class="inline-form"
        >
          <button type="submit" class="secondary">Regenerate RSS</button>
          <span class="htmx-indicator" id="publish-regenerate-indicator">
            <span class="spinner" aria-label="Loading"></span>
          </span>
        </form>
        <form
          hx-post="/api/podcast-feed/upload"
          hx-target="#converted-list"
          hx-swap="outerHTML"
          hx-indicator="#publish-upload-indicator"
          class="inline-form"
        >
          <button type="submit" class="contrast"${uploadDisabled}>Upload</button>
          <span class="htmx-indicator" id="publish-upload-indicator">
            <span class="spinner" aria-label="Loading"></span>
          </span>
        </form>
      </div>

      <div class="publish-status">
        <span>${escapeHtml(status.message || "RSS status current.")}</span>
        <span class="muted">Generated ${escapeHtml(formatTimestamp(status.generatedAt))}</span>
      </div>
      ${skipped}
      ${uploadSummary}
    </div>
  `;
};

export const renderConvertedManagement = async (
  entries: ConvertedEntry[],
  status: PodcastFeedStatus
) => {
  const table = await renderConvertedTable(entries);
  return `
    <section id="converted-list">
      ${renderPodcastPublishPanel(status)}
      ${table}
    </section>
  `;
};
