(() => {
  const collect = (root, selector) => {
    const result = [];
    if (root instanceof Element && root.matches(selector)) {
      result.push(root);
    }
    if (root instanceof Element || root instanceof Document) {
      result.push(...root.querySelectorAll(selector));
    }
    return result;
  };

  const updateFeedDescriptionToggles = (root = document) => {
    const items = collect(root, ".feed-description");
    items.forEach((details) => {
      const preview = details.querySelector(".feed-description-preview");
      if (!preview) return;
      const hasMore = preview.scrollHeight > preview.clientHeight + 1;
      if (hasMore) {
        details.classList.remove("no-more");
      } else {
        details.classList.add("no-more");
        details.open = true;
      }
    });
  };

  const syncEpisodeToggle = (description, toggle) => {
    const expanded = !description.classList.contains("is-collapsed");
    toggle.textContent = expanded ? "Show less" : "Show more";
    toggle.setAttribute("aria-expanded", String(expanded));
  };

  const updateEpisodeDescriptions = (root = document) => {
    const descriptions = collect(root, "[data-ep-description]");
    descriptions.forEach((description) => {
      const sibling = description.nextElementSibling;
      if (!(sibling instanceof HTMLElement) || !sibling.matches("[data-ep-toggle]")) return;

      const wasExpanded = !description.classList.contains("is-collapsed");
      if (wasExpanded) description.classList.add("is-collapsed");
      const hasMore = description.scrollHeight > description.clientHeight + 1;
      if (wasExpanded) description.classList.remove("is-collapsed");

      if (!hasMore) {
        description.classList.remove("is-collapsed");
        sibling.hidden = true;
        sibling.setAttribute("aria-hidden", "true");
        sibling.setAttribute("aria-expanded", "false");
        return;
      }

      sibling.hidden = false;
      sibling.removeAttribute("aria-hidden");
      syncEpisodeToggle(description, sibling);
    });
  };

  const setupFeedDetailFetch = () => {
    const detail = document.querySelector("[data-feed-detail]");
    if (!(detail instanceof HTMLElement)) return;
    if (detail.getAttribute("hx-get")) return;

    const parts = window.location.pathname.split("/").filter(Boolean);
    const feedId = parts[parts.length - 1];
    if (!feedId) {
      detail.textContent = "Missing feed id.";
      return;
    }

    detail.setAttribute("hx-get", `/api/feed/${feedId}`);
    detail.setAttribute("hx-trigger", "load");
    if (window.htmx && typeof window.htmx.process === "function") {
      window.htmx.process(detail);
    }
  };

  const customUploadForm = () => document.querySelector("[data-custom-upload]");

  const hasDraggedFiles = (event) => {
    const types = event.dataTransfer && event.dataTransfer.types;
    return Boolean(types && Array.from(types).includes("Files"));
  };

  const setupCustomUploadDrop = () => {
    let dragDepth = 0;

    document.addEventListener("dragenter", (event) => {
      if (!customUploadForm() || !hasDraggedFiles(event)) return;
      dragDepth += 1;
      document.body.classList.add("is-drag-over");
    });

    document.addEventListener("dragover", (event) => {
      if (!customUploadForm() || !hasDraggedFiles(event)) return;
      event.preventDefault();
    });

    document.addEventListener("dragleave", (event) => {
      if (!customUploadForm() || !hasDraggedFiles(event)) return;
      dragDepth = Math.max(0, dragDepth - 1);
      if (dragDepth === 0) document.body.classList.remove("is-drag-over");
    });

    document.addEventListener("drop", (event) => {
      const form = customUploadForm();
      if (!(form instanceof HTMLFormElement) || !hasDraggedFiles(event)) return;
      event.preventDefault();
      dragDepth = 0;
      document.body.classList.remove("is-drag-over");

      const files = Array.from(event.dataTransfer.files || []);
      const file = files.find((f) => f.name.toLowerCase().endsWith(".mp3"));
      if (!file) return;

      const input = form.querySelector('input[type="file"][name="file"]');
      if (!(input instanceof HTMLInputElement)) return;
      const transfer = new DataTransfer();
      transfer.items.add(file);
      input.files = transfer.files;

      const details = form.closest("details");
      if (details instanceof HTMLDetailsElement) details.open = true;

      form.requestSubmit();
    });
  };

  const initUi = (root = document) => {
    updateFeedDescriptionToggles(root);
    updateEpisodeDescriptions(root);
  };

  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const toggle = target.closest("[data-ep-toggle]");
    if (!(toggle instanceof HTMLElement)) return;
    const description = toggle.previousElementSibling;
    if (!(description instanceof HTMLElement) || !description.matches("[data-ep-description]")) return;
    description.classList.toggle("is-collapsed");
    syncEpisodeToggle(description, toggle);
  });

  document.addEventListener("submit", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLFormElement)) return;
    const message = target.getAttribute("data-confirm");
    if (message && !window.confirm(message)) {
      event.preventDefault();
    }
  });

  const boot = () => {
    setupFeedDetailFetch();
    setupCustomUploadDrop();
    initUi(document);
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

  document.body.addEventListener("htmx:afterSwap", (event) => {
    const detailTarget = event.detail && event.detail.target;
    const root = detailTarget instanceof Element ? detailTarget : document;
    initUi(root);
  });
})();
