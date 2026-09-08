const STORAGE_KEY = "videoBookmarks";

const currentPage = document.querySelector("#currentPage");
const noteInput = document.querySelector("#bookmarkNote");
const saveButton = document.querySelector("#saveBookmark");
const clearButton = document.querySelector("#clearBookmarks");
const bookmarkList = document.querySelector("#bookmarkList");
const emptyState = document.querySelector("#emptyState");

let activeTab = null;

async function getBookmarks() {
  const stored = await chrome.storage.local.get({ [STORAGE_KEY]: [] });
  return stored[STORAGE_KEY];
}

async function saveBookmarks(bookmarks) {
  await chrome.storage.local.set({ [STORAGE_KEY]: bookmarks });
}

function createBookmarkItem(bookmark) {
  const item = document.createElement("li");

  const openButton = document.createElement("button");
  openButton.className = "bookmark-link";
  openButton.type = "button";

  const title = document.createElement("span");
  title.className = "bookmark-title";
  title.textContent = bookmark.title || "Untitled video";

  const note = document.createElement("span");
  note.className = "bookmark-note";
  note.textContent = bookmark.note || "No timestamp or note";

  openButton.append(title, note);
  openButton.addEventListener("click", () => chrome.tabs.create({ url: bookmark.url }));

  const deleteButton = document.createElement("button");
  deleteButton.className = "delete-button";
  deleteButton.type = "button";
  deleteButton.setAttribute("aria-label", "Delete bookmark");
  deleteButton.textContent = "×";
  deleteButton.addEventListener("click", async () => {
    const bookmarks = await getBookmarks();
    await saveBookmarks(bookmarks.filter((item) => item.id !== bookmark.id));
    await renderBookmarks();
  });

  item.append(openButton, deleteButton);
  return item;
}

async function renderBookmarks() {
  const bookmarks = await getBookmarks();
  bookmarkList.replaceChildren(...bookmarks.map(createBookmarkItem));
  emptyState.hidden = bookmarks.length > 0;
}

async function loadCurrentTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTab = tabs[0] || null;

  if (!activeTab?.url) {
    currentPage.textContent = "The current tab cannot be bookmarked.";
    saveButton.disabled = true;
    return;
  }

  currentPage.textContent = activeTab.title || activeTab.url;
}

saveButton.addEventListener("click", async () => {
  if (!activeTab?.url) {
    return;
  }

  const bookmarks = await getBookmarks();
  bookmarks.unshift({
    id: crypto.randomUUID(),
    title: activeTab.title || "Untitled video",
    url: activeTab.url,
    note: noteInput.value.trim(),
    createdAt: new Date().toISOString(),
  });

  await saveBookmarks(bookmarks.slice(0, 25));
  noteInput.value = "";
  await renderBookmarks();
});

clearButton.addEventListener("click", async () => {
  await saveBookmarks([]);
  await renderBookmarks();
});

Promise.all([loadCurrentTab(), renderBookmarks()]).catch((error) => {
  currentPage.textContent = `Extension error: ${error.message}`;
});
