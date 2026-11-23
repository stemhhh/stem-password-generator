const CLEAR_MS = 30000;
let clearTimer = 0;

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "stem-clipboard-write") {
    const text = String(message.text || "");
    if (message.text) {
      message.text = "";
    }
    writeClipboard(text).then((ok) => {
      if (ok) {
        armClear();
      }
      sendResponse({ ok });
    });
    return true;
  }
  if (message?.type === "stem-clipboard-clear") {
    clearNow().then((ok) => sendResponse({ ok }));
    return true;
  }
  return false;
});

function armClear() {
  clearTimeout(clearTimer);
  clearTimer = setTimeout(() => {
    writeClipboard("");
  }, CLEAR_MS);
}

async function clearNow() {
  clearTimeout(clearTimer);
  clearTimer = 0;
  return writeClipboard("");
}

async function writeClipboard(text) {
  if (!navigator.clipboard?.writeText) {
    return false;
  }
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (_error) {
    return false;
  }
}
