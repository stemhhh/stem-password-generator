const HOST = "com.stem.passwordgenerator";
const SCRIPT_ID = "stem-page-helper";
const TOP_FRAME = { frameId: 0 };

console.log("[STEM][BG] service worker active");
console.log("[STEM][NATIVE] host name:", HOST);

chrome.runtime.onInstalled.addListener(() => {
  registerExtension();
  restoreSiteScripts();
  refreshBadge();
});

chrome.runtime.onStartup.addListener(() => {
  restoreSiteScripts();
  refreshBadge();
});

chrome.alarms.create("stem-status", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "stem-status") {
    refreshBadge();
  }
});

startWatch();
refreshBadge();

chrome.tabs.onUpdated.addListener((_tabId, info, tab) => {
  if (info.status === "complete") {
    offerPendingOnTab(tab).catch(() => {});
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  clearPendingSave(tabId).catch(() => {});
  sessionRemove(userKey(tabId)).catch(() => {});
});

chrome.commands.onCommand.addListener((command) => {
  if (command === "assist-login") {
    trustedTab().then((tab) => fillActiveTab(tab, "login"));
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "stem-clipboard-write" || message?.type === "stem-clipboard-clear") {
    return false;
  }
  handleMessage(message, sender).then(sendResponse).catch((error) => sendResponse({ ok: false, error: String(error) }));
  return true;
});

async function handleMessage(message, sender) {
  const tab = await trustedTab(sender);
  if (message?.type === "assist") {
    return assistUrl(tab, message.intent || "login");
  }
  if (message?.type === "fill-page") {
    return fillActiveTab(tab, message.intent || "login");
  }
  if (message?.type === "fill-id") {
    return fillActiveTab(tab, message.intent || "login", message.id);
  }
  if (message?.type === "open-item") {
    return openItem(tab, message.id);
  }
  if (message?.type === "list-logins") {
    return listLogins(tab);
  }
  if (message?.type === "alias") {
    return fillAlias(tab);
  }
  if (message?.type === "save-preview") {
    return savePreview(tab);
  }
  if (message?.type === "save-commit") {
    return saveCommit(tab);
  }
  if (message?.type === "pending-save") {
    return storePendingSave(tab, message);
  }
  if (message?.type === "save-pending") {
    return savePending(tab);
  }
  if (message?.type === "pending-save-status") {
    return pendingSaveStatus(tab);
  }
  if (message?.type === "dismiss-save") {
    await clearPendingSave(tab?.id);
    return { ok: true };
  }
  if (message?.type === "remember-username") {
    return rememberUsername(tab, message);
  }
  if (message?.type === "allow-site") {
    return allowActiveSite(tab);
  }
  if (message?.type === "status") {
    return native({ action: "status" });
  }
  if (message?.type === "generate") {
    return native({ action: "generate", length: message.length || 20 });
  }
  if (message?.type === "vault-changed") {
    return { ok: true };
  }
  if (message?.type === "chip-query") {
    return chipStateForTab(tab);
  }
  return { ok: false, error: "Unknown message." };
}

async function registerExtension() {
  const id = chrome.runtime.id || "";
  if (!/^[a-p]{32}$/.test(id)) {
    return;
  }
  await native({ action: "register" });
}

async function listLogins(tab) {
  tab = await sameTab(tab);
  const target = tab?.url || "";
  const blocked = transportBlock(target);
  if (blocked) {
    return blocked;
  }
  const listed = stripSecrets(await nativeVault(Object.assign({ action: "match", url: target }, isolationFields(tab))));
  return Object.assign(listed, await pageHints(tab));
}

async function assistUrl(tab, intent) {
  tab = await sameTab(tab);
  const target = tab?.url || "";
  const blocked = transportBlock(target);
  if (blocked) {
    return blocked;
  }
  if (intent === "signup") {
    await openProtocol(target, intent);
    return { ok: true, launched: true };
  }
  const response = stripSecrets(await nativeVault(Object.assign({ action: "match", url: target, intent }, isolationFields(tab))));
  if (response.ok && response.unlocked && Array.isArray(response.matches) && response.matches.length) {
    return response;
  }
  if (response.needsHello || response.warning || response.error === "Stem will not fill over HTTP.") {
    return response;
  }
  if (response.error) {
    return response;
  }
  return response.ok
    ? response
    : { ok: false, error: "Keep Stem open and unlocked, then tap Sign in again." };
}

async function fillActiveTab(tab, intent, id) {
  tab = await sameTab(tab);
  const target = tab?.url || "";
  const blocked = transportBlock(target);
  if (blocked) {
    return blocked;
  }
  if (tab?.id != null) {
    await ensureSiteAccess(tab);
    await inject(tab.id);
    tab = await sameTab(tab);
    if (!tab) {
      return { ok: false, error: "The page changed. Try again." };
    }
  }
  const listed = stripSecrets(await nativeVault(Object.assign({ action: "match", url: tab.url, intent }, isolationFields(tab))));
  if (!listed.ok && (listed.warning || listed.error === "Stem will not fill over HTTP.")) {
    return listed;
  }
  if (listed.needsHello) {
    return listed;
  }
  if (!listed.ok) {
    return listed.error || listed.warning
      ? listed
      : { ok: false, error: "Keep Stem open and unlocked, then tap Sign in again." };
  }
  const matches = Array.isArray(listed.matches) ? listed.matches : [];
  const fillable = matches.filter((match) => match?.id && !match.boundOtherContainer);
  if (id && matches.some((match) => match.id === id && match.boundOtherContainer)) {
    return openItem(tab, id);
  }
  if (id && !fillable.some((match) => match.id === id)) {
    return { ok: false, error: "That login does not belong to this site." };
  }
  if (!id && fillable.length > 1) {
    try {
      if (chrome.action?.openPopup) {
        await chrome.action.openPopup();
      }
    } catch (_error) {
    }
    return {
      ok: false,
      needsChoice: true,
      matches,
      error: "Choose which login in the Stem popup."
    };
  }
  const chosen = id || (fillable.length === 1 ? fillable[0].id : "");
  if (!chosen || tab?.id == null) {
    if (!fillable.length) {
      const hidden = matches.filter((match) => match?.id && match.boundOtherContainer);
      if (hidden.length) {
        return openItem(tab, hidden[0].id);
      }
      if (listed.warning) {
        return listed;
      }
      return { ok: false, error: "No saved login for this site." };
    }
    return listed;
  }
  tab = await sameTab(tab);
  if (!tab) {
    return { ok: false, error: "The page changed. Try again." };
  }
  const secret = await nativeVault(Object.assign({ action: "secret", id: chosen, url: tab.url }, isolationFields(tab)));
  const match = secret.matches && secret.matches[0];
  if (!secret.ok || !match?.password) {
    return stripSecrets(secret.ok ? listed : secret);
  }
  const info = await collectPageInfo(tab.id);
  const totpFieldCount = Number(info?.totpFieldCount) || 0;
  const pageInfoOk = !!info?.ok;
  const totp = String(match.totp || "");
  const sendTotp = isCopyableTotp(totp) && (!pageInfoOk || totpFieldCount > 0);
  const shouldCopyTotp = isCopyableTotp(totp) && pageInfoOk && totpFieldCount <= 0;
  let filled;
  let totpCopied = false;
  try {
    filled = await messagePasswordFrames(tab.id, {
      type: "fill",
      username: match.username,
      password: match.password,
      totp: sendTotp ? totp : "",
      intent: intent || "login"
    });
    if (shouldCopyTotp && filled?.ok) {
      totpCopied = await copyTotp(totp, tab.id);
    }
  } finally {
    match.password = "";
    match.totp = "";
  }
  if (!filled?.ok || filled.hasPassword === false) {
    return { ok: false, error: "Could not find a password box on this page." };
  }
  return stripSecrets(Object.assign({}, listed, await pageHints(tab), {
    ok: true,
    filledTitle: match.title,
    totpCopied
  }));
}

async function savePreview(tab) {
  tab = await sameTab(tab);
  const blocked = transportBlock(tab?.url, true);
  if (blocked) {
    return blocked;
  }
  if (tab?.id == null) {
    return { ok: false, error: "Open a website first." };
  }
  await ensureSiteAccess(tab);
  await inject(tab.id);
  tab = await sameTab(tab);
  if (!tab) {
    return { ok: false, error: "The page changed. Try again." };
  }
  const pending = await readPendingSave(tab.id);
  if (pending?.password) {
    return {
      ok: true,
      username: String(pending.username || "").slice(0, 200),
      host: pending.host || tabHost(tab.url),
      url: tab.url,
      inContainer: willBind(tab),
      browserManager: false
    };
  }
  const info = await collectPageInfo(tab.id);
  if (!info?.canSave) {
    return { ok: false, error: "Type the password on the page first." };
  }
  return {
    ok: true,
    username: String(info.username || "").slice(0, 200),
    host: tabHost(tab.url),
    url: tab.url,
    inContainer: willBind(tab),
    browserManager: !!info.browserManager
  };
}

async function saveCommit(tab) {
  tab = await sameTab(tab);
  const blocked = transportBlock(tab?.url, true);
  if (blocked) {
    return blocked;
  }
  if (tab?.id == null) {
    return { ok: false, error: "Open a website first." };
  }
  await ensureSiteAccess(tab);
  await inject(tab.id);
  tab = await sameTab(tab);
  if (!tab) {
    return { ok: false, error: "The page changed. Try again." };
  }
  const pending = await readPendingSave(tab.id);
  if (pending?.password) {
    return commitCapturedSave(tab, pending);
  }
  const captured = await captureFromTab(tab);
  if (!captured?.password) {
    return { ok: false, error: captured?.error || "Could not read the form." };
  }
  return commitCapturedSave(tab, captured);
}

async function commitCapturedSave(tab, captured) {
  const remembered = await readRememberedUsername(tab.id);
  const username = String(captured.username || remembered?.username || "").slice(0, 200);
  const host = tabHost(captured.url || tab.url);
  const saved = await nativeVault(Object.assign({
    action: "save",
    url: captured.url || tab.url,
    username,
    password: captured.password,
    title: captured.title || host
  }, isolationFields(tab)));
  captured.password = "";
  if (saved.ok) {
    await clearPendingSave(tab.id);
    await messageTop(tab.id, { type: "hide-save-bar" });
  }
  return {
    ok: !!saved.ok,
    needsHello: !!saved.needsHello,
    error: saved.error || saved.warning || (saved.ok ? "" : "Could not save that login."),
    warning: saved.warning,
    username,
    host
  };
}

async function fillAlias(tab) {
  tab = await sameTab(tab);
  const blocked = transportBlock(tab?.url);
  if (blocked) {
    return blocked;
  }
  if (tab?.id != null) {
    await ensureSiteAccess(tab);
    await inject(tab.id);
    tab = await sameTab(tab);
    if (!tab) {
      return { ok: false, error: "The page changed. Try again." };
    }
  }
  const result = await nativeVault({ action: "alias", url: tab.url });
  if (result.ok && result.alias && tab?.id != null) {
    await messagePasswordFrames(tab.id, { type: "fill-alias", alias: result.alias });
  }
  return result;
}

async function allowActiveSite(tab) {
  tab = await sameTab(tab);
  if (!tab?.url || !/^https?:/i.test(tab.url)) {
    return { ok: false, error: "Open a website first." };
  }
  const origin = originPattern(tab.url);
  if (!origin) {
    return { ok: false, error: "Stem cannot run on this page." };
  }
  const granted = await requestOrigin(origin);
  if (!granted) {
    return { ok: false, error: "Permission was not granted." };
  }
  await restoreSiteScripts();
  await inject(tab.id);
  return { ok: true };
}

function transportBlock(url, forSave) {
  if (!url || !/^https?:/i.test(url)) {
    return { ok: false, error: "Open a website first." };
  }
  try {
    const parsed = new URL(url);
    const loopback = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]";
    if (parsed.protocol === "http:" && !loopback) {
      return { ok: false, error: forSave ? "Stem will not save over HTTP." : "Stem will not fill over HTTP." };
    }
  } catch (_error) {
    return { ok: false, error: "Open a website first." };
  }
  return null;
}

async function openItem(tab, id) {
  tab = await sameTab(tab);
  const target = tab?.url || "";
  const blocked = transportBlock(target);
  if (blocked) {
    return blocked;
  }
  if (!id) {
    return { ok: false, error: "That login does not belong to this site." };
  }
  return stripSecrets(await nativeVault({ action: "open", url: target, id }));
}

function stripSecrets(response) {
  const matches = Array.isArray(response?.matches)
    ? response.matches.map((match) => ({
        id: match.id,
        title: match.title,
        username: match.username,
        url: match.url,
        reusedCount: match.reusedCount,
        reusedHint: match.reusedHint,
        hasTotp: !!match.hasTotp,
        containerWarning: !!match.containerWarning,
        boundOtherContainer: !!match.boundOtherContainer
      }))
    : [];
  const copy = Object.assign({}, response, { matches });
  delete copy.secret;
  if (copy.totpCopied) {
    copy.totpCopied = true;
  }
  return copy;
}

async function ensureSiteAccess(tab) {
  const origin = originPattern(tab?.url);
  if (!origin || !chrome.permissions?.contains) {
    return;
  }
  const already = await chrome.permissions.contains({ origins: [origin] });
  if (!already) {
    await requestOrigin(origin);
    await restoreSiteScripts();
  }
}

async function requestOrigin(origin) {
  if (!chrome.permissions?.request) {
    return true;
  }
  try {
    return await chrome.permissions.request({ origins: [origin] });
  } catch (_error) {
    return false;
  }
}

function isolationFields(tab) {
  return {
    container: String(tab?.cookieStoreId || ""),
    incognito: !!tab?.incognito
  };
}

function willBind(tab) {
  if (tab?.incognito) {
    return false;
  }
  if (/^firefox-container-\d+$/.test(String(tab?.cookieStoreId || ""))) {
    return true;
  }
  return !/Firefox/i.test(navigator.userAgent || "");
}

async function pageHints(tab) {
  if (tab?.id == null) {
    return {};
  }
  try {
    await inject(tab.id);
    const info = await collectPageInfo(tab.id);
    return { browserManager: !!info?.browserManager };
  } catch (_error) {
    return {};
  }
}

function originPattern(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    return parsed.origin + "/*";
  } catch (_error) {
    return null;
  }
}

async function inject(tabId) {
  if (!chrome.scripting?.executeScript) {
    try {
      await chrome.tabs.sendMessage(tabId, { type: "ping" }, TOP_FRAME);
    } catch (_error) {
    }
    return;
  }
  try {
    await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      files: ["content.js"]
    });
  } catch (_error) {
    try {
      await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ["content.js"] });
    } catch (_ignored) {
    }
  }
}

async function passwordFrameIds(tabId) {
  try {
    const found = await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      func: () => {
        try {
          return document.querySelectorAll("input[type='password']").length > 0;
        } catch (_error) {
          return false;
        }
      }
    });
    const ids = found.filter((row) => row.result).map((row) => row.frameId);
    return ids.length ? ids : [0];
  } catch (_error) {
    return [0];
  }
}

async function messagePasswordFrames(tabId, message) {
  const frames = await passwordFrameIds(tabId);
  let last = { ok: false };
  for (const frameId of frames) {
    try {
      const reply = await chrome.tabs.sendMessage(tabId, message, { frameId });
      if (reply?.ok) {
        last = reply;
      }
    } catch (_error) {
    }
  }
  return last;
}

async function collectPageInfo(tabId) {
  const frames = await passwordFrameIds(tabId);
  const merged = {
    ok: false,
    canSave: false,
    hasPassword: false,
    username: "",
    url: "",
    host: "",
    totpFieldCount: 0,
    browserManager: false
  };
  for (const frameId of frames) {
    try {
      const info = await chrome.tabs.sendMessage(tabId, { type: "page-info" }, { frameId });
      if (!info) {
        continue;
      }
      merged.ok = true;
      merged.hasPassword = merged.hasPassword || !!info.hasPassword;
      merged.canSave = merged.canSave || !!info.canSave;
      merged.totpFieldCount += Number(info.totpFieldCount) || 0;
      merged.browserManager = merged.browserManager || !!info.browserManager;
      if (!merged.username && info.username) {
        merged.username = info.username;
      }
      merged.url = info.url || merged.url;
      merged.host = info.host || merged.host;
    } catch (_error) {
    }
  }
  return merged;
}

async function captureFromTab(tab) {
  if (tab?.id == null) {
    return null;
  }
  const frames = await passwordFrameIds(tab.id);
  for (const frameId of frames) {
    try {
      const captured = await chrome.tabs.sendMessage(tab.id, { type: "capture" }, { frameId });
      if (captured?.ok && captured.password) {
        return captured;
      }
    } catch (_error) {
    }
  }
  return null;
}

async function messageTop(tabId, message) {
  try {
    await chrome.tabs.sendMessage(tabId, message, TOP_FRAME);
  } catch (_error) {
    try {
      await chrome.tabs.sendMessage(tabId, message);
    } catch (_ignored) {
    }
  }
}

const memorySession = new Map();

function saveKey(tabId) {
  return "stem-save-" + tabId;
}

function userKey(tabId) {
  return "stem-user-" + tabId;
}

async function sessionSet(key, value) {
  if (chrome.storage?.session) {
    await chrome.storage.session.set({ [key]: value });
    return;
  }
  memorySession.set(key, value);
}

async function sessionGet(key) {
  if (chrome.storage?.session) {
    const bag = await chrome.storage.session.get(key);
    return bag[key];
  }
  return memorySession.get(key);
}

async function sessionRemove(key) {
  if (chrome.storage?.session) {
    await chrome.storage.session.remove(key);
    return;
  }
  memorySession.delete(key);
}

function registrableHost(host) {
  const parts = String(host || "").replace(/^www\./i, "").split(".").filter(Boolean);
  if (parts.length < 2) {
    return String(host || "");
  }
  if (parts.length >= 3 && parts[parts.length - 1].length === 2 && parts[parts.length - 2].length <= 3) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

function hostsRelated(left, right) {
  const a = registrableHost(tabHost(left));
  const b = registrableHost(tabHost(right));
  return !!a && a === b;
}

async function readPendingSave(tabId) {
  if (tabId == null) {
    return null;
  }
  const pending = await sessionGet(saveKey(tabId));
  if (!pending?.password) {
    return null;
  }
  if (Date.now() - Number(pending.at || 0) > 120000) {
    await clearPendingSave(tabId);
    return null;
  }
  return pending;
}

async function clearPendingSave(tabId) {
  if (tabId == null) {
    return;
  }
  await sessionRemove(saveKey(tabId));
}

async function rememberUsername(tab, message) {
  if (tab?.id == null) {
    return { ok: false };
  }
  const username = String(message?.username || "").trim().slice(0, 200);
  if (!username) {
    return { ok: false };
  }
  await sessionSet(userKey(tab.id), { username, url: message.url || tab.url, at: Date.now() });
  return { ok: true };
}

async function readRememberedUsername(tabId) {
  const remembered = await sessionGet(userKey(tabId));
  if (!remembered?.username || Date.now() - Number(remembered.at || 0) > 120000) {
    return null;
  }
  return remembered;
}

async function storePendingSave(tab, message) {
  const url = message?.url || tab?.url || "";
  const blocked = transportBlock(url, true);
  if (blocked) {
    return blocked;
  }
  if (!tab?.id) {
    return { ok: false, error: "Open a website first." };
  }
  if (message?.filledByStem || !message?.password) {
    if (message?.username) {
      await rememberUsername(tab, message);
    }
    return { ok: true, offer: false };
  }
  const remembered = await readRememberedUsername(tab.id);
  const username = String(message.username || remembered?.username || "").slice(0, 200);
  const host = tabHost(url);
  const payload = {
    username,
    password: String(message.password || "").slice(0, 256),
    url,
    host,
    title: host,
    at: Date.now()
  };
  message.password = "";
  await sessionSet(saveKey(tab.id), payload);
  await messageTop(tab.id, { type: "show-save-bar", username, host });
  return { ok: true, offer: true, username, host };
}

async function pendingSaveStatus(tab) {
  const pending = await readPendingSave(tab?.id);
  if (!pending?.password) {
    return { ok: true, offer: false };
  }
  if (tab?.url && !hostsRelated(pending.url, tab.url)) {
    return { ok: true, offer: false };
  }
  return { ok: true, offer: true, username: pending.username, host: pending.host };
}

async function savePending(tab) {
  tab = await sameTab(tab) || tab;
  const blocked = transportBlock(tab?.url || "", true);
  if (blocked) {
    return blocked;
  }
  const pending = await readPendingSave(tab?.id);
  if (!pending?.password) {
    return saveCommit(tab);
  }
  return commitCapturedSave(tab, pending);
}

async function offerPendingOnTab(tab) {
  if (!tab?.id || transportBlock(tab.url, true)) {
    return;
  }
  const pending = await readPendingSave(tab.id);
  if (!pending?.password || !hostsRelated(pending.url, tab.url)) {
    return;
  }
  await inject(tab.id);
  await messageTop(tab.id, { type: "show-save-bar", username: pending.username, host: pending.host });
}

async function restoreSiteScripts() {
  if (!chrome.scripting?.registerContentScripts || !chrome.permissions?.getAll) {
    return;
  }
  const all = await chrome.permissions.getAll();
  const matches = (all.origins || []).filter((origin) => origin.startsWith("http"));
  try {
    await chrome.scripting.unregisterContentScripts({ ids: [SCRIPT_ID] });
  } catch (_error) {
  }
  if (!matches.length) {
    return;
  }
  try {
    await chrome.scripting.registerContentScripts([{
      id: SCRIPT_ID,
      js: ["content.js"],
      matches,
      runAt: "document_idle",
      persistAcrossSessions: true,
      allFrames: false
    }]);
  } catch (_error) {
  }
}

let lastUnlocked;
let watchPort = null;
let watchStarting = false;
let totpClipboardArmed = false;

async function refreshBadge() {
  const status = await native({ action: "status" });
  await applyBadge(!!(status.ok && status.unlocked), !!status.helloEnabled, status.connected !== false && status.vaultState !== "unknown");
}

async function applyBadge(unlocked, helloEnabled, connected = true) {
  const was = lastUnlocked;
  lastUnlocked = !!unlocked;
  if (chrome.action?.setBadgeText) {
    await chrome.action.setBadgeText({ text: unlocked ? "" : connected ? "!" : "?" });
    if (chrome.action.setBadgeBackgroundColor) {
      await chrome.action.setBadgeBackgroundColor({ color: unlocked ? "#108C10" : connected ? "#C42B1C" : "#C47B1C" });
    }
    if (chrome.action.setTitle) {
      const title = !connected
        ? "Stem — desktop disconnected"
        : unlocked
          ? "Stem — vault unlocked"
          : helloEnabled
            ? "Stem — confirm Windows Hello"
            : "Stem — vault locked";
      await chrome.action.setTitle({ title });
    }
  }
  if (!unlocked && was !== false) {
    await clearFilledTabs();
    await clearTotpClipboard();
  }
}

function startWatch() {
  if (watchStarting || watchPort || !chrome.runtime.connectNative) {
    return;
  }
  watchStarting = true;
  console.log("[STEM][NATIVE] attempting connection");
  try {
    watchPort = chrome.runtime.connectNative(HOST);
  } catch (error) {
    console.error("[STEM][NATIVE][ERROR]", String(error && error.message ? error.message : error));
    watchStarting = false;
    watchPort = null;
    setTimeout(startWatch, 1500);
    return;
  }
  watchPort.onMessage.addListener((message) => {
    if (typeof message?.unlocked === "boolean") {
      applyBadge(!!(message.ok !== false && message.unlocked), !!message.helloEnabled, message.ok !== false);
    }
    if (message?.vaultChanged || typeof message?.unlocked === "boolean") {
      chrome.runtime.sendMessage({
        type: "vault-changed",
        unlocked: !!(message?.ok !== false && message?.unlocked),
        vaultChanged: !!message?.vaultChanged
      }).catch(() => {});
      scheduleChipRefresh();
    }
  });
  watchPort.onDisconnect.addListener(() => {
    const message = chrome.runtime.lastError && chrome.runtime.lastError.message;
    if (message) {
      console.error("[STEM][NATIVE][ERROR]", message);
    }
    watchPort = null;
    watchStarting = false;
    refreshBadge();
    setTimeout(startWatch, 1500);
  });
  watchPort.postMessage({ action: "watch", origin: extensionOrigin() });
  watchStarting = false;
}

function isCopyableTotp(value) {
  return /^\d{6,8}$/.test(String(value || ""));
}

async function copyTotp(code, tabId) {
  if (!isCopyableTotp(code)) {
    return false;
  }
  if (await copyTotpOffscreen(code)) {
    totpClipboardArmed = true;
    return true;
  }
  if (tabId != null) {
    try {
      const copied = await chrome.tabs.sendMessage(tabId, { type: "copy-totp", totp: code }, TOP_FRAME);
      if (copied?.ok) {
        totpClipboardArmed = true;
        return true;
      }
    } catch (_error) {
    }
  }
  return false;
}

async function copyTotpOffscreen(code) {
  if (!chrome.offscreen?.createDocument) {
    return false;
  }
  try {
    const existing = chrome.runtime.getContexts
      ? await chrome.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"] })
      : [];
    if (!existing.length) {
      await chrome.offscreen.createDocument({
        url: "offscreen.html",
        reasons: ["CLIPBOARD"],
        justification: "Copy a one-time login code for 30 seconds, then erase it."
      });
    }
    const written = await chrome.runtime.sendMessage({ type: "stem-clipboard-write", text: code });
    return !!written?.ok;
  } catch (_error) {
    return false;
  }
}

async function clearTotpClipboard() {
  if (!totpClipboardArmed) {
    return;
  }
  totpClipboardArmed = false;
  const tabs = await chrome.tabs.query({ url: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"] });
  await Promise.all(tabs.map(async (tab) => {
    if (tab.id == null) {
      return;
    }
    try {
      await chrome.tabs.sendMessage(tab.id, { type: "clear-totp-clipboard" }, TOP_FRAME);
    } catch (_error) {
    }
  }));
  try {
    await chrome.runtime.sendMessage({ type: "stem-clipboard-clear" });
  } catch (_error) {
  }
}

async function clearFilledTabs() {
  const tabs = await chrome.tabs.query({ url: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"] });
  await Promise.all(tabs.map(async (tab) => {
    if (tab.id == null) {
      return;
    }
    try {
      await chrome.tabs.sendMessage(tab.id, { type: "clear" }, TOP_FRAME);
    } catch (_error) {
    }
  }));
}

let chipTimer = 0;

function scheduleChipRefresh() {
  clearTimeout(chipTimer);
  chipTimer = setTimeout(() => {
    notifyChips().catch(() => {});
  }, 300);
}

async function notifyChips() {
  const tabs = await chrome.tabs.query({ url: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"] });
  for (const tab of tabs) {
    if (tab.id == null) {
      continue;
    }
    const state = await chipStateForTab(tab);
    try {
      await chrome.tabs.sendMessage(tab.id, Object.assign({ type: "chip-state" }, state), TOP_FRAME);
    } catch (_error) {
    }
  }
}

async function chipStateForTab(tab) {
  const empty = { unlocked: false, canFill: false, hiddenOther: false };
  if (!tab?.url || transportBlock(tab.url)) {
    return empty;
  }
  const status = await native({ action: "status" });
  const unlocked = !!(status.ok && status.unlocked);
  if (!unlocked) {
    return empty;
  }
  const listed = stripSecrets(await native(Object.assign({ action: "match", url: tab.url }, isolationFields(tab))));
  const matches = Array.isArray(listed.matches) ? listed.matches : [];
  return {
    unlocked: true,
    canFill: matches.some((match) => match?.id && !match.boundOtherContainer),
    hiddenOther: matches.some((match) => match?.id && match.boundOtherContainer)
  };
}

function native(payload) {
  return new Promise((resolve) => {
    console.log("[STEM][NATIVE] attempting connection", payload && payload.action ? payload.action : "");
    if (!chrome.runtime.sendNativeMessage) {
      console.error("[STEM][NATIVE][ERROR] Native messaging API unavailable");
      resolve({ ok: false, connected: false, vaultState: "unknown", error: "Native messaging is unavailable." });
      return;
    }
    chrome.runtime.sendNativeMessage(HOST, Object.assign({ origin: extensionOrigin() }, payload), (response) => {
      if (chrome.runtime.lastError) {
        const message = chrome.runtime.lastError.message || "Native messaging failed.";
        console.error("[STEM][NATIVE][ERROR]", message);
        resolve({ ok: false, connected: false, vaultState: "unknown", error: message, needsRegister: true });
        return;
      }
      resolve(classifyNative(response));
    });
  });
}

function classifyNative(response) {
  const payload = response || { ok: false, error: "No response from Stem." };
  if (payload.ok) {
    const vaultState = payload.unlocked ? "unlocked" : "locked";
    console.log("[STEM][NATIVE] connected successfully");
    console.log("[STEM][VAULT] state =", vaultState);
    return Object.assign({ connected: true, vaultState }, payload);
  }
  const locked = !!payload.needsHello
    || payload.error === "Unlock the vault."
    || payload.error === "Confirm Windows Hello in Stem."
    || payload.error === "Finish the number pad in Stem."
    || payload.error === "Enable Windows Hello in Stem Protect, then try again.";
  const connected = locked || payload.unlocked === true;
  const vaultState = locked ? "locked" : (payload.unlocked ? "unlocked" : "unknown");
  console.log("[STEM][DESKTOP] received status connected=", connected, "vault=", vaultState);
  return Object.assign({ connected, vaultState }, payload);
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitUntilUnlocked(ms) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const status = await native({ action: "status" });
    if (status?.ok && status.unlocked) {
      return true;
    }
    await delay(400);
  }
  return false;
}

async function nativeVault(payload) {
  const first = await native(payload);
  if (!first?.needsHello) {
    return first;
  }
  if (!await waitUntilUnlocked(90000)) {
    return first;
  }
  return native(payload);
}

async function openProtocol(url, intent) {
  return native({ action: "assist", url, intent });
}

function extensionOrigin() {
  const id = chrome.runtime.id || "";
  if (/^[a-p]{32}$/.test(id)) {
    return "chrome-extension://" + id + "/";
  }
  return id ? String(id) : "";
}

async function trustedTab(sender) {
  if (sender?.tab?.id != null) {
    return sender.tab;
  }
  return activeTab();
}

async function sameTab(tab) {
  if (tab?.id == null) {
    return null;
  }
  try {
    const fresh = await chrome.tabs.get(tab.id);
    if (!sameOrigin(tab.url, fresh?.url)) {
      return null;
    }
    return fresh;
  } catch (_error) {
    return null;
  }
}

function sameOrigin(left, right) {
  try {
    const a = new URL(left);
    const b = new URL(right);
    return a.protocol === b.protocol && a.host === b.host;
  } catch (_error) {
    return false;
  }
}

function tabHost(url) {
  try {
    return new URL(url).hostname;
  } catch (_error) {
    return "";
  }
}

async function activeTab() {
  const tabs = await chrome.tabs.query({ currentWindow: true, active: true });
  return tabs[0];
}
