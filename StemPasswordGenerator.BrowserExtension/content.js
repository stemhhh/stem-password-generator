(function () {
  if (window.__stemPasswordHelper) {
    return;
  }
  window.__stemPasswordHelper = true;
  console.log("[STEM][CONTENT] loaded:", location.href);

  const MAX_USER = 200;
  const MAX_SECRET = 256;
  const SAVE_HOST_ID = "stem-save-host";

  function queryDeep(selector, root) {
    const found = [];
    const visit = (node) => {
      if (!node || !node.querySelectorAll) {
        return;
      }
      found.push(...node.querySelectorAll(selector));
      node.querySelectorAll("*").forEach((element) => {
        if (element.shadowRoot) {
          visit(element.shadowRoot);
        }
      });
    };
    visit(root || document);
    return found;
  }

  function visible(element) {
    if (!element || element.disabled) {
      return false;
    }
    const rect = element.getBoundingClientRect();
    const style = window.getComputedStyle(element);
    return rect.width > 20 && rect.height > 12 && style.visibility !== "hidden" && style.display !== "none";
  }

  function fieldKey(element) {
    return `${element.autocomplete || ""} ${element.name || ""} ${element.id || ""} ${element.placeholder || ""} ${element.getAttribute("aria-label") || ""}`.toLowerCase();
  }

  function isTotpField(element) {
    const key = fieldKey(element);
    return element.autocomplete === "one-time-code"
      || /otp|totp|2fa|one-time|one_time|codigo|código/.test(key)
      || (element.inputMode === "numeric" && element.maxLength === 6);
  }

  function passwordRole(input) {
    const key = fieldKey(input);
    if (key.includes("new-password") || /new|confirm|repeat|nueva|confirmar/.test(key)) {
      return "new";
    }
    if (key.includes("current-password") || /old|current|existing|actual|vieja/.test(key)) {
      return "current";
    }
    return "unknown";
  }

  function passwordInputs() {
    return queryDeep("input[type='password']").filter((input) => visible(input) && !isTotpField(input));
  }

  function totpInputs() {
    return queryDeep("input").filter((input) => visible(input) && isTotpField(input));
  }

  function frameIsUsable() {
    if (window.top === window) {
      return true;
    }
    return window.innerWidth >= 240 && window.innerHeight >= 80;
  }

  function pageHaystack() {
    const heading = document.querySelector("h1,h2,[class*='title']");
    const form = document.querySelector("form");
    const text = `${heading?.innerText || ""} ${form?.innerText || ""} ${document.title || ""}`;
    return text.slice(0, 4000).toLowerCase();
  }

  function formKind() {
    const boxes = passwordInputs();
    const news = boxes.filter((input) => passwordRole(input) === "new");
    const currents = boxes.filter((input) => passwordRole(input) === "current");
    const haystack = pageHaystack();
    if (currents.length && news.length) {
      return "change";
    }
    if (news.length >= 2 || /sign up|signup|register|create account|join now|registr|crear cuenta|create your/.test(haystack)) {
      return "signup";
    }
    if (boxes.length >= 2 && news.length === 0 && /sign up|signup|register|crear cuenta|create account/.test(haystack)) {
      return "signup";
    }
    return "login";
  }

  function intent() {
    const kind = formKind();
    return kind === "signup" ? "signup" : "login";
  }

  function scoreUsername(element, form) {
    const key = fieldKey(element);
    const type = (element.type || "text").toLowerCase();
    if (type === "hidden" || type === "password" || type === "submit" || type === "button" || type === "checkbox" || type === "radio" || type === "file") {
      return -100;
    }
    if (element.getAttribute("role") === "searchbox" || /search|query|^q$|captcha|filter/.test(key)) {
      return -100;
    }
    if (isTotpField(element)) {
      return -100;
    }
    let score = 0;
    if (form && (element.form === form || form.contains(element))) {
      score += 25;
    } else if (form) {
      score -= 8;
    }
    if (type === "email" || element.autocomplete === "email") {
      score += 40;
    }
    if (element.autocomplete === "username") {
      score += 35;
    }
    if (/email|user|login|identifier|phone|account/.test(key)) {
      score += 20;
    }
    if (type === "text" || type === "tel" || type === "url") {
      score += 5;
    }
    return score;
  }

  function usernameField() {
    const pass = passwordInputs()[0];
    const form = pass?.form || pass?.closest("form") || document.querySelector("form");
    const candidates = queryDeep("input:not([type='hidden']):not([type='password']):not([type='submit']):not([type='button']):not([type='checkbox']):not([type='radio']):not([type='file'])")
      .filter(visible);
    const ranked = candidates
      .map((element) => ({ element, score: scoreUsername(element, form) }))
      .filter((row) => row.score > 0)
      .sort((left, right) => right.score - left.score);
    return ranked[0]?.element || null;
  }

  function emailField() {
    return queryDeep("input[type='email'], input[name='email' i], input[autocomplete='email']").filter(visible)[0]
      || usernameField();
  }

  function mark(element) {
    if (element) {
      element.setAttribute("data-stem-filled", "1");
    }
  }

  function setValue(element, value, protect) {
    if (!element || value == null) {
      return;
    }
    const prototype = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(prototype, "value")?.set;
    element.focus();
    setter ? setter.call(element, value) : (element.value = value);
    mark(element);
    element.dispatchEvent(new Event("input", { bubbles: true }));
    element.dispatchEvent(new Event("change", { bubbles: true }));
    if (protect) {
      protectFromManager(element, value);
    }
  }

  function isUserEdit(event) {
    if (!event.isTrusted) {
      return false;
    }
    const type = event.inputType || "";
    return type === "insertText"
      || type === "insertCompositionText"
      || type === "deleteContentBackward"
      || type === "deleteContentForward"
      || type === "deleteByCut";
  }

  function protectFromManager(element, expected) {
    const until = Date.now() + 2500;
    const onInput = (event) => {
      if (Date.now() > until) {
        element.removeEventListener("input", onInput, true);
        return;
      }
      if (isUserEdit(event)) {
        element.removeEventListener("input", onInput, true);
        return;
      }
      if (element.value === expected) {
        return;
      }
      const prototype = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(prototype, "value")?.set;
      setter ? setter.call(element, expected) : (element.value = expected);
    };
    element.addEventListener("input", onInput, true);
  }

  function clearFilled(passwordsOnly) {
    queryDeep("[data-stem-filled='1']").forEach((element) => {
      if (passwordsOnly && element.getAttribute("type") !== "password") {
        return;
      }
      setValue(element, "");
      element.removeAttribute("data-stem-filled");
    });
  }

  function fillPasswords(password, fillIntent) {
    const boxes = passwordInputs();
    const news = boxes.filter((input) => passwordRole(input) === "new");
    const currents = boxes.filter((input) => passwordRole(input) === "current");
    if (fillIntent === "signup" || news.length >= 2) {
      (news.length ? news : boxes).forEach((input) => setValue(input, password, true));
      return;
    }
    if (currents.length) {
      currents.forEach((input) => setValue(input, password, true));
      return;
    }
    if (boxes.length >= 2) {
      setValue(boxes[0], password, true);
      return;
    }
    boxes.forEach((input) => setValue(input, password, true));
  }

  function clip(value, max) {
    return String(value || "").slice(0, max);
  }

  let totpClearTimer = 0;
  let lastStemFill = null;
  let lastCaptureKey = "";
  let lastCaptureAt = 0;

  async function copyTotpCode(code) {
    if (!/^\d{6,8}$/.test(code) || !navigator.clipboard?.writeText) {
      return false;
    }
    try {
      await navigator.clipboard.writeText(code);
      armTotpClear();
      return true;
    } catch (_error) {
      return false;
    }
  }

  function armTotpClear() {
    clearTimeout(totpClearTimer);
    totpClearTimer = setTimeout(() => {
      clearTotpClipboard();
    }, 30000);
  }

  async function clearTotpClipboard() {
    clearTimeout(totpClearTimer);
    totpClearTimer = 0;
    if (!navigator.clipboard?.writeText) {
      return false;
    }
    try {
      await navigator.clipboard.writeText("");
      return true;
    } catch (_error) {
      return false;
    }
  }

  function capturePassword() {
    const spanish = (navigator.language || "").toLowerCase().startsWith("es");
    const boxes = passwordInputs();
    const news = boxes.filter((input) => passwordRole(input) === "new");
    if (news.length >= 2 && news[0].value !== news[1].value) {
      return { error: spanish ? "Las claves nuevas no coinciden." : "The new passwords do not match." };
    }
    const source = news.length ? news[0] : boxes[0];
    const value = source?.value || "";
    if (!value) {
      return { error: spanish ? "Escribe la clave en la página primero." : "Type the password on the page first." };
    }
    if (value.length > MAX_SECRET) {
      return { error: spanish ? "Esa clave es demasiado larga para guardar." : "That password is too long to save." };
    }
    return { password: value };
  }

  function invitesBrowserManager() {
    const pass = passwordInputs()[0];
    if (!pass) {
      return false;
    }
    const user = usernameField();
    const auto = `${user?.autocomplete || ""} ${pass.autocomplete || ""}`.toLowerCase();
    if (auto.includes("current-password") || auto.includes("username") || auto.includes("webauthn")) {
      return true;
    }
    return (pass.value || "").length > 0 && pass.getAttribute("data-stem-filled") !== "1";
  }

  function pageInfo() {
    const user = clip((usernameField()?.value || "").trim(), MAX_USER);
    return {
      url: location.href,
      intent: intent(),
      kind: formKind(),
      hasPassword: passwordInputs().length > 0,
      canSave: passwordInputs().some((input) => (input.value || "").length > 0),
      totpFieldCount: totpInputs().length,
      browserManager: invitesBrowserManager(),
      username: user,
      host: location.hostname
    };
  }

  function filledByStem(username, password) {
    if (!lastStemFill || !password) {
      return false;
    }
    return lastStemFill.password === password
      && (!username || !lastStemFill.username || lastStemFill.username === username)
      && Date.now() - lastStemFill.at < 120000;
  }

  function captureCredentials() {
    const secret = capturePassword();
    const username = clip((usernameField()?.value || "").trim(), MAX_USER);
    if (secret.error && !username) {
      return { ok: false, error: secret.error };
    }
    if (secret.error) {
      return { ok: true, username, password: "", filledByStem: false };
    }
    return {
      ok: true,
      url: location.href,
      username,
      password: secret.password,
      title: location.hostname,
      filledByStem: filledByStem(username, secret.password)
    };
  }

  function maybeOfferSave() {
    const captured = captureCredentials();
    if (!captured.ok) {
      return;
    }
    if (!captured.password) {
      if (captured.username) {
        chrome.runtime.sendMessage({ type: "remember-username", username: captured.username, url: location.href }).catch(() => {});
      }
      return;
    }
    const key = `${captured.username}\0${captured.password}`;
    if (key === lastCaptureKey && Date.now() - lastCaptureAt < 1500) {
      return;
    }
    lastCaptureKey = key;
    lastCaptureAt = Date.now();
    chrome.runtime.sendMessage({
      type: "pending-save",
      url: captured.url,
      username: captured.username,
      password: captured.password,
      title: captured.title,
      filledByStem: !!captured.filledByStem
    }).then((result) => {
      captured.password = "";
      if (result?.offer) {
        showSaveBar(result.username || captured.username, result.host || location.hostname);
      }
    }).catch(() => {
      captured.password = "";
    });
  }

  function looksLikeSubmit(element) {
    if (!element || element.nodeType !== 1) {
      return false;
    }
    const target = element.closest("button, input[type='submit'], input[type='image'], [type='submit']");
    if (!target) {
      return false;
    }
    const type = (target.getAttribute("type") || (target.tagName === "BUTTON" ? "submit" : "")).toLowerCase();
    if (type === "reset") {
      return false;
    }
    const text = `${target.textContent || ""} ${target.value || ""} ${target.getAttribute("name") || ""} ${target.getAttribute("aria-label") || ""}`.toLowerCase();
    if (/show password|hide password|mostrar contraseña|ocultar|toggle password/.test(text)) {
      return false;
    }
    if (type === "submit" || type === "image" || type === "") {
      return true;
    }
    return /sign|log in|log-in|login|entrar|iniciar|continue|next|siguiente|submit|crear|register|join|ingresar/.test(text);
  }

  function showSaveBar(username, host) {
    if (!frameIsUsable()) {
      return;
    }
    const spanish = (navigator.language || "").toLowerCase().startsWith("es");
    let hostEl = document.getElementById(SAVE_HOST_ID);
    if (!hostEl) {
      hostEl = document.createElement("div");
      hostEl.id = SAVE_HOST_ID;
      hostEl.style.all = "initial";
      hostEl.style.position = "fixed";
      hostEl.style.top = "0";
      hostEl.style.left = "0";
      hostEl.style.right = "0";
      hostEl.style.zIndex = "2147483647";
      document.documentElement.appendChild(hostEl);
    }
    const shadow = hostEl.shadowRoot || hostEl.attachShadow({ mode: "open" });
    shadow.replaceChildren();
    const wrap = document.createElement("div");
    wrap.setAttribute("part", "stem-save");
    Object.assign(wrap.style, {
      display: "flex",
      gap: "12px",
      alignItems: "center",
      justifyContent: "space-between",
      padding: "10px 14px",
      background: "#101820",
      color: "#e8eef7",
      font: "13px/1.35 Segoe UI, sans-serif",
      boxShadow: "0 8px 24px rgba(0,0,0,.28)"
    });
    const text = document.createElement("div");
    const title = document.createElement("div");
    title.style.fontWeight = "600";
    title.textContent = spanish ? "¿Guardar este inicio en Stem?" : "Save this login in Stem?";
    const detail = document.createElement("div");
    detail.style.color = "#9aa8bc";
    detail.style.fontSize = "12px";
    const userBit = username ? `${username} · ` : "";
    detail.textContent = spanish
      ? `${userBit}${host || ""} — Stem no muestra la clave.`
      : `${userBit}${host || ""} — Stem will not show the password.`;
    text.append(title, detail);
    const actions = document.createElement("div");
    Object.assign(actions.style, { display: "flex", gap: "8px", flexShrink: "0" });
    const save = document.createElement("button");
    save.type = "button";
    save.textContent = spanish ? "Guardar" : "Save";
    Object.assign(save.style, {
      border: "0",
      borderRadius: "8px",
      padding: "8px 12px",
      background: "#0a58ca",
      color: "#fff",
      cursor: "pointer",
      font: "13px Segoe UI, sans-serif"
    });
    const later = document.createElement("button");
    later.type = "button";
    later.textContent = spanish ? "Ahora no" : "Not now";
    Object.assign(later.style, {
      border: "0",
      borderRadius: "8px",
      padding: "8px 12px",
      background: "#243044",
      color: "#e8eef7",
      cursor: "pointer",
      font: "13px Segoe UI, sans-serif"
    });
    save.addEventListener("click", async (event) => {
      event.preventDefault();
      event.stopPropagation();
      save.disabled = true;
      title.textContent = spanish ? "Guardando en Stem…" : "Saving in Stem…";
      const result = await chrome.runtime.sendMessage({ type: "save-pending" });
      if (result?.ok) {
        hideSaveBar();
        return;
      }
      save.disabled = false;
      title.textContent = result?.needsHello || result?.error === "Confirm Windows Hello in Stem." || result?.error === "Finish the number pad in Stem."
        ? (spanish ? "Confirma Windows Hello en Stem, luego pulsa Guardar." : "Confirm Windows Hello in Stem, then tap Save.")
        : (result?.error || result?.warning || (spanish ? "No se pudo guardar." : "Could not save."));
    });
    later.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      chrome.runtime.sendMessage({ type: "dismiss-save" }).catch(() => {});
      hideSaveBar();
    });
    actions.append(save, later);
    wrap.append(text, actions);
    shadow.append(wrap);
  }

  function hideSaveBar() {
    document.getElementById(SAVE_HOST_ID)?.remove();
  }

  function onMessage(message, _sender, sendResponse) {
    if (message?.type === "ping") {
      sendResponse({ ok: true });
      return true;
    }
    if (message?.type === "fill") {
      const user = usernameField();
      setValue(user, message.username, true);
      fillPasswords(message.password, message.intent || intent());
      lastStemFill = {
        username: String(message.username || ""),
        password: String(message.password || ""),
        at: Date.now()
      };
      if (message.totp) {
        totpInputs().forEach((input) => setValue(input, message.totp, true));
      }
      sendResponse({ ok: true, hasPassword: passwordInputs().length > 0 });
      return true;
    }
    if (message?.type === "fill-alias") {
      setValue(emailField(), message.alias);
      sendResponse({ ok: true });
      return true;
    }
    if (message?.type === "clear") {
      clearFilled(false);
      sendResponse({ ok: true });
      return true;
    }
    if (message?.type === "page-info") {
      sendResponse(pageInfo());
      return true;
    }
    if (message?.type === "capture") {
      const captured = captureCredentials();
      if (!captured.password) {
        sendResponse({ ok: false, error: captured.error || "Type the password on the page first." });
        return true;
      }
      sendResponse(captured);
      return true;
    }
    if (message?.type === "copy-totp") {
      const code = String(message.totp || "");
      if (message.totp) {
        message.totp = "";
      }
      copyTotpCode(code).then((ok) => sendResponse({ ok }));
      return true;
    }
    if (message?.type === "clear-totp-clipboard") {
      clearTotpClipboard().then((ok) => sendResponse({ ok }));
      return true;
    }
    if (message?.type === "chip-state") {
      applyChipState(message);
      sendResponse({ ok: true });
      return true;
    }
    if (message?.type === "show-save-bar") {
      showSaveBar(String(message.username || ""), String(message.host || location.hostname));
      sendResponse({ ok: true });
      return true;
    }
    if (message?.type === "hide-save-bar") {
      hideSaveBar();
      sendResponse({ ok: true });
      return true;
    }
    return false;
  }

  chrome.runtime.onMessage.addListener(onMessage);

  document.addEventListener("submit", () => {
    maybeOfferSave();
  }, true);

  document.addEventListener("click", (event) => {
    if (looksLikeSubmit(event.target)) {
      maybeOfferSave();
    }
  }, true);

  window.addEventListener("pagehide", () => {
    maybeOfferSave();
  });

  let chipState = { unlocked: false, canFill: false, hiddenOther: false };

  function chipLabel() {
    const spanish = (navigator.language || "").toLowerCase().startsWith("es");
    if (formKind() === "signup") {
      return spanish ? "Crear con Stem" : "Create with Stem";
    }
    if (chipState.hiddenOther && !chipState.canFill) {
      return spanish ? "Abrir Stem para quitar atado" : "Open Stem to unbind";
    }
    return spanish ? "Entrar con Stem" : "Sign in with Stem";
  }

  function applyChipState(state) {
    if (state && typeof state === "object") {
      chipState = {
        unlocked: !!state.unlocked,
        canFill: !!state.canFill,
        hiddenOther: !!state.hiddenOther
      };
    }
    const first = passwordInputs()[0];
    if (first && !document.getElementById("stem-pass-chip") && frameIsUsable()) {
      mountChip();
    }
    const chip = document.getElementById("stem-pass-chip");
    if (!chip) {
      return;
    }
    chip.textContent = chipLabel();
    placeChip();
  }

  function placeChip() {
    const chip = document.getElementById("stem-pass-chip");
    const first = passwordInputs()[0];
    if (!chip || !first) {
      return;
    }
    const rect = first.getBoundingClientRect();
    chip.style.top = `${window.scrollY + rect.top - 34}px`;
    chip.style.left = `${window.scrollX + Math.max(8, rect.right - chip.offsetWidth)}px`;
  }

  function mountChip() {
    const first = passwordInputs()[0];
    if (!first || document.getElementById("stem-pass-chip") || !frameIsUsable()) {
      return;
    }

    const chip = document.createElement("button");
    chip.id = "stem-pass-chip";
    chip.type = "button";
    chip.textContent = chipLabel();
    Object.assign(chip.style, {
      position: "absolute",
      zIndex: "2147483646",
      border: "0",
      borderRadius: "999px",
      padding: "6px 10px",
      font: "12px/1.2 Segoe UI, sans-serif",
      color: "#f3f8ff",
      background: "#0a58ca",
      cursor: "pointer"
    });
    chip.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      chrome.runtime.sendMessage({
        type: formKind() === "signup" ? "assist" : "fill-page",
        url: location.href,
        intent: intent()
      });
    });
    document.body.appendChild(chip);
    placeChip();
    window.addEventListener("scroll", placeChip, { passive: true });
    window.addEventListener("resize", placeChip);
    chrome.runtime.sendMessage({ type: "chip-query" }).then(applyChipState).catch(() => {});
  }

  function askPendingBar() {
    chrome.runtime.sendMessage({ type: "pending-save-status" }).then((pending) => {
      if (pending?.offer && pending.host) {
        showSaveBar(pending.username || "", pending.host);
      }
    }).catch(() => {});
  }

  mountChip();
  askPendingBar();
  new MutationObserver(() => mountChip()).observe(document.documentElement, { childList: true, subtree: true });
})();
