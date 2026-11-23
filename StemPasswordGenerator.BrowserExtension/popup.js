const spanish = (navigator.language || "").toLowerCase().startsWith("es");
const status = document.getElementById("status");
const badge = document.getElementById("badge");
const matchesBox = document.getElementById("matches");
const confirmBox = document.getElementById("confirm-save");
const confirmText = document.getElementById("confirm-text");

const copy = {
  login: spanish ? "Entrar en este sitio" : "Sign in on this site",
  signup: spanish ? "Crear una cuenta en este sitio" : "Create an account on this site",
  alias: spanish ? "Usar un alias de Stem" : "Use a Stem email alias",
  allow: spanish ? "Permitir Stem en este sitio" : "Allow Stem on this site",
  save: spanish ? "Guardar este inicio" : "Save this login",
  saveHint: spanish
    ? "Si inicias sesión en una página, Stem te pregunta si quieres guardar. También puedes guardar desde aquí."
    : "After you sign in, Stem asks to save. You can also save from here.",
  saveYes: spanish ? "Guardar en la bóveda" : "Save in vault",
  saveNo: spanish ? "Cancelar" : "Cancel",
  checking: spanish ? "Comprobando esta página…" : "Checking this page…",
  opening: spanish ? "Abriendo Stem…" : "Opening Stem…",
  signupWait: spanish ? "Crea la cuenta en el navegador y luego guarda el inicio en Stem." : "Create the account in the browser, then save the login in Stem.",
  locked: spanish ? "Bóveda bloqueada" : "Vault locked",
  helloReady: spanish ? "Usa Windows Hello" : "Use Windows Hello",
  helloFill: spanish
    ? "Confirma Windows Hello en Stem. Si pide el teclado numérico, termínalo ahí. Luego Stem rellena."
    : "Confirm Windows Hello in Stem. If it asks for the number pad, finish it there. Then Stem fills.",
  helloEnable: spanish
    ? "Activa Windows Hello en Stem (Proteger) para rellenar o guardar desde el ayudante."
    : "Enable Windows Hello in Stem Protect to fill or save from the helper.",
  open: spanish ? "Bóveda desbloqueada" : "Vault unlocked",
  choose: spanish ? "Elige qué inicio rellenar. Stem no muestra la clave aquí." : "Choose which login to fill. Stem does not show the password here.",
  none: spanish ? "No hay un inicio guardado para este sitio." : "No saved login for this site.",
  totp: spanish ? "2FA" : "2FA",
  totpCopied: spanish
    ? "Código 2FA copiado. Stem lo borra del portapapeles en 30 s. No se muestra aquí."
    : "2FA code copied. Stem clears it from the clipboard in 30s. It is not shown here.",
  confirmSave: (user, host) => spanish
    ? `¿Guardar ${user || "este inicio"} en ${host}? Stem no mostrará la clave.`
    : `Save ${user || "this login"} on ${host}? Stem will not show the password.`,
  saved: (user, host) => spanish ? `Guardado: ${user || "inicio"} en ${host}` : `Saved: ${user || "login"} on ${host}`,
  reuse: (hint) => spanish
    ? `Esta clave también está en: ${hint}`
    : `This password is also on: ${hint}`,
  aliasOk: (value) => spanish ? `Alias listo: ${value}` : `Alias ready: ${value}`,
  allowOk: spanish ? "Stem podrá mostrar el chip en este sitio la próxima vez." : "Stem can show the chip on this site next time.",
  noTab: spanish ? "Abre un sitio web primero." : "Open a website first.",
  browserManager: spanish
    ? "El administrador de contraseñas del navegador también puede rellenar este formulario. Si pisa a Stem, desactívalo para este sitio."
    : "The browser password manager can also fill this form. If it overwrites Stem, turn it off for this site.",
  container: spanish
    ? "Este inicio no está atado a este perfil o contenedor."
    : "This login is not bound to this browser profile or Firefox container.",
  saveContainer: spanish
    ? "Se guardará atado a este perfil o contenedor de Firefox."
    : "It will be bound to this browser profile or Firefox container.",
  hidden: spanish
    ? "Hay un inicio de este sitio en otro perfil o contenedor de Firefox. Ábrelo en Stem para quitar el atado. Stem no muestra la clave."
    : "A login for this site is saved in another browser profile or Firefox container. Open it in Stem to remove the binding. Stem does not show the password.",
  openBound: spanish
    ? "Abrir en Stem para quitar el atado"
    : "Open in Stem to unbind",
  opened: spanish
    ? "Abierto en Stem. Quita el atado a perfil o contenedor ahí si este no es el correcto. Stem no rellenó la página."
    : "Opened in Stem. Remove the profile or container binding there if this is the wrong one. Stem did not fill the page.",
  disconnectedBadge: spanish ? "Stem desconectado" : "Stem disconnected",
  disconnected: spanish
    ? "No se puede conectar con Stem Desktop."
    : "Cannot connect to Stem Desktop.",
  vaultUnknown: spanish ? "Estado de la bóveda desconocido" : "Vault state unknown"
};

document.getElementById("login").textContent = copy.login;
document.getElementById("signup").textContent = copy.signup;
document.getElementById("alias").textContent = copy.alias;
document.getElementById("allow").textContent = copy.allow;
document.getElementById("save").textContent = copy.save;
document.getElementById("save-hint").textContent = copy.saveHint;
document.getElementById("confirm-save-yes").textContent = copy.saveYes;
document.getElementById("confirm-save-no").textContent = copy.saveNo;

function clip(value, max) {
  return String(value || "").slice(0, max);
}

function matchLabel(match) {
  const title = clip(match.title || "Login", 80);
  const user = clip(match.username || "", 80);
  const totp = match.hasTotp ? ` · ${copy.totp}` : "";
  return user ? `${title}${totp}\n${user}` : `${title}${totp}`;
}

function fillableMatches(result) {
  return (Array.isArray(result?.matches) ? result.matches : []).filter((match) => match?.id && !match.boundOtherContainer);
}

function hiddenMatches(result) {
  return (Array.isArray(result?.matches) ? result.matches : []).filter((match) => match?.id && match.boundOtherContainer);
}

function renderMatches(result) {
  matchesBox.replaceChildren();
  const matches = Array.isArray(result?.matches) ? result.matches.slice(0, 20) : [];
  if (!matches.length) {
    return;
  }
  matches.forEach((match) => {
    if (!match?.id) {
      return;
    }
    const button = document.createElement("button");
    button.type = "button";
    if (match.boundOtherContainer) {
      button.className = "pick secondary";
      button.textContent = matchLabel(match) + "\n" + copy.openBound;
      button.addEventListener("click", () => openBound(match.id));
    } else {
      button.className = "pick";
      button.textContent = matchLabel(match);
      button.addEventListener("click", () => fillId(match.id));
    }
    matchesBox.appendChild(button);
  });
}

async function current() {
  const [tab] = await chrome.tabs.query({ currentWindow: true, active: true });
  return tab;
}

function notes(result) {
  const lines = [];
  const hidden = hiddenMatches(result).length > 0;
  if (result?.ok && result.warning && !hidden) {
    lines.push(result.warning);
  }
  if (hidden) {
    lines.push(copy.hidden);
  }
  if (result?.matches?.some((match) => match.containerWarning) && !result?.warning) {
    lines.push(copy.container);
  }
  if (result?.browserManager) {
    lines.push(copy.browserManager);
  }
  return lines.length ? "\n" + lines.join("\n") : "";
}

function showResult(result) {
  if (result?.needsHello || result?.error === "Confirm Windows Hello in Stem." || result?.error === "Finish the number pad in Stem.") {
    status.textContent = copy.helloFill;
    return;
  }
  if (result?.error === "Enable Windows Hello in Stem Protect, then try again.") {
    status.textContent = copy.helloEnable;
    return;
  }
  if (result?.ok && result?.launched && !result?.filledTitle) {
    status.textContent = copy.opened;
    return;
  }
  if (result?.needsChoice) {
    status.textContent = copy.choose + notes(result);
    renderMatches(result);
    return;
  }
  if (result?.warning && !result.ok) {
    status.textContent = result.warning;
    return;
  }
  if (result?.error) {
    status.textContent = result.error;
    return;
  }
  const fillable = fillableMatches(result);
  const hidden = hiddenMatches(result);
  if (!fillable.length && hidden.length) {
    renderMatches(result);
    status.textContent = copy.hidden;
    return;
  }
  const match = fillable[0];
  if (match || result?.filledTitle) {
    const title = clip(result.filledTitle || match?.title, 80);
    const reuse = match?.reusedCount > 1 && match.reusedHint
      ? "\n" + copy.reuse(clip(match.reusedHint, 120))
      : "";
    const totp = result.totpCopied ? "\n" + copy.totpCopied : "";
    status.textContent = (spanish ? `Listo: ${title}` : `Ready: ${title}`) + reuse + totp + notes(result);
    return;
  }
  if (result?.alias) {
    status.textContent = copy.aliasOk(result.alias);
    return;
  }
  if (result?.warning) {
    status.textContent = result.warning;
    return;
  }
  status.textContent = copy.signupWait;
}

async function fillId(id) {
  const tab = await current();
  status.textContent = copy.opening;
  const result = await chrome.runtime.sendMessage({ type: "fill-id", url: tab?.url, intent: "login", id });
  showResult(result);
}

async function openBound(id) {
  const tab = await current();
  status.textContent = copy.opening;
  const result = await chrome.runtime.sendMessage({ type: "open-item", url: tab?.url, id });
  status.textContent = result?.ok ? copy.opened : (result?.error || result?.warning || copy.noTab);
}

document.getElementById("login").addEventListener("click", async () => {
  const tab = await current();
  status.textContent = copy.opening;
  const result = await chrome.runtime.sendMessage({ type: "fill-page", url: tab?.url, intent: "login" });
  showResult(result);
});

document.getElementById("signup").addEventListener("click", async () => {
  const tab = await current();
  status.textContent = copy.opening;
  const result = await chrome.runtime.sendMessage({ type: "assist", url: tab?.url, intent: "signup" });
  showResult(result);
});

document.getElementById("alias").addEventListener("click", async () => {
  const tab = await current();
  status.textContent = copy.opening;
  const result = await chrome.runtime.sendMessage({ type: "alias", url: tab?.url });
  showResult(result);
});

document.getElementById("allow").addEventListener("click", async () => {
  const result = await chrome.runtime.sendMessage({ type: "allow-site" });
  status.textContent = result?.ok ? copy.allowOk : (result?.error || copy.noTab);
});

document.getElementById("save").addEventListener("click", async () => {
  const preview = await chrome.runtime.sendMessage({ type: "save-preview" });
  if (!preview?.ok) {
    status.textContent = preview?.error || copy.noTab;
    confirmBox.classList.remove("show");
    return;
  }
  confirmText.textContent = copy.confirmSave(clip(preview.username, 80), clip(preview.host, 80))
    + (preview.inContainer ? "\n" + copy.saveContainer : "")
    + (preview.browserManager ? "\n" + copy.browserManager : "");
  confirmBox.classList.add("show");
  status.textContent = "";
});

document.getElementById("confirm-save-yes").addEventListener("click", async () => {
  const result = await chrome.runtime.sendMessage({ type: "save-pending" });
  confirmBox.classList.remove("show");
  if (result?.ok) {
    status.textContent = copy.saved(clip(result.username, 80), clip(result.host, 80));
    return;
  }
  status.textContent = result?.warning || result?.error || copy.noTab;
});

document.getElementById("confirm-save-no").addEventListener("click", () => {
  confirmBox.classList.remove("show");
  chrome.runtime.sendMessage({ type: "dismiss-save" }).catch(() => {});
});

let listing = false;

function isDisconnected(vault) {
  return !vault?.ok || vault?.connected === false || vault?.vaultState === "unknown";
}

async function refreshList() {
  if (listing || confirmBox.classList.contains("show")) {
    return;
  }
  listing = true;
  try {
    console.log("[STEM][POPUP] requesting state");
    const tab = await current();
    status.textContent = tab?.url || copy.noTab;
    const vault = await chrome.runtime.sendMessage({ type: "status" });
    const unlocked = !!vault?.ok && !!vault?.unlocked;
    if (isDisconnected(vault)) {
      badge.textContent = copy.disconnectedBadge;
      badge.className = "disconnected";
      status.textContent = (vault?.error || copy.disconnected) + "\n" + copy.vaultUnknown;
      matchesBox.replaceChildren();
      return;
    }
    if (unlocked) {
      badge.textContent = copy.open;
      badge.className = "open";
    } else {
      badge.textContent = vault?.helloEnabled ? copy.helloReady : copy.locked;
      badge.className = "locked";
    }
    const pending = await chrome.runtime.sendMessage({ type: "pending-save-status" });
    if (pending?.offer) {
      confirmText.textContent = copy.confirmSave(clip(pending.username, 80), clip(pending.host, 80));
      confirmBox.classList.add("show");
    }
    if (!unlocked || !tab?.url) {
      status.textContent = !unlocked
        ? (vault?.helloEnabled ? copy.helloFill : copy.helloEnable)
        : (tab?.url || copy.noTab);
      matchesBox.replaceChildren();
      return;
    }
    const listed = await chrome.runtime.sendMessage({ type: "list-logins", url: tab.url });
    if (listed?.warning || listed?.error) {
      if (!listed.ok && !listed.matches?.length) {
        status.textContent = listed.warning || listed.error;
        matchesBox.replaceChildren();
        return;
      }
    }
    renderMatches(listed);
    const fillable = fillableMatches(listed);
    const hidden = hiddenMatches(listed);
    if (listed?.warning && !listed?.matches?.length) {
      status.textContent = listed.warning;
    } else if (fillable.length > 1) {
      status.textContent = copy.choose + notes(listed);
    } else if (!fillable.length && hidden.length) {
      status.textContent = copy.hidden;
    } else if (!listed?.matches?.length) {
      status.textContent = copy.none + notes(listed);
    } else {
      status.textContent = (tab?.url || copy.noTab) + notes(listed);
    }
  } finally {
    listing = false;
  }
}

chrome.runtime.onMessage.addListener((message) => {
  if (message?.type === "vault-changed") {
    refreshList();
  }
});

console.log("[STEM][POPUP] opened");
refreshList();
