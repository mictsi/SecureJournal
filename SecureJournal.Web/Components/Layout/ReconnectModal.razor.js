// Set up event handlers only if reconnect UI is present.
const reconnectModal = document.getElementById("components-reconnect-modal");
const retryButton = document.getElementById("components-reconnect-button");
const resumeButton = document.getElementById("components-resume-button");
const reconnectLogPrefix = "[SecureJournal.Reconnect]";
const reconnectDiagnosticsEnabled = window.secureJournalReconnectDiagnostics !== false;
const reconnectStateClasses = [
    "components-reconnect-show",
    "components-reconnect-retrying",
    "components-reconnect-failed",
    "components-reconnect-paused",
    "components-reconnect-resume-failed"
];

function logReconnect(level, message, details) {
    if (!reconnectDiagnosticsEnabled || !window.console) {
        return;
    }

    const payload = details !== undefined
        ? [reconnectLogPrefix, message, details]
        : [reconnectLogPrefix, message];

    if (level === "error") {
        console.error(...payload);
        return;
    }

    if (level === "warn") {
        console.warn(...payload);
        return;
    }

    console.info(...payload);
}

if (reconnectModal && retryButton && resumeButton) {
    reconnectModal.addEventListener("components-reconnect-state-changed", handleReconnectStateChanged);
    retryButton.addEventListener("click", retry);
    resumeButton.addEventListener("click", resume);
    logReconnect("info", "Reconnect modal diagnostics initialized.");
} else {
    logReconnect(
        "warn",
        "Reconnect modal diagnostics unavailable because expected DOM elements were not found.",
        {
            hasModal: Boolean(reconnectModal),
            hasRetryButton: Boolean(retryButton),
            hasResumeButton: Boolean(resumeButton)
        });
}

function handleReconnectStateChanged(event) {
    const state = event?.detail?.state ?? "";
    logReconnect("info", `Reconnect state changed to '${state || "(empty)"}'.`, event?.detail);
    applyReconnectState(state);

    if (state === "show") {
        reconnectModal.showModal();
    } else if (state === "hide") {
        reconnectModal.close();
    } else if (state === "failed") {
        document.addEventListener("visibilitychange", retryWhenDocumentBecomesVisible);
    } else if (state === "rejected") {
        location.reload();
    }
}

function applyReconnectState(state) {
    if (!reconnectModal) {
        return;
    }

    reconnectStateClasses.forEach(cssClass => reconnectModal.classList.remove(cssClass));

    let stateClass = "";
    if (state === "show" || state === "retrying" || state === "failed" || state === "paused") {
        stateClass = `components-reconnect-${state}`;
    } else if (state === "resumefailed" || state === "resume-failed") {
        stateClass = "components-reconnect-resume-failed";
    }

    if (stateClass) {
        reconnectModal.classList.add(stateClass);
    }
}

async function retry() {
    if (!reconnectModal) {
        return;
    }

    logReconnect("info", "Retry requested.");
    document.removeEventListener("visibilitychange", retryWhenDocumentBecomesVisible);
    applyReconnectState("retrying");

    try {
        if (!window.Blazor || typeof Blazor.reconnect !== "function") {
            logReconnect("warn", "Blazor.reconnect is unavailable; reloading page.");
            location.reload();
            return;
        }

        // Reconnect will asynchronously return:
        // - true to mean success
        // - false to mean we reached the server, but it rejected the connection (e.g., unknown circuit ID)
        // - exception to mean we didn't reach the server (this can be sync or async)
        const successful = await Blazor.reconnect();
        if (!successful) {
            logReconnect("warn", "Reconnect reached server but was rejected; attempting circuit resume.");
            // We have been able to reach the server, but the circuit is no longer available.
            // We'll reload the page so the user can continue using the app as quickly as possible.
            const resumeSuccessful = await Blazor.resumeCircuit();
            if (!resumeSuccessful) {
                logReconnect("warn", "Resume failed after reconnect rejection; reloading page.");
                location.reload();
            } else {
                logReconnect("info", "Resume succeeded after reconnect rejection.");
                applyReconnectState("hide");
                reconnectModal.close();
            }
        } else {
            logReconnect("info", "Reconnect succeeded.");
        }
    } catch (err) {
        logReconnect("error", "Reconnect attempt failed with exception.", err);
        // We got an exception, server is currently unavailable
        applyReconnectState("failed");
        document.addEventListener("visibilitychange", retryWhenDocumentBecomesVisible);
    }
}

async function resume() {
    if (!reconnectModal) {
        return;
    }

    logReconnect("info", "Resume requested.");
    try {
        if (!window.Blazor || typeof Blazor.resumeCircuit !== "function") {
            logReconnect("warn", "Blazor.resumeCircuit is unavailable; reloading page.");
            location.reload();
            return;
        }

        const successful = await Blazor.resumeCircuit();
        if (!successful) {
            logReconnect("warn", "Resume returned false; reloading page.");
            location.reload();
        } else {
            logReconnect("info", "Resume succeeded.");
        }
    } catch (err) {
        logReconnect("error", "Resume attempt failed with exception.", err);
        applyReconnectState("resume-failed");
    }
}

async function retryWhenDocumentBecomesVisible() {
    if (document.visibilityState === "visible") {
        await retry();
    }
}
