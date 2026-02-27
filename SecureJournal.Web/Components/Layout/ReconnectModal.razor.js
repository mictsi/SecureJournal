// Set up event handlers only if reconnect UI is present.
const reconnectModal = document.getElementById("components-reconnect-modal");
const retryButton = document.getElementById("components-reconnect-button");
const resumeButton = document.getElementById("components-resume-button");
const reconnectStateClasses = [
    "components-reconnect-show",
    "components-reconnect-retrying",
    "components-reconnect-failed",
    "components-reconnect-paused",
    "components-reconnect-resume-failed"
];

if (reconnectModal && retryButton && resumeButton) {
    reconnectModal.addEventListener("components-reconnect-state-changed", handleReconnectStateChanged);
    retryButton.addEventListener("click", retry);
    resumeButton.addEventListener("click", resume);
}

function handleReconnectStateChanged(event) {
    const state = event?.detail?.state ?? "";
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

    document.removeEventListener("visibilitychange", retryWhenDocumentBecomesVisible);
    applyReconnectState("retrying");

    try {
        if (!window.Blazor || typeof Blazor.reconnect !== "function") {
            location.reload();
            return;
        }

        // Reconnect will asynchronously return:
        // - true to mean success
        // - false to mean we reached the server, but it rejected the connection (e.g., unknown circuit ID)
        // - exception to mean we didn't reach the server (this can be sync or async)
        const successful = await Blazor.reconnect();
        if (!successful) {
            // We have been able to reach the server, but the circuit is no longer available.
            // We'll reload the page so the user can continue using the app as quickly as possible.
            const resumeSuccessful = await Blazor.resumeCircuit();
            if (!resumeSuccessful) {
                location.reload();
            } else {
                applyReconnectState("hide");
                reconnectModal.close();
            }
        }
    } catch (err) {
        // We got an exception, server is currently unavailable
        applyReconnectState("failed");
        document.addEventListener("visibilitychange", retryWhenDocumentBecomesVisible);
    }
}

async function resume() {
    if (!reconnectModal) {
        return;
    }

    try {
        if (!window.Blazor || typeof Blazor.resumeCircuit !== "function") {
            location.reload();
            return;
        }

        const successful = await Blazor.resumeCircuit();
        if (!successful) {
            location.reload();
        }
    } catch {
        applyReconnectState("resume-failed");
    }
}

async function retryWhenDocumentBecomesVisible() {
    if (document.visibilityState === "visible") {
        await retry();
    }
}
