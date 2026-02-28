window.secureJournalTheme = (() => {
    const storageKey = "securejournal.theme";

    function applyTheme(theme) {
        const next = theme === "dark" ? "dark" : "light";
        document.documentElement.setAttribute("data-theme", next);
        document.body.setAttribute("data-theme", next);
        try {
            localStorage.setItem(storageKey, next);
        } catch {
            // ignore storage failures in restricted environments
        }
        return next;
    }

    function getPreferredTheme() {
        try {
            const saved = localStorage.getItem(storageKey);
            if (saved === "dark" || saved === "light") {
                return saved;
            }
        } catch {
            // ignore storage failures
        }

        return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
            ? "dark"
            : "light";
    }

    return {
        init: () => applyTheme(getPreferredTheme()),
        toggle: () => {
            const current = document.documentElement.getAttribute("data-theme") || getPreferredTheme();
            return applyTheme(current === "dark" ? "light" : "dark");
        }
    };
})();

window.secureJournalDownloads = {
    downloadText(fileName, contentType, content) {
        const blob = new Blob([content ?? ""], { type: contentType || "text/plain;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = fileName || "export.txt";
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
};

window.secureJournalSession = {
    set(name, value, maxAgeSeconds) {
        if (!name) {
            return;
        }

        const encodedName = encodeURIComponent(name);
        const encodedValue = encodeURIComponent(value ?? "");
        const attrs = [
            `${encodedName}=${encodedValue}`,
            "path=/",
            "samesite=lax"
        ];

        if (Number.isFinite(maxAgeSeconds) && maxAgeSeconds > 0) {
            const boundedMaxAge = Math.min(900, Math.floor(maxAgeSeconds));
            attrs.push(`max-age=${boundedMaxAge}`);
        }

        if (window.location && window.location.protocol === "https:") {
            attrs.push("secure");
        }

        document.cookie = attrs.join("; ");
    },
    get(name) {
        if (!name) {
            return null;
        }

        const encodedName = `${encodeURIComponent(name)}=`;
        const cookies = document.cookie ? document.cookie.split("; ") : [];
        for (const cookie of cookies) {
            if (cookie.startsWith(encodedName)) {
                return decodeURIComponent(cookie.substring(encodedName.length));
            }
        }

        return null;
    },
    clear(name) {
        if (!name) {
            return;
        }

        const encodedName = encodeURIComponent(name);
        const attrs = [
            `${encodedName}=`,
            "path=/",
            "expires=Thu, 01 Jan 1970 00:00:00 GMT",
            "max-age=0",
            "samesite=lax"
        ];

        if (window.location && window.location.protocol === "https:") {
            attrs.push("secure");
        }

        document.cookie = attrs.join("; ");
    }
};

(() => {
    const initTheme = () => {
        try {
            window.secureJournalTheme?.init?.();
        } catch {
            // ignore initialization failures; Blazor toggle button can retry later
        }
    };

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initTheme, { once: true });
    } else {
        initTheme();
    }
})();
