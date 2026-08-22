window.secureJournalTheme = (() => {
    // Sekura owns the theme: its manager reads and writes the same sk-theme /
    // sk-contrast keys the pre-paint script in App.razor uses, and sets
    // data-sk-theme on <html>. This wrapper exists so Blazor can drive it.
    function manager() {
        return window.Sekura ? window.Sekura.getTheme() : null;
    }

    function resolved() {
        return document.documentElement.getAttribute("data-sk-theme") || "light";
    }

    return {
        init: () => resolved(),
        resolved,
        get: () => manager()?.get() ?? "system",
        set: (preference) => {
            manager()?.set(preference);
            return resolved();
        },
        // Kept for callers that only want the next value in the cycle.
        toggle: () => {
            const order = ["system", "light", "dark"];
            const next = order[(order.indexOf(manager()?.get() ?? "system") + 1) % order.length];
            manager()?.set(next);
            return resolved();
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

window.secureJournalEditors = (() => {
    // The editor renders in an iframe, so it cannot inherit the page's custom
    // properties. Resolve the tokens it needs against the live document instead,
    // and rebuild the editors whenever the theme changes.
    function token(name, fallback) {
        const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
        return value || fallback;
    }

    function isDark() {
        return (document.documentElement.getAttribute("data-sk-theme") || "light").includes("dark");
    }

    function editorDefaults() {
        const dark = isDark();
        return {
            base_url: "/lib/tinymce",
            suffix: ".min",
            license_key: "gpl",
            menubar: false,
            branding: false,
            promotion: false,
            statusbar: false,
            resize: false,
            plugins: "autoresize advlist code link lists table",
            toolbar: "blocks | bold italic underline strikethrough | bullist numlist blockquote | link table | code | removeformat",
            skin: dark ? "oxide-dark" : "oxide",
            content_css: dark ? "dark" : "default",
            valid_elements:
                "a[href|target|rel],blockquote,br,code,em,h2,h3,h4,li,ol,p,pre,s,strong,u,ul," +
                "table,caption,colgroup,col[span],thead,tbody,tfoot,tr," +
                "th[colspan|rowspan|scope|headers|abbr],td[colspan|rowspan|headers]",
            invalid_elements: "script,style,iframe,object,embed,svg,math,form,input,button,textarea,select",
            link_default_target: "_blank",
            link_assume_external_targets: true,
            default_link_target: "_blank",
            forced_root_block: "p",
            table_default_attributes: {},
            table_default_styles: {},
            table_sizing_mode: "auto",
            table_advtab: false,
            table_cell_advtab: false,
            table_row_advtab: false,
            table_appearance_options: false,
            table_grid: true,
            table_header_type: "sectionCells",
            table_use_colgroups: true,
            content_style: `
                body {
                    background: ${token("--sk-color-surface-base", "#ffffff")};
                    color: ${token("--sk-color-text-primary", "#181e27")};
                    font-family: ${token("--sk-font-family-sans", "'Segoe UI', sans-serif")};
                    font-size: 14px;
                    line-height: 1.65;
                    padding: ${token("--sk-space-16", "1rem")};
                }
                a { color: ${token("--sk-color-action-primary-text", "#2a5bd7")}; }
                blockquote {
                    border-inline-start: 3px solid ${token("--sk-color-border-default", "#dfe3ea")};
                    margin: 1rem 0;
                    padding-inline-start: 1rem;
                    color: ${token("--sk-color-text-secondary", "#515b6b")};
                }
                pre {
                    background: ${token("--sk-color-surface-sunken", "#f7f8fa")};
                    color: ${token("--sk-color-text-primary", "#181e27")};
                    font-family: ${token("--sk-font-family-mono", "ui-monospace, monospace")};
                    padding: 0.85rem 1rem;
                    border-radius: ${token("--sk-radius-md", "0.5rem")};
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin: 0.75rem 0;
                }
                caption {
                    caption-side: top;
                    padding-bottom: 0.5rem;
                    text-align: left;
                    color: ${token("--sk-color-text-secondary", "#515b6b")};
                }
                th, td {
                    padding: 0.5rem 0.75rem;
                    border: 1px solid ${token("--sk-color-border-default", "#dfe3ea")};
                    text-align: left;
                    vertical-align: top;
                }
                th {
                    background: ${token("--sk-color-surface-subtle", "#f7f8fa")};
                    font-weight: 600;
                }
                code {
                    background: ${token("--sk-color-surface-sunken", "#f7f8fa")};
                    color: ${token("--sk-color-text-primary", "#181e27")};
                    font-family: ${token("--sk-font-family-mono", "ui-monospace, monospace")};
                    padding: 0.1rem 0.3rem;
                    border-radius: ${token("--sk-radius-sm", "0.25rem")};
                }
            `
        };
    }

    // The editor draws its toolbar icons as bare <svg>. The buttons around them
    // already carry an accessible name, so the icons are decorative and must not
    // be announced. The toolbar is built after "init" and rebuilt as menus open,
    // so a one-shot pass misses most of it — watch the container instead.
    function hideDecorativeIcons(editor) {
        const root = editor?.getContainer();
        if (!root) {
            return;
        }

        const sweep = (target) => {
            for (const svg of target.querySelectorAll("svg:not([aria-hidden])")) {
                svg.setAttribute("aria-hidden", "true");
                svg.setAttribute("focusable", "false");
            }
        };

        sweep(root);
        // Menus and dialogs are appended to the document, not to the container.
        sweep(document.body);

        if (root.dataset.iconSweepAttached === "true") {
            return;
        }

        root.dataset.iconSweepAttached = "true";
        const observer = new MutationObserver(() => {
            sweep(root);
            sweep(document.body);
        });
        observer.observe(document.body, { childList: true, subtree: true });
        editor.on("remove", () => observer.disconnect());
    }

    function syncEditor(editor) {
        const target = editor?.targetElm;
        if (!target) {
            return;
        }

        target.value = editor.getContent({ format: "html" });
        target.dispatchEvent(new Event("change", { bubbles: true }));
    }

    function normalizeArray(value) {
        if (Array.isArray(value)) {
            return value;
        }

        if (value && typeof value === "object") {
            return Object.values(value);
        }

        if (value === null || value === undefined) {
            return [];
        }

        return [value];
    }

    function getEditorInstances(ids) {
        const normalizedIds = normalizeArray(ids).filter((id) => typeof id === "string" && id.length > 0);
        if (normalizedIds.length > 0) {
            return normalizedIds.map((id) => window.tinymce.get(id)).filter(Boolean);
        }

        return normalizeArray(window.tinymce?.editors).filter(Boolean);
    }

    function attachFormSync(target) {
        const form = target?.closest("form");
        if (!form || form.dataset.richTextSyncAttached === "true") {
            return;
        }

        form.dataset.richTextSyncAttached = "true";
        form.addEventListener("submit", () => {
            if (!window.tinymce?.editors) {
                return;
            }

            for (const editor of window.tinymce.editors) {
                syncEditor(editor);
            }
        }, true);
    }

    function dispose(ids) {
        if (!window.tinymce) {
            return;
        }

        for (const editor of getEditorInstances(ids)) {
            editor.remove();
        }
    }

    function flush(ids) {
        if (!window.tinymce) {
            return;
        }

        for (const editor of getEditorInstances(ids)) {
            syncEditor(editor);
        }
    }

    async function syncTinyMce(editors, knownIds) {
        const requestedEditors = normalizeArray(editors);
        if (requestedEditors.length === 0 || !window.tinymce) {
            return;
        }

        const expectedIds = normalizeArray(knownIds).length > 0
            ? normalizeArray(knownIds)
            : requestedEditors.map((config) => config?.id).filter(Boolean);

        for (const id of expectedIds) {
            const target = document.getElementById(id);
            const existing = window.tinymce.get(id);
            if (existing && !target) {
                existing.remove();
            }
        }

        const defaults = editorDefaults();

        for (const config of requestedEditors) {
            if (!config?.id) {
                continue;
            }

            const target = document.getElementById(config.id);
            if (!target) {
                continue;
            }

            attachFormSync(target);

            const existing = window.tinymce.get(config.id);
            if (existing) {
                const nextValue = config.value ?? "";
                if (existing.getContent({ format: "html" }) !== nextValue) {
                    existing.setContent(nextValue);
                    syncEditor(existing);
                }
                continue;
            }

            await window.tinymce.init({
                ...defaults,
                target,
                min_height: config.minHeight ?? 260,
                setup(editor) {
                    editor.on("init", () => {
                        editor.setContent(config.value ?? "");
                        syncEditor(editor);
                        hideDecorativeIcons(editor);
                    });

                    editor.on("change input keyup undo redo SetContent", () => syncEditor(editor));
                }
            });
        }
    }

    // A skin change needs a fresh instance; TinyMCE cannot swap skins in place.
    // Capture the content first so a theme switch never discards the user's work.
    function rebuildForTheme() {
        if (!window.tinymce?.editors?.length) {
            return;
        }

        const snapshot = window.tinymce.editors
            .filter((editor) => editor?.targetElm?.id)
            .map((editor) => ({
                id: editor.targetElm.id,
                value: editor.getContent({ format: "html" }),
                minHeight: editor.settings?.min_height
            }));

        if (snapshot.length === 0) {
            return;
        }

        dispose(snapshot.map((entry) => entry.id));
        void syncTinyMce(snapshot, snapshot.map((entry) => entry.id));
    }

    return {
        syncTinyMce,
        flush,
        dispose,
        rebuildForTheme
    };
})();

(() => {
    const start = () => {
        try {
            // Wires every data-sk-* behaviour and keeps watching the DOM, so
            // components Blazor renders after this point are enhanced too.
            window.Sekura?.autoEnhance?.();
        } catch {
            // A failed enhancement must not take the page down; the components
            // degrade to their unenhanced markup.
        }

        document.documentElement.addEventListener("sk:theme:change", () => {
            window.secureJournalEditors?.rebuildForTheme?.();
        });
    };

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", start, { once: true });
    } else {
        start();
    }
})();
