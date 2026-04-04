window.secureJournalTheme = (() => {
    function applyTheme() {
        document.documentElement.setAttribute("data-theme", "dark");
        document.body.setAttribute("data-theme", "dark");
        return "dark";
    }

    return {
        init: () => applyTheme(),
        toggle: () => applyTheme()
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
    const editorDefaults = {
        base_url: "/lib/tinymce",
        suffix: ".min",
        license_key: "gpl",
        menubar: false,
        branding: false,
        promotion: false,
        statusbar: false,
        resize: false,
        plugins: "autoresize advlist code link lists",
        toolbar: "blocks | bold italic underline strikethrough | bullist numlist blockquote | link | code | removeformat",
        skin: "oxide-dark",
        content_css: "dark",
        valid_elements: "a[href|target|rel],blockquote,br,code,em,h2,h3,h4,li,ol,p,pre,s,strong,u,ul",
        invalid_elements: "script,style,iframe,object,embed,svg,math,form,input,button,textarea,select",
        link_default_target: "_blank",
        link_assume_external_targets: true,
        default_link_target: "_blank",
        forced_root_block: "p",
        content_style: "body { background: #202c3e; color: #edf4ff; font-family: 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.65; padding: 1rem; } a { color: #b9d3ff; } blockquote { border-left: 3px solid rgba(166, 191, 231, 0.35); margin: 1rem 0; padding-left: 1rem; color: #dbe7fa; } pre { background: rgba(8, 15, 28, 0.78); color: #eef4ff; padding: 0.85rem 1rem; border-radius: 0.75rem; } code { background: rgba(8, 15, 28, 0.55); color: #eef4ff; padding: 0.1rem 0.3rem; border-radius: 0.35rem; }"
    };

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
                ...editorDefaults,
                target,
                min_height: config.minHeight ?? 260,
                setup(editor) {
                    editor.on("init", () => {
                        editor.setContent(config.value ?? "");
                        syncEditor(editor);
                    });

                    editor.on("change input keyup undo redo SetContent", () => syncEditor(editor));
                }
            });
        }
    }

    return {
        syncTinyMce,
        flush,
        dispose
    };
})();

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
