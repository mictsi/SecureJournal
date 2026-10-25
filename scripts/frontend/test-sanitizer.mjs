// Browser regressions for the official upstream sanitizer fixes and the actual
// served TinyMCE build. No application credentials or databases are involved.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { homedir } from "node:os";
import { dirname, extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const assets = join(root, "SecureJournal.Web/wwwroot");
const inputs = JSON.parse(await readFile(join(here, "build-inputs.json"), "utf8"));
const packages = process.env.NUGET_PACKAGES || join(homedir(), ".nuget/packages");
const original = await readFile(join(packages, "tinymce", inputs.tinymceVersion, "content/scripts/tinymce/tinymce.js"), "utf8");
const rebuilt = await readFile(join(assets, "lib/tinymce/tinymce.js"), "utf8");
const endBoundary = "\n\n    /**\n     * This class handles parsing, modification and serialization of URI/URL strings.";
const oldStart = original.indexOf("    /*! @license DOMPurify 3.4.12 ");
const newStart = rebuilt.indexOf("    var purify = (() => {");
assert.ok(oldStart > 0 && newStart > 0, "Pinned sanitizer module boundaries exist");
const originalModule = original.slice(oldStart, original.indexOf(endBoundary, oldStart));
const rebuiltModule = rebuilt.slice(newStart, rebuilt.indexOf(endBoundary, newStart));

const server = createServer(async (request, response) => {
    try {
        if (request.url === "/") {
            response.setHeader("Content-Type", "text/html; charset=utf-8");
            response.end('<!doctype html><html><head><meta charset="utf-8"></head><body><textarea id="editor"></textarea></body></html>');
            return;
        }
        const pathname = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
        const file = resolve(assets, `.${pathname}`);
        if (!file.startsWith(assets + sep)) throw new Error("Outside fixture assets");
        response.setHeader("Content-Type", ({ ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" })[extname(file)] || "application/octet-stream");
        response.end(await readFile(file));
    } catch {
        response.writeHead(404).end();
    }
});
await new Promise((done) => server.listen(0, "127.0.0.1", done));
const browser = await chromium.launch({
    headless: true,
    ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE } : {})
});
try {
    const page = await browser.newPage();
    const browserErrors = [];
    page.on("pageerror", error => browserErrors.push(error.message));
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    async function inspectModule(source) {
        await page.addScriptTag({ content: `window.testPurify = (() => { ${source}\nreturn purify; })();` });
        return page.evaluate(() => {
            const sanitizer = window.testPurify();
            const root = document.createElement("div");
            root.innerHTML = '<footer><img onerror="window.unwantedExecution=true"></footer><div>safe</div>';
            const image = root.querySelector("img");
            sanitizer.addHook("uponSanitizeElement", node => {
                if (node.tagName === "FOOTER") node.remove();
            });
            sanitizer.sanitize(root, { IN_PLACE: true, ALLOWED_TAGS: ["div", "footer", "#text"] });
            const detachedHandlerSurvives = image.hasAttribute("onerror");
            const rawtext = document.createElement("style");
            rawtext.textContent = '</style><img src=x onerror="window.unwantedExecution=true">';
            document.body.append(rawtext);
            let rawtextRejected = false;
            try {
                const output = window.testPurify().sanitize(rawtext, { IN_PLACE: true });
                const probe = document.createElement("div");
                probe.innerHTML = output.outerHTML;
                rawtextRejected = !probe.querySelector("img[onerror]");
            } catch (error) {
                rawtextRejected = error instanceof TypeError;
            } finally {
                rawtext.remove();
            }
            return { version: sanitizer.version, detachedHandlerSurvives, rawtextRejected };
        });
    }
    const before = await inspectModule(originalModule);
    const after = await inspectModule(rebuiltModule);
    assert.equal(before.version, "3.4.12");
    assert.equal(before.detachedHandlerSurvives, true, "Original bundle reproduces GHSA-55q2-fjhq-7xh7");
    assert.equal(before.rawtextRejected, false, "Original bundle reproduces GHSA-6688-9rhm-gjv2");
    assert.equal(after.version, inputs.dompurifyVersion);
    assert.equal(after.detachedHandlerSurvives, false, "Patched module neutralizes detached descendants");
    assert.equal(after.rawtextRejected, true, "Patched module rejects the GHSA-6688-9rhm-gjv2 rawtext root");

    // The original vulnerable control deliberately queues an event; isolate the
    // real editor checks from that discarded document and its marker.
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.addScriptTag({ url: "/lib/tinymce/tinymce.min.js" });
    await page.evaluate(async () => {
        await tinymce.init({
            selector: "#editor", license_key: "gpl", base_url: "/lib/tinymce", suffix: ".min",
            plugins: "autoresize advlist code link lists table", promotion: false,
            toolbar: "bold italic bullist numlist link table code", menubar: false,
            valid_elements: "p,strong,em,ul,ol,li,a[href],table,tbody,tr,td",
            invalid_elements: "script,style,iframe,object,embed,svg,math,form,input"
        });
    });
    const content = await page.evaluate(() => {
        const editor = tinymce.get("editor");
        editor.setContent('<p>Safe <strong>decision</strong></p><table><tbody><tr><td>Kept cell</td></tr></tbody></table><img src=x onerror="window.unwantedExecution=true"><script>window.unwantedExecution=true</script><p><a href="javascript:alert(1)">unsafe link</a></p>');
        return {
            version: `${tinymce.majorVersion}.${tinymce.minorVersion}`,
            html: editor.getContent(), executed: !!window.unwantedExecution,
            plugins: Object.keys(editor.plugins).sort()
        };
    });
    assert.equal(content.version, inputs.tinymceVersion);
    assert.match(content.html, /<strong>decision<\/strong>/);
    assert.match(content.html, /<td>Kept cell<\/td>/);
    assert.doesNotMatch(content.html, /<script|<img|onerror|javascript:/i);
    assert.equal(content.executed, false);
    assert.deepEqual(content.plugins, ["advlist", "autoresize", "code", "link", "lists", "table"]);
    assert.deepEqual(browserErrors, []);
    console.log(JSON.stringify({ before, after, editorVersion: content.version, editorRoundTrip: "passed" }, null, 2));
} finally {
    await browser.close();
    await new Promise(done => server.close(done));
}
