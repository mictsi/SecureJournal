// Replace one bundled upstream module. No application-specific sanitization is
// introduced: DOMPurify's complete official distribution supplies the fix.
import { createHash } from "node:crypto";
import { readFile, writeFile, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { transform, version as esbuildVersion } from "esbuild";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const inputs = JSON.parse(await readFile(join(here, "build-inputs.json"), "utf8"));
const packages = process.env.NUGET_PACKAGES || join(homedir(), ".nuget/packages");
const corePath = join(packages, "tinymce", inputs.tinymceVersion, "content/scripts/tinymce/tinymce.js");
const purifyPath = join(here, "node_modules/dompurify/dist/purify.es.mjs");
const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const core = await readFile(corePath, "utf8");
const purifyModule = await readFile(purifyPath, "utf8");
if (sha256(core) !== inputs.tinymceCoreSha256 || sha256(purifyModule) !== inputs.dompurifyModuleSha256) {
    throw new Error("Upstream module hash changed. Review and update build-inputs.json before rebuilding.");
}
if (esbuildVersion !== inputs.esbuildVersion) throw new Error("Run npm ci to restore the pinned minifier.");

const startMarker = "    /*! @license DOMPurify 3.4.12 ";
const endMarker = "    var purify = createDOMPurify();";
const exportMarker = "export { purify_default as default };";
const start = core.indexOf(startMarker);
const end = core.indexOf(endMarker, start) + endMarker.length;
if (start < 0 || end < start || core.indexOf(startMarker, start + 1) >= 0 ||
    purifyModule.split(exportMarker).length !== 2) {
    throw new Error("Upstream DOMPurify module boundaries changed; refusing an ambiguous replacement.");
}
const isolatedPurify = purifyModule
    .replace(exportMarker, "return purify_default;")
    .replace(/\/\/# sourceMappingURL=.*$/m, "");
const replacement = `    var purify = (() => {\n${isolatedPurify}\n    })();`;
const output = core.slice(0, start) + replacement + core.slice(end);
const banner = `/*! Secure Journal: TinyMCE ${inputs.tinymceVersion} with official DOMPurify ${inputs.dompurifyVersion}. See THIRD-PARTY-BUILD.txt. */`;
const minified = await transform(output, {
    loader: "js", minify: true, target: "es2022", legalComments: "inline", charset: "ascii",
    supported: { "template-literal": false }
});
const target = join(root, "SecureJournal.Web/wwwroot/lib/tinymce");
await writeFile(join(target, "tinymce.js"), output);
await writeFile(join(target, "tinymce.min.js"), `${banner}\n${minified.code}`);
await writeFile(join(target, "DOMPurify-LICENSE"), await readFile(join(here, "node_modules/dompurify/LICENSE")));
await writeFile(join(target, "THIRD-PARTY-BUILD.txt"), [
    `TinyMCE ${inputs.tinymceVersion}, GPL-2.0-or-later, https://www.tiny.cloud/`,
    `Secure Journal rebuild replaces the embedded DOMPurify 3.4.12 module with the complete`,
    `official DOMPurify ${inputs.dompurifyVersion} distribution (Apache-2.0 OR MPL-2.0).`,
    `Source: https://github.com/cure53/DOMPurify/releases/tag/${inputs.dompurifyVersion}`,
    `The replacement is isolated in a closure and retains TinyMCE's existing module interface.`,
    `Core input SHA-256: ${inputs.tinymceCoreSha256}`,
    `DOMPurify input SHA-256: ${inputs.dompurifyModuleSha256}`,
    `Minifier: esbuild ${inputs.esbuildVersion}; pinned inputs and npm lockfile: scripts/frontend/`,
    `Rebuild: npm ci --ignore-scripts --prefix scripts/frontend`,
    `         python3 scripts/verify-frontend-assets.py --sync-tinymce`,
    `The unused codesample plugin is omitted; it bundles an older Prism implementation.`,
    `Upstream license.md and notices.txt are retained unchanged; their DOMPurify version is superseded above.`,
    ""
].join("\n"));
for (const plugin of inputs.omittedPlugins) {
    if (!/^[a-z]+$/.test(plugin)) throw new Error("Invalid omitted plugin name");
    await rm(join(target, "plugins", plugin), { recursive: true, force: true });
}
console.log(`Rebuilt TinyMCE ${inputs.tinymceVersion} with DOMPurify ${inputs.dompurifyVersion}; omitted ${inputs.omittedPlugins.join(", ")}.`);
