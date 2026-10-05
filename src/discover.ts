import { readdirSync, statSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import type { ConfigFile, Kind } from "./types.ts";

const SKIP_DIRS = new Set([
    "node_modules",
    ".git",
    "dist",
    "build",
    "out",
    "target",
    ".next",
    ".turbo",
    "coverage",
    ".venv",
    "venv",
    "__pycache__",
    ".gradle",
]);

const INSTRUCTION_FILES = new Set([
    "agents.md",
    "claude.md",
    "gemini.md",
    ".cursorrules",
    ".windsurfrules",
    "copilot-instructions.md",
]);

const toPosix = (p: string): string => p.split(sep).join("/");

/**
 * Which agent reads this file, judged from its absolute path so that scanning
 * `~/.claude` directly still recognises `settings.json` as Claude settings.
 */
export function classify(absPath: string): Kind | null {
    const p = toPosix(absPath).toLowerCase();
    const base = p.slice(p.lastIndexOf("/") + 1);
    if (base === "skill.md") return "skill";
    if (INSTRUCTION_FILES.has(base)) return "instructions";
    if (/\.(instructions|prompt|agent|chatmode)\.md$/.test(base)) return "instructions";
    if (/\/\.cursor\/rules\/[^/]+\.mdc$/.test(p)) return "instructions";
    if (/\/\.(claude|copilot)\/(rules|agents|commands|instructions)\/.+\.md$/.test(p)) return "instructions";
    if (/\/\.claude\/settings(\.local)?\.json$/.test(p)) return "settings";
    if (/\/\.vscode\/settings\.json$/.test(p)) return "settings";
    if (/\/\.github\/hooks\/[^/]+\.json$/.test(p)) return "hooks";
    if (/\/\.(claude|copilot)\/hooks\.json$/.test(p)) return "hooks";
    if (/\/(\.vscode\/mcp|\.cursor\/mcp|\.mcp|mcp)\.json$/.test(p)) return "mcp";
    return null;
}

function fallbackKind(absPath: string): Kind | null {
    const p = absPath.toLowerCase();
    if (p.endsWith(".md") || p.endsWith(".mdc")) return "instructions";
    if (p.endsWith(".json")) return "settings";
    return null;
}

const MAX_BYTES = 2 * 1024 * 1024;
const SCRIPT_EXT = /\.(sh|bash|zsh|ps1|psm1|py|js|mjs|cjs|ts|rb|cmd|bat)$/i;

/** Scripts shipped inside a skill folder run with the agent's permissions too. */
function skillScripts(dir: string, depth = 0): string[] {
    if (depth > 3) return [];
    const out: string[] = [];
    for (const e of readdirSync(dir, { withFileTypes: true })) {
        const abs = resolve(dir, e.name);
        if (e.isDirectory() && !SKIP_DIRS.has(e.name)) out.push(...skillScripts(abs, depth + 1));
        else if (e.isFile() && SCRIPT_EXT.test(e.name)) out.push(abs);
    }
    return out;
}

/**
 * Agent config files under `targets` (files or directories). An explicitly named
 * file is always included; inside directories only recognised names count.
 * Symlinks are not followed. Paths are reported relative to `root`.
 */
export function discover(targets: string[], root: string = process.cwd()): ConfigFile[] {
    const found = new Map<string, ConfigFile>();
    const add = (abs: string, kind: Kind): void => {
        if (statSync(abs).size > MAX_BYTES) return;
        found.set(abs, { abs, kind, path: toPosix(relative(root, abs)) || toPosix(abs) });
        if (kind === "skill") for (const s of skillScripts(resolve(abs, ".."))) if (!found.has(s)) add(s, "script");
    };
    const walk = (dir: string): void => {
        for (const e of readdirSync(dir, { withFileTypes: true })) {
            const abs = resolve(dir, e.name);
            if (e.isDirectory()) {
                if (!SKIP_DIRS.has(e.name)) walk(abs);
            } else if (e.isFile()) {
                const kind = classify(abs);
                if (kind) add(abs, kind);
            }
        }
    };
    for (const t of targets) {
        const abs = resolve(root, t);
        const st = statSync(abs);
        if (st.isDirectory()) walk(abs);
        else {
            const kind = classify(abs) ?? fallbackKind(abs);
            if (kind) add(abs, kind);
        }
    }
    return [...found.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}
