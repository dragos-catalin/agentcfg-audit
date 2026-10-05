import { lineOf, scanText } from "./rules.ts";
import type { ConfigFile, Finding } from "./types.ts";

/** Strip // and /* *\/ comments and trailing commas so JSONC parses. Strings are respected. */
export function stripJsonc(text: string): string {
    let out = "";
    let i = 0;
    let inStr = false;
    while (i < text.length) {
        const c = text[i]!;
        if (inStr) {
            out += c;
            if (c === "\\") out += text[++i] ?? "";
            else if (c === '"') inStr = false;
            i++;
        } else if (c === '"') {
            inStr = true;
            out += c;
            i++;
        } else if (c === "/" && text[i + 1] === "/") {
            while (i < text.length && text[i] !== "\n") i++;
        } else if (c === "/" && text[i + 1] === "*") {
            i += 2;
            while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
            i += 2;
        } else {
            out += c;
            i++;
        }
    }
    return out.replace(/,(\s*[}\]])/g, "$1");
}

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
const isObj = (v: unknown): v is Record<string, Json> => typeof v === "object" && v !== null && !Array.isArray(v);

/** Where a JSON string sits in the original text (first 40 chars of its encoded form). */
function locate(text: string, value: string): number {
    return lineOf(text, JSON.stringify(value).slice(1, 41));
}

const COMMAND_KEYS = new Set(["command", "bash", "powershell", "windows", "linux", "osx", "sh", "cmd"]);

/** Every command string under a `hooks` object, with the event name it fires on. */
function hookCommands(node: Json, event = ""): { event: string; command: string }[] {
    const out: { event: string; command: string }[] = [];
    if (Array.isArray(node)) for (const n of node) out.push(...hookCommands(n, event));
    else if (isObj(node)) {
        for (const [k, v] of Object.entries(node)) {
            if (COMMAND_KEYS.has(k) && typeof v === "string") out.push({ event, command: v });
            else out.push(...hookCommands(v, event || k));
        }
    }
    return out;
}

const SESSION_START = /^(sessionstart|session_start|userpromptsubmit|onstart)$/i;

function scanHooks(f: ConfigFile, text: string, hooks: Json): Finding[] {
    const out: Finding[] = [];
    for (const { event, command } of hookCommands(hooks)) {
        const line = locate(text, command);
        out.push({
            rule: "ACA010",
            severity: SESSION_START.test(event) ? "medium" : "low",
            file: f.path,
            line,
            message: SESSION_START.test(event)
                ? `Hook runs a command automatically on ${event}, before you have reviewed anything in the session`
                : `Hook runs a command automatically on ${event || "an agent event"}`,
            excerpt: command.length > 120 ? `${command.slice(0, 117)}...` : command,
        });
        out.push(...scanText(f.path, command, { asCommand: true, firstLine: line }));
    }
    return out;
}

const BROAD_ALLOW = /^(Bash|Shell|PowerShell|run_in_terminal)(\(\s*\*?\s*\))?$|^\*$/i;

function scanClaudeSettings(f: ConfigFile, text: string, j: Record<string, Json>): Finding[] {
    const out: Finding[] = [];
    const perms = j["permissions"];
    if (isObj(perms)) {
        if (perms["defaultMode"] === "bypassPermissions") {
            out.push({
                rule: "ACA011",
                severity: "high",
                file: f.path,
                line: lineOf(text, "bypassPermissions"),
                message: "Permission mode bypassPermissions: every tool call runs without asking",
            });
        }
        const allow = perms["allow"];
        if (Array.isArray(allow)) {
            for (const a of allow) {
                if (typeof a === "string" && BROAD_ALLOW.test(a.trim())) {
                    out.push({
                        rule: "ACA011",
                        severity: "high",
                        file: f.path,
                        line: locate(text, a),
                        message: `Allow-list entry "${a}" approves any shell command`,
                    });
                }
            }
        }
    }
    if (j["enableAllProjectMcpServers"] === true) {
        out.push({
            rule: "ACA011",
            severity: "medium",
            file: f.path,
            line: lineOf(text, "enableAllProjectMcpServers"),
            message: "enableAllProjectMcpServers starts every MCP server a repository defines, without asking",
        });
    }
    return out;
}

const VSCODE_AUTO_APPROVE = ["chat.tools.autoApprove", "chat.tools.global.autoApprove", "chat.tools.edits.autoApprove"];

function scanVsCodeSettings(f: ConfigFile, text: string, j: Record<string, Json>): Finding[] {
    const out: Finding[] = [];
    for (const k of VSCODE_AUTO_APPROVE) {
        if (j[k] === true) {
            out.push({
                rule: "ACA011",
                severity: "high",
                file: f.path,
                line: lineOf(text, k),
                message: `${k} is true: agent tool calls run without confirmation`,
            });
        }
    }
    const term = j["chat.tools.terminal.autoApprove"];
    if (isObj(term)) {
        for (const [pattern, v] of Object.entries(term)) {
            if (v === true && /^\/\.\*\/[a-z]*$|^\*$/.test(pattern)) {
                out.push({
                    rule: "ACA011",
                    severity: "high",
                    file: f.path,
                    line: locate(text, pattern),
                    message: `Terminal auto-approve pattern "${pattern}" approves every command`,
                });
            }
        }
    }
    return out;
}

const LOCAL_HOST = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$)/i;
/** `npx -y pkg` / `uvx pkg` / `pnpm dlx pkg` with no version: whatever is latest runs next time. */
const RUNNERS = new Set(["npx", "bunx", "uvx", "pipx", "dlx"]);

function unpinnedPackage(command: string, args: string[]): string | null {
    const base = command
        .replace(/\\/g, "/")
        .split("/")
        .pop()!
        .replace(/\.(cmd|exe)$/i, "");
    const all = base === "pnpm" || base === "yarn" ? args.slice(1) : args;
    if (!RUNNERS.has(base) && !((base === "pnpm" || base === "yarn") && args[0] === "dlx")) return null;
    const pkg = all.find((a) => !a.startsWith("-"));
    if (!pkg) return null;
    const at = pkg.lastIndexOf("@");
    const hasVersion = at > 0 && /\d/.test(pkg.slice(at + 1)) && pkg.slice(at + 1) !== "latest";
    const isPath = /^[.~/]|^[A-Za-z]:[\\/]/.test(pkg);
    return hasVersion || isPath || /==\d/.test(pkg) ? null : pkg;
}

function scanMcp(f: ConfigFile, text: string, j: Record<string, Json>): Finding[] {
    const out: Finding[] = [];
    const servers = {
        ...(isObj(j["servers"]) ? j["servers"] : {}),
        ...(isObj(j["mcpServers"]) ? j["mcpServers"] : {}),
    };
    for (const [name, def] of Object.entries(servers)) {
        if (!isObj(def)) continue;
        const command = typeof def["command"] === "string" ? def["command"] : null;
        const args = Array.isArray(def["args"]) ? def["args"].filter((a): a is string => typeof a === "string") : [];
        const nameLine = locate(text, name);
        if (command) {
            const full = [command, ...args].join(" ");
            out.push(...scanText(f.path, full, { asCommand: true, firstLine: nameLine }));
            const pkg = unpinnedPackage(command, args);
            if (pkg) {
                out.push({
                    rule: "ACA012",
                    severity: "medium",
                    file: f.path,
                    line: locate(text, pkg),
                    message: `MCP server "${name}" runs "${pkg}" without a version: a new release runs on the next start, unreviewed`,
                });
            }
        }
        const url = typeof def["url"] === "string" ? def["url"] : null;
        if (url && url.startsWith("http://") && !LOCAL_HOST.test(url)) {
            out.push({
                rule: "ACA013",
                severity: "medium",
                file: f.path,
                line: locate(text, url),
                message: `MCP server "${name}" uses plain HTTP to a remote host`,
            });
        }
        if (url) out.push(...scanText(f.path, url, { asCommand: true, firstLine: locate(text, url) }));
        for (const block of ["env", "headers"]) {
            const vals = def[block];
            if (!isObj(vals)) continue;
            for (const v of Object.values(vals)) {
                if (typeof v === "string" && !/^\$\{|^\$[A-Z_]|^%[A-Z_]+%$/.test(v)) {
                    out.push(...scanText(f.path, v, { firstLine: locate(text, v) }));
                }
            }
        }
    }
    return out;
}

/** JSON-shaped config: hooks, settings, MCP. Returns a parse finding instead of throwing. */
export function scanJson(f: ConfigFile, text: string): Finding[] {
    let j: Json;
    try {
        j = JSON.parse(stripJsonc(text.replace(/^\uFEFF/, ""))) as Json;
    } catch (e) {
        return [
            {
                rule: "ACA000",
                severity: "low",
                file: f.path,
                line: 1,
                message: `Not valid JSON, not checked: ${(e as Error).message}`,
            },
        ];
    }
    if (!isObj(j)) return [];
    const out: Finding[] = [];
    if (j["hooks"] !== undefined) out.push(...scanHooks(f, text, j["hooks"]));
    if (f.kind === "settings") {
        out.push(...scanClaudeSettings(f, text, j));
        out.push(...scanVsCodeSettings(f, text, j));
    }
    if (f.kind === "mcp" || j["mcpServers"] !== undefined) out.push(...scanMcp(f, text, j));
    return out;
}
