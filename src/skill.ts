import { lineOf } from "./rules.ts";
import type { ConfigFile, Finding } from "./types.ts";

/** Minimal YAML front-matter reader: top-level `key: value` and `key: [a, b]` / dash lists. */
export function frontMatter(text: string): { data: Record<string, string | string[]>; endLine: number } | null {
    const m = /^\uFEFF?---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text);
    if (!m) return null;
    const data: Record<string, string | string[]> = {};
    let current: string | null = null;
    for (const raw of (m[1] ?? "").split(/\r?\n/)) {
        const item = /^\s+-\s+(.*)$/.exec(raw);
        if (item && current) {
            const prev = data[current];
            data[current] = [...(Array.isArray(prev) ? prev : []), unquote(item[1] ?? "")];
            continue;
        }
        const kv = /^([A-Za-z0-9_-]+):\s*(.*)$/.exec(raw);
        if (!kv) continue;
        current = kv[1]!;
        const v = (kv[2] ?? "").trim();
        if (v.startsWith("[") && v.endsWith("]")) {
            data[current] = v
                .slice(1, -1)
                .split(",")
                .map((s) => unquote(s.trim()))
                .filter(Boolean);
        } else data[current] = unquote(v);
    }
    return { data, endLine: (m[0].match(/\n/g) ?? []).length };
}

const unquote = (s: string): string => s.replace(/^(['"])(.*)\1$/, "$2");

const SHELL_TOOLS = /^(Bash|Shell|PowerShell|run_in_terminal|execute|terminal)(\(\s*\*?\s*\))?$|^\*$/i;

/** SKILL.md: a skill must say what it is for, and should not grant itself an unrestricted shell. */
export function scanSkill(f: ConfigFile, text: string): Finding[] {
    const out: Finding[] = [];
    const fm = frontMatter(text);
    if (!fm || !fm.data["name"] || !fm.data["description"]) {
        out.push({
            rule: "ACA014",
            severity: "low",
            file: f.path,
            line: 1,
            message: "SKILL.md has no front matter with name and description: the agent cannot tell when it applies",
        });
    }
    const raw = fm?.data["allowed-tools"] ?? fm?.data["tools"];
    const tools = Array.isArray(raw) ? raw : typeof raw === "string" ? raw.split(/[\s,]+/).filter(Boolean) : [];
    for (const t of tools) {
        if (SHELL_TOOLS.test(t)) {
            out.push({
                rule: "ACA015",
                severity: "medium",
                file: f.path,
                line: lineOf(text, t),
                message: `Skill grants itself "${t}" without a command filter: any shell command runs pre-approved`,
            });
        }
    }
    return out;
}
