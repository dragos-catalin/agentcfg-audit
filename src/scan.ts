import { readFileSync } from "node:fs";
import { scanMarkdownComments, scanText } from "./rules.ts";
import { scanSkill } from "./skill.ts";
import { scanJson } from "./structured.ts";
import { SEVERITIES, type ConfigFile, type Finding } from "./types.ts";

export function scanFile(f: ConfigFile, text: string = readFileSync(f.abs, "utf8")): Finding[] {
    const out: Finding[] = [];
    switch (f.kind) {
        case "skill":
            out.push(...scanSkill(f, text));
        // falls through: a skill is also instructions
        case "instructions":
            out.push(...scanText(f.path, text), ...scanMarkdownComments(f.path, text));
            break;
        case "script":
            out.push(...scanText(f.path, text, { asCommand: true }));
            break;
        case "settings":
        case "hooks":
        case "mcp":
            out.push(...scanJson(f, text));
            // Hidden characters anywhere in the file, not only in parsed strings.
            out.push(...scanText(f.path, text).filter((x) => x.rule === "ACA001" || x.rule === "ACA008"));
            break;
    }
    return dedupe(out);
}

function dedupe(fs: Finding[]): Finding[] {
    const seen = new Set<string>();
    return fs.filter((x) => {
        const k = `${x.rule}|${x.file}|${x.line}|${x.message}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
    });
}

export interface Report {
    files: ConfigFile[];
    findings: Finding[];
}

export function scanAll(files: ConfigFile[]): Report {
    const findings = files.flatMap((f) => scanFile(f));
    findings.sort(
        (a, b) =>
            SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity) ||
            a.file.localeCompare(b.file) ||
            a.line - b.line,
    );
    return { files, findings };
}
