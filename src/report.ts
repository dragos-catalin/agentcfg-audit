import { LINE_RULES } from "./rules.ts";
import type { Report } from "./scan.ts";
import type { Severity } from "./types.ts";

export const RULES: Record<string, string> = {
    ACA000: "File could not be parsed",
    ACA001: "Hidden Unicode (tag, bidi, zero-width) characters",
    ACA002: "Instructions hidden in an HTML comment",
    ...Object.fromEntries(LINE_RULES.map((r) => [r.id, r.message])),
    ACA010: "Hook runs a command automatically",
    ACA011: "Permission settings approve tools without asking",
    ACA012: "MCP server package without a pinned version",
    ACA013: "MCP server over plain HTTP",
    ACA014: "Skill without name/description front matter",
    ACA015: "Skill pre-approves an unrestricted shell",
};

export function formatText(r: Report): string {
    if (r.findings.length === 0) return `agentcfg-audit: ${r.files.length} file(s) scanned, no findings`;
    const lines = r.findings.map(
        (f) =>
            `${f.severity.toUpperCase().padEnd(8)} ${f.rule}  ${f.file}:${f.line}  ${f.message}${f.excerpt ? `\n           ${f.excerpt}` : ""}`,
    );
    const counts = new Map<Severity, number>();
    for (const f of r.findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
    const summary = [...counts].map(([s, n]) => `${n} ${s}`).join(", ");
    return `${lines.join("\n")}\n\n${r.files.length} file(s) scanned: ${summary}`;
}

const SARIF_LEVEL: Record<Severity, "note" | "warning" | "error"> = {
    info: "note",
    low: "note",
    medium: "warning",
    high: "error",
    critical: "error",
};

/** SARIF 2.1.0 for GitHub code scanning (upload with github/codeql-action/upload-sarif). */
export function formatSarif(r: Report, version: string): string {
    const used = [...new Set(r.findings.map((f) => f.rule))].sort();
    return JSON.stringify(
        {
            $schema: "https://json.schemastore.org/sarif-2.1.0.json",
            version: "2.1.0",
            runs: [
                {
                    tool: {
                        driver: {
                            name: "agentcfg-audit",
                            version,
                            informationUri: "https://github.com/dragos-catalin/agentcfg-audit",
                            rules: used.map((id) => ({ id, shortDescription: { text: RULES[id] ?? id } })),
                        },
                    },
                    results: r.findings.map((f) => ({
                        ruleId: f.rule,
                        level: SARIF_LEVEL[f.severity],
                        message: { text: f.message },
                        properties: { severity: f.severity },
                        locations: [
                            {
                                physicalLocation: {
                                    artifactLocation: { uri: f.file },
                                    region: { startLine: f.line },
                                },
                            },
                        ],
                    })),
                },
            ],
        },
        null,
        2,
    );
}
