import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

/** A temp repo with the given files. Paths use forward slashes. */
export function repo(files: Record<string, string>): string {
    const dir = mkdtempSync(join(tmpdir(), "agentcfg-"));
    for (const [p, body] of Object.entries(files)) {
        const abs = join(dir, ...p.split("/"));
        mkdirSync(dirname(abs), { recursive: true });
        writeFileSync(abs, body);
    }
    return dir;
}

/** Strings that secret scanners would flag in this repo, assembled at runtime. */
export const FAKE = {
    githubToken: ["ghp", "_", "A".repeat(36)].join(""),
    tag: (s: string): string => [...s].map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join(""),
    zwsp: String.fromCharCode(0x200b),
    rlo: String.fromCharCode(0x202e),
};
