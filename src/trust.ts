import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parsePublicKey } from "./sign.ts";

/**
 * Trusted signer keys as base64 SPKI: each `extra` entry (PEM file path, or PEM/base64 text),
 * then env AGENTCFG_TRUSTED_KEYS (separated by newline, comma or semicolon), then
 * ~/.config/agentcfg/trusted_keys (one per line, `#` comments). Never read from the repository.
 */
export function trustedKeys(
    extra: readonly string[],
    env: NodeJS.ProcessEnv = process.env,
    home: string = homedir(),
): string[] {
    const raw: string[] = [];
    for (const t of extra) raw.push(existsSync(t) ? readFileSync(t, "utf8") : t);
    const fromEnv = env["AGENTCFG_TRUSTED_KEYS"];
    if (fromEnv) raw.push(...fromEnv.split(/[\n,;]/));
    const file = join(home, ".config", "agentcfg", "trusted_keys");
    if (existsSync(file)) raw.push(...readFileSync(file, "utf8").split(/\r?\n/));
    const out: string[] = [];
    for (const r of raw) {
        const t = r.replace(/#.*$/, "").trim();
        if (!t) continue;
        // A PEM file holds one key over several lines; a list file holds one per line.
        try {
            out.push(parsePublicKey(t));
        } catch {
            throw new Error(`not an ed25519 public key: ${t.slice(0, 40)}`);
        }
    }
    return out;
}
