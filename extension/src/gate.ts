// Pure decision logic for the editor gate. No `vscode` import: everything here is unit-tested,
// and extension.ts only adapts it to the editor API.
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { classify, discover } from "../../src/discover.ts";
import { scanAll } from "../../src/scan.ts";
import {
    DEFAULT_MANIFEST,
    canonical,
    entries,
    hashContent,
    parseManifest,
    verifyManifest,
    verifyOk,
    type ManifestEntry,
} from "../../src/sign.ts";
import { atLeast, type Finding, type Severity } from "../../src/types.ts";

export type UnsignedPolicy = "scan" | "lock" | "warn";
export type GateState = "verified" | "locked" | "unsigned" | "acknowledged";

/** The workspace settings file the gate itself writes when it locks. */
export const SETTINGS_PATH = ".vscode/settings.json";

/**
 * Settings written at workspace (folder) scope to stop the Local agent harness from loading the
 * repository's customizations. Ids from code.visualstudio.com/docs/agents/reference/ai-settings
 * (checked 2026-10-06). `map: true` = an object of locations; every key of the effective value is
 * set to false. `chat.mcp.access` and application-scoped settings are deliberately not touched.
 */
export const LOCK_SETTINGS: readonly LockSetting[] = [
    { id: "chat.useAgentsMdFile", value: false },
    { id: "chat.useNestedAgentsMdFiles", value: false },
    { id: "chat.useClaudeMdFile", value: false },
    { id: "github.copilot.chat.codeGeneration.useInstructionFiles", value: false },
    { id: "chat.includeApplyingInstructions", value: false },
    { id: "chat.includeReferencedInstructions", value: false },
    { id: "chat.useAgentSkills", value: false },
    { id: "chat.useHooks", value: false },
    { id: "chat.useClaudeHooks", value: false },
    { id: "chat.mcp.autostart", value: "never" },
    { id: "chat.instructionsFilesLocations", map: true },
    { id: "chat.promptFilesLocations", map: true },
    { id: "chat.agentFilesLocations", map: true },
    { id: "chat.agentSkillsLocations", map: true },
    { id: "chat.hookFilesLocations", map: true },
];

export type LockSetting = { id: string; value: boolean | string } | { id: string; map: true };

/** A settings value as remembered in workspaceState; `null` means the key was absent. */
export type SavedValue = { value: unknown } | null;

/** What the gate wrote to SETTINGS_PATH: content hashes before (null = no file) and after. */
export interface SelfWrite {
    path: string;
    before: string | null;
    after: string;
}

export interface GateInput {
    root: string;
    /** Injected by the adapter from application-scope settings, env and ~/.config — never the repo. */
    trustedKeys: () => string[];
    unsignedPolicy: UnsignedPolicy;
    lockOnSeverity: Severity;
    selfWrite?: SelfWrite | undefined;
    acknowledged?: readonly string[] | undefined;
}

export interface Evaluation {
    state: GateState;
    locked: boolean;
    signed: boolean;
    reasons: string[];
    findings: Finding[];
    entries: ManifestEntry[];
    ackHash: string;
}

/** Undo the gate's own write to SETTINGS_PATH, so locking does not make the workspace locked forever. */
export function substituteSelfWrite(live: ManifestEntry[], sw: SelfWrite | undefined): ManifestEntry[] {
    if (!sw) return live;
    const out: ManifestEntry[] = [];
    for (const e of live) {
        if (e.path !== sw.path || e.sha256 !== sw.after) out.push(e);
        else if (sw.before !== null) out.push({ ...e, sha256: sw.before });
    }
    return out;
}

/**
 * The record after another gate write. Re-locking on top of our own last write keeps the original
 * `before`; anything else (a manual edit in between) starts from the edited content, which is then
 * still compared against the manifest and reported. Unlocking is a gate write too: its result maps
 * back to the content from before the lock.
 */
export function nextSelfWrite(
    prev: SelfWrite | undefined,
    before: string | null,
    after: string | null,
): SelfWrite | undefined {
    const orig = prev && before === prev.after ? prev.before : before;
    if (after === null) return undefined;
    return { path: SETTINGS_PATH, before: orig, after };
}

/** Content hash of a file as the manifest computes it, or null when absent. */
export function fileHash(abs: string): string | null {
    return existsSync(abs) ? hashContent(readFileSync(abs)) : null;
}

/** Stable across discovery order: sha256 of the canonical, path-sorted entry list. */
export function ackHash(live: readonly ManifestEntry[]): string {
    const sorted = [...live].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    return createHash("sha256").update(canonical(sorted)).digest("hex");
}

export function evaluateFolder(input: GateInput): Evaluation {
    const live = substituteSelfWrite(entries(discover(["."], input.root)), input.selfWrite);
    const hash = ackHash(live);
    const reasons: string[] = [];
    let findings: Finding[] = [];
    let locked: boolean;
    const manifestPath = join(input.root, DEFAULT_MANIFEST);
    const signed = existsSync(manifestPath);

    if (signed) {
        locked = !verifySigned(manifestPath, live, input.trustedKeys, reasons);
    } else {
        findings = scanAll(discover(["."], input.root)).findings;
        const blocking = findings.filter((f) => atLeast(f.severity, input.lockOnSeverity));
        if (input.unsignedPolicy === "lock") {
            locked = true;
            reasons.push("unsigned: policy is lock (no agentcfg.lock.json)");
        } else if (input.unsignedPolicy === "scan" && blocking.length > 0) {
            locked = true;
            reasons.push(`unsigned: ${blocking.length} finding(s) at or above ${input.lockOnSeverity}`);
        } else {
            locked = false;
            if (findings.length) reasons.push(`unsigned: ${findings.length} finding(s)`);
            else reasons.push("unsigned: no agentcfg.lock.json");
        }
    }

    if (locked && input.acknowledged?.includes(hash)) {
        return { state: "acknowledged", locked: false, signed, reasons, findings, entries: live, ackHash: hash };
    }
    const state: GateState = locked ? "locked" : signed ? "verified" : "unsigned";
    return { state, locked, signed, reasons, findings, entries: live, ackHash: hash };
}

function verifySigned(manifestPath: string, live: ManifestEntry[], keys: () => string[], reasons: string[]): boolean {
    let trusted: string[] = [];
    try {
        trusted = keys();
    } catch (e) {
        reasons.push(`trusted keys: ${(e as Error).message}`);
    }
    let r;
    try {
        r = verifyManifest(parseManifest(readFileSync(manifestPath, "utf8")), live, trusted);
    } catch (e) {
        reasons.push(`manifest unreadable: ${(e as Error).message}`);
        return false;
    }
    if (!r.signatureValid) reasons.push("signature invalid");
    if (!r.trusted) reasons.push(`untrusted signer ${r.fingerprint}`);
    for (const p of r.changed) reasons.push(`changed ${p}`);
    for (const p of r.added) reasons.push(`added ${p}`);
    for (const p of r.removed) reasons.push(`removed ${p}`);
    return verifyOk(r);
}

export interface SettingWrite {
    id: string;
    value: unknown;
}

/** Values to write when locking, given each setting's effective value (config.get). */
export function lockPlan(effective: (id: string) => unknown): SettingWrite[] {
    return LOCK_SETTINGS.map((s) => {
        if (!("map" in s)) return { id: s.id, value: s.value };
        const cur = effective(s.id);
        const keys = cur && typeof cur === "object" && !Array.isArray(cur) ? Object.keys(cur) : [];
        return { id: s.id, value: Object.fromEntries(keys.map((k) => [k, false])) };
    });
}

/** Remember the workspace-level values (inspect().workspaceValue / workspaceFolderValue). */
export function saveValues(workspaceValue: (id: string) => unknown): Record<string, SavedValue> {
    return Object.fromEntries(
        LOCK_SETTINGS.map((s) => {
            const v = workspaceValue(s.id);
            return [s.id, v === undefined ? null : { value: v }];
        }),
    );
}

/** Values to write when unlocking; `undefined` removes the key. */
export function restorePlan(saved: Record<string, SavedValue>): SettingWrite[] {
    return LOCK_SETTINGS.map((s) => ({ id: s.id, value: saved[s.id]?.value }));
}

/** True when the workspace already holds every lock value, so no write (and no file event) is needed. */
export function planApplied(plan: readonly SettingWrite[], workspaceValue: (id: string) => unknown): boolean {
    return plan.every((w) => canonical(workspaceValue(w.id)) === canonical(w.value));
}

const SCRIPT_EXT = /\.(sh|bash|zsh|ps1|psm1|py|js|mjs|cjs|ts|rb|cmd|bat)$/i;

/** One watcher glob over every file kind discovery can return; events are filtered by isRelevantPath. */
export const WATCH_GLOB =
    "**/{*.md,*.mdc,*.json,.cursorrules,.windsurfrules,*.sh,*.bash,*.zsh,*.ps1,*.psm1,*.py,*.js,*.mjs,*.cjs,*.ts,*.rb,*.cmd,*.bat}";

export function isRelevantPath(absPath: string): boolean {
    const p = absPath.replace(/\\/g, "/");
    if (/\/(node_modules|\.git)\//.test(p)) return false;
    if (p.toLowerCase().endsWith(`/${DEFAULT_MANIFEST}`)) return true;
    return classify(p) !== null || SCRIPT_EXT.test(p);
}

export function statusText(state: GateState): string {
    switch (state) {
        case "verified":
            return "$(shield) agent config verified";
        case "locked":
            return "$(lock) agent config locked";
        case "acknowledged":
            return "$(unlock) agent config unlocked";
        case "unsigned":
            return "$(warning) unsigned";
    }
}

/** Worst state across folders, for the single status bar item. */
export function overallState(states: readonly GateState[]): GateState {
    for (const s of ["locked", "unsigned", "acknowledged", "verified"] as const) if (states.includes(s)) return s;
    return "verified";
}

export function formatReport(folder: string, e: Evaluation): string {
    const lines = [`## ${folder}: ${e.state}${e.locked ? " (agent config locked)" : ""}`];
    for (const r of e.reasons) lines.push(`  - ${r}`);
    if (e.findings.length) {
        lines.push("  findings:");
        for (const f of e.findings)
            lines.push(`    ${f.severity.padEnd(8)} ${f.rule} ${f.file}:${f.line} ${f.message}`);
    }
    lines.push(`  ${e.entries.length} config file(s), content hash ${e.ackHash.slice(0, 12)}`);
    return lines.join("\n");
}
