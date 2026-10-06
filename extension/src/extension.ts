// Thin adapter: reads editor state, calls the pure functions in gate.ts, writes settings and UI.
import { join } from "node:path";
import * as vscode from "vscode";
import { trustedKeys } from "../../src/trust.ts";
import { isSeverity, type Severity } from "../../src/types.ts";
import {
    LOCK_SETTINGS,
    SETTINGS_PATH,
    WATCH_GLOB,
    evaluateFolder,
    fileHash,
    formatReport,
    isRelevantPath,
    lockPlan,
    nextSelfWrite,
    overallState,
    planApplied,
    saveValues,
    statusText,
    type Evaluation,
    type SavedValue,
    type SelfWrite,
    type SettingWrite,
    type UnsignedPolicy,
} from "./gate.ts";

type Target = "folder" | "workspace";
interface LockRecord {
    saved: Record<string, SavedValue>;
    targets: Record<string, Target>;
}

const key = (kind: string, f: vscode.WorkspaceFolder): string => `agentcfgGate.${kind}:${f.uri.toString()}`;

class Gate implements vscode.Disposable {
    private readonly status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    private readonly output = vscode.window.createOutputChannel("agentcfg gate");
    private readonly results = new Map<string, { folder: vscode.WorkspaceFolder; e: Evaluation }>();
    private timer: ReturnType<typeof setTimeout> | undefined;
    private running: Promise<void> = Promise.resolve();
    private readonly ctx: vscode.ExtensionContext;

    constructor(ctx: vscode.ExtensionContext) {
        this.ctx = ctx;
        this.status.command = "agentcfgGate.showReport";
        this.status.show();
    }

    dispose(): void {
        if (this.timer) clearTimeout(this.timer);
        this.status.dispose();
        this.output.dispose();
    }

    schedule(): void {
        if (this.timer) clearTimeout(this.timer);
        this.timer = setTimeout(() => void this.evaluateAll(), 1000);
    }

    /** Serialised so two evaluations never write settings at the same time. */
    evaluateAll(): Promise<void> {
        this.running = this.running.then(() => this.run()).catch((e: unknown) => this.log(`error: ${String(e)}`));
        return this.running;
    }

    private async run(): Promise<void> {
        this.results.clear();
        const newlyLocked: string[] = [];
        for (const folder of vscode.workspace.workspaceFolders ?? []) {
            const e = this.evaluate(folder);
            this.results.set(folder.uri.toString(), { folder, e });
            if (!vscode.workspace.isTrusted) continue; // restricted mode: settings are ignored anyway
            const record = this.ctx.workspaceState.get<LockRecord>(key("lock", folder));
            if (e.locked) {
                if (!record) newlyLocked.push(folder.name);
                await this.lock(folder, record);
            } else if (record) {
                await this.restore(folder, record);
            }
        }
        this.render();
        if (newlyLocked.length) void this.notify(newlyLocked);
    }

    private evaluate(folder: vscode.WorkspaceFolder): Evaluation {
        const cfg = vscode.workspace.getConfiguration("agentcfgGate");
        // Application-scope settings: only the user's globalValue counts, never a repo's settings.json.
        const keys = cfg.inspect<string[]>("trustedKeys")?.globalValue ?? [];
        const policy = cfg.inspect<string>("unsignedPolicy")?.globalValue ?? "scan";
        const sev = cfg.inspect<string>("lockOnSeverity")?.globalValue ?? "high";
        const e = evaluateFolder({
            root: folder.uri.fsPath,
            trustedKeys: () => trustedKeys(keys),
            unsignedPolicy: (["scan", "lock", "warn"].includes(policy) ? policy : "scan") as UnsignedPolicy,
            lockOnSeverity: isSeverity(sev) ? (sev as Severity) : "high",
            selfWrite: this.ctx.workspaceState.get<SelfWrite>(key("self", folder)),
            acknowledged: this.ctx.workspaceState.get<string[]>(key("ack", folder)) ?? [],
        });
        if (this.ctx.workspaceState.get<boolean>(key("manual", folder)) && !e.locked) {
            return { ...e, state: "locked", locked: true, reasons: ["locked manually", ...e.reasons] };
        }
        return e;
    }

    private multiRoot(): boolean {
        return vscode.workspace.workspaceFile !== undefined;
    }

    private async lock(folder: vscode.WorkspaceFolder, existing: LockRecord | undefined): Promise<void> {
        const cfg = vscode.workspace.getConfiguration(undefined, folder.uri);
        const plan = lockPlan((id) => cfg.get(id));
        const current = (id: string): unknown => {
            const i = cfg.inspect(id);
            const t = existing?.targets[id] ?? (this.multiRoot() ? "folder" : "workspace");
            return t === "folder" ? i?.workspaceFolderValue : i?.workspaceValue;
        };
        if (existing && planApplied(plan, current)) return;
        const record: LockRecord = existing ?? {
            saved: {},
            targets: {},
        };
        const folderSaved = saveValues((id) => cfg.inspect(id)?.workspaceFolderValue);
        const wsSaved = saveValues((id) => cfg.inspect(id)?.workspaceValue);
        await this.writeTracked(folder, async () => {
            for (const w of plan) {
                if (existing?.targets[w.id] !== undefined) {
                    await this.write(cfg, w, existing.targets[w.id] as Target);
                    continue;
                }
                const target = await this.writeFirst(cfg, w);
                record.targets[w.id] = target;
                record.saved[w.id] = (target === "folder" ? folderSaved : wsSaved)[w.id] ?? null;
            }
        });
        await this.ctx.workspaceState.update(key("lock", folder), record);
    }

    private async restore(folder: vscode.WorkspaceFolder, record: LockRecord): Promise<void> {
        const cfg = vscode.workspace.getConfiguration(undefined, folder.uri);
        await this.writeTracked(folder, async () => {
            for (const s of LOCK_SETTINGS) {
                const t = record.targets[s.id];
                if (t) await this.write(cfg, { id: s.id, value: record.saved[s.id]?.value }, t);
            }
        });
        await this.ctx.workspaceState.update(key("lock", folder), undefined);
    }

    /** Wrap a settings write so the resulting .vscode/settings.json hash is recorded as our own. */
    private async writeTracked(folder: vscode.WorkspaceFolder, fn: () => Promise<void>): Promise<void> {
        const file = join(folder.uri.fsPath, ...SETTINGS_PATH.split("/"));
        const before = fileHash(file);
        await fn();
        const prev = this.ctx.workspaceState.get<SelfWrite>(key("self", folder));
        await this.ctx.workspaceState.update(key("self", folder), nextSelfWrite(prev, before, fileHash(file)));
    }

    private async writeFirst(cfg: vscode.WorkspaceConfiguration, w: SettingWrite): Promise<Target> {
        if (this.multiRoot()) {
            try {
                await this.write(cfg, w, "folder");
                return "folder";
            } catch {
                // window-scoped settings cannot be written per folder; fall back to the workspace file
            }
        }
        await this.write(cfg, w, "workspace");
        return "workspace";
    }

    private async write(cfg: vscode.WorkspaceConfiguration, w: SettingWrite, t: Target): Promise<void> {
        const target =
            t === "folder" ? vscode.ConfigurationTarget.WorkspaceFolder : vscode.ConfigurationTarget.Workspace;
        try {
            await cfg.update(w.id, w.value, target);
        } catch (e) {
            if (t === "folder") throw e;
            this.log(`could not write ${w.id}: ${(e as Error).message}`); // e.g. a setting this build does not register
        }
    }

    private render(): void {
        const all = [...this.results.values()];
        if (!all.length) {
            this.status.hide();
            return;
        }
        const state = overallState(all.map((r) => r.e.state));
        this.status.text = statusText(state);
        const md = new vscode.MarkdownString();
        for (const { folder, e } of all) {
            md.appendMarkdown(`**${folder.name}**: ${e.state}\n\n`);
            for (const r of e.reasons.slice(0, 10)) md.appendText(`- ${r}\n`);
            md.appendMarkdown("\n");
        }
        if (!vscode.workspace.isTrusted)
            md.appendText("Restricted Mode: nothing is written; agent config is not loaded.");
        this.status.tooltip = md;
        this.status.backgroundColor =
            state === "locked" ? new vscode.ThemeColor("statusBarItem.warningBackground") : undefined;
        this.status.show();
    }

    private async notify(names: string[]): Promise<void> {
        const pick = await vscode.window.showWarningMessage(
            `agentcfg gate locked the agent config of ${names.join(", ")}: it did not verify.`,
            "Show report",
            "Unlock",
        );
        if (pick === "Show report") this.showReport();
        else if (pick === "Unlock") await this.unlock();
    }

    showReport(): void {
        this.output.clear();
        for (const { folder, e } of this.results.values()) this.output.appendLine(formatReport(folder.name, e));
        this.output.show(true);
    }

    async unlock(): Promise<void> {
        const locked = [...this.results.values()].filter((r) => r.e.locked);
        if (!locked.length) {
            void vscode.window.showInformationMessage("agentcfg gate: nothing is locked.");
            return;
        }
        const ok = await vscode.window.showWarningMessage(
            `Unlock ${locked.map((r) => r.folder.name).join(", ")}? The repository's agent config (instructions, skills, hooks, MCP servers) will load. It stays unlocked until that config changes.`,
            { modal: true },
            "Unlock",
        );
        if (ok !== "Unlock") return;
        for (const { folder, e } of locked) {
            const acks = this.ctx.workspaceState.get<string[]>(key("ack", folder)) ?? [];
            await this.ctx.workspaceState.update(key("ack", folder), [...new Set([...acks, e.ackHash])]);
            await this.ctx.workspaceState.update(key("manual", folder), undefined);
        }
        await this.evaluateAll();
    }

    async lockManually(): Promise<void> {
        for (const folder of vscode.workspace.workspaceFolders ?? []) {
            await this.ctx.workspaceState.update(key("manual", folder), true);
        }
        await this.evaluateAll();
    }

    private log(s: string): void {
        this.output.appendLine(s);
    }
}

export function activate(ctx: vscode.ExtensionContext): void {
    const gate = new Gate(ctx);
    const watcher = vscode.workspace.createFileSystemWatcher(WATCH_GLOB);
    const onFile = (uri: vscode.Uri): void => {
        if (isRelevantPath(uri.fsPath)) gate.schedule();
    };
    ctx.subscriptions.push(
        gate,
        watcher,
        watcher.onDidChange(onFile),
        watcher.onDidCreate(onFile),
        watcher.onDidDelete(onFile),
        vscode.workspace.onDidChangeWorkspaceFolders(() => void gate.evaluateAll()),
        vscode.workspace.onDidGrantWorkspaceTrust(() => void gate.evaluateAll()),
        vscode.workspace.onDidChangeConfiguration((e) => {
            if (e.affectsConfiguration("agentcfgGate")) gate.schedule();
        }),
        vscode.commands.registerCommand("agentcfgGate.verify", () => gate.evaluateAll()),
        vscode.commands.registerCommand("agentcfgGate.showReport", () => gate.showReport()),
        vscode.commands.registerCommand("agentcfgGate.unlock", () => gate.unlock()),
        vscode.commands.registerCommand("agentcfgGate.lock", () => gate.lockManually()),
    );
    void gate.evaluateAll();
}

export function deactivate(): void {}
