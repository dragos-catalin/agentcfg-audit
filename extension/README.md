# agentcfg gate

Checks a workspace's agent config — `AGENTS.md`, `CLAUDE.md`, `*.instructions.md`, skills, hooks, `mcp.json`, `.vscode/settings.json` — against a signed `agentcfg.lock.json` made with [agentcfg-audit](https://github.com/dragos-catalin/agentcfg-audit). If it does not verify, the gate turns that config off for VS Code's Local agent until you unlock it.

- **Verified**: signature valid, signer in your trusted keys, no file changed, added or removed.
- **Locked**: anything else. Workspace settings stop chat from loading instructions, `AGENTS.md`/`CLAUDE.md`, prompts, custom agents, skills and hooks, and stop MCP servers from autostarting. Unlocking restores your previous values.
- **Unsigned**: no manifest. By default the config is scanned and locked when a finding is `high` or worse.

## Settings (user settings only)

- `agentcfgGate.trustedKeys`: trusted signer public keys. Also read: `AGENTCFG_TRUSTED_KEYS`, `~/.config/agentcfg/trusted_keys`.
- `agentcfgGate.unsignedPolicy`: `scan` (default), `lock` or `warn`.
- `agentcfgGate.lockOnSeverity`: `high` by default.

All three are application-scoped, so a repository cannot set them for itself.

## Limits

It activates on `*` on purpose: that is the earliest moment an extension can run, and the gate has to decide before chat reads the config. The check is a few file reads and hashes.

The gate races VS Code's own loading of customizations on the very first open. Open unknown repositories in Restricted Mode and grant trust after the gate shows its verdict. It governs only the Local agent; for Copilot CLI, Claude or Codex run `agentcfg-audit verify` as the first hook.

MIT licensed.
