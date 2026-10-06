# Changelog

## 0.2.0

- Editor gate: VS Code extension `agentcfg-gate` (`extension/`) verifies each workspace folder's agent config on startup and on change, and locks it out of the Local agent (workspace settings, restored on unlock) when verification fails or an unsigned config has findings at or above a severity.
- `trustedKeys` moved from the CLI into `src/trust.ts` and exported; CLI behaviour unchanged.
- CI packages the extension; releases attach `agentcfg-gate.vsix`.

## 0.1.0

- `scan` with rules ACA001–ACA015 over AGENTS.md, CLAUDE.md, instructions, skills (and their scripts), hooks, settings and mcp.json; text, JSON and SARIF output.
- `keygen`, `sign` and `verify`: ed25519-signed `agentcfg.lock.json` over SHA-256 of each config file (CRLF normalised); trust only from keys configured outside the repository.
