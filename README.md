# agentcfg-audit

Scan and sign the files that tell your coding agent what to do.

## Problem

`AGENTS.md`, `CLAUDE.md`, `*.instructions.md`, `SKILL.md`, hooks and `mcp.json` are code. The agent reads them as instructions and runs what they say with your permissions, often before you have looked at anything:

- Hooks run on `SessionStart` and after every tool call. CVE-2025-59536 showed repository hooks running before the trust prompt in Claude Code.
- A cloned repo's `mcp.json` starts servers, and `npx -y some-server` runs whatever was published last night.
- Skills are shared like packages. The ToxicSkills study found flaws in 36.8 % of 3,984 public skills and 76 that were plainly malicious.
- Text the model reads but a reviewer does not see: Unicode tag characters, bidi overrides, zero-width characters and HTML comments.

Nobody runs a linter over these files, and nothing proves the copy on your disk is the one someone reviewed.

## Approach

Two commands, no runtime dependencies:

```text
agentcfg-audit scan              # find agent config under . and report risky content
agentcfg-audit sign --key k.pem  # hash every config file into a signed agentcfg.lock.json
agentcfg-audit verify            # signature valid + signer trusted + nothing changed
```

`scan` finds the files by name (it knows the layouts of Copilot, Claude Code, Cursor, Windsurf, Gemini and VS Code), including scripts shipped inside a skill folder, and applies these rules:

| Rule   | Default severity         | What it catches                                                                     |
| ------ | ------------------------ | ----------------------------------------------------------------------------------- |
| ACA001 | high / critical          | Hidden Unicode: tag characters, bidi overrides, zero-width characters, inner BOM    |
| ACA002 | medium                   | Instruction-like text inside an HTML comment                                        |
| ACA003 | high / medium            | "Ignore previous instructions", "don't tell the user", acting silently              |
| ACA004 | high, critical in a hook | `curl … \| sh`, `iwr … \| iex` and similar remote code execution                    |
| ACA005 | high                     | Reads `~/.ssh`, `~/.aws/credentials`, browser login stores, `.env`                  |
| ACA006 | high, critical in a hook | Known exfiltration and tunnel endpoints (webhook.site, ngrok, interact.sh, …)       |
| ACA007 | medium, high in a hook   | Decode-and-run payloads (`base64 -d \| sh`, `-EncodedCommand`, `eval(atob(…))`)     |
| ACA008 | critical                 | Literal secrets (GitHub, OpenAI/Anthropic, AWS, Slack tokens, private keys)         |
| ACA009 | medium, high in a hook   | Disabled safety controls (`--dangerously-skip-permissions`, TLS verification off)   |
| ACA010 | low, medium on start     | Every hook command, so you see what runs automatically                              |
| ACA011 | high / medium            | `bypassPermissions`, `Bash` allow-all, VS Code `chat.tools.autoApprove`, all MCP on |
| ACA012 | medium                   | MCP server run through `npx`/`uvx`/`pnpm dlx` without a pinned version              |
| ACA013 | medium                   | MCP server over plain HTTP to a remote host                                         |
| ACA014 | low                      | `SKILL.md` without `name` and `description`                                         |
| ACA015 | medium                   | Skill that pre-approves an unrestricted shell in `allowed-tools`                    |

Output is text, `--json` or `--sarif` (GitHub code scanning). `scan` exits 1 when a finding is at or above `--fail-on` (default `high`).

`sign` writes `agentcfg.lock.json`: path, kind and SHA-256 of every config file (CRLF normalised), signed with an ed25519 key over canonical JSON. `verify` fails when the signature is wrong, when the signer is not in your trusted keys, or when any file was changed, added or removed since signing.

## Use

```text
npx @codai/agentcfg-audit scan
npx @codai/agentcfg-audit keygen --out ~/.config/agentcfg     # once; never commit the .key
npx @codai/agentcfg-audit sign --key ~/.config/agentcfg/agentcfg-signing.key
npx @codai/agentcfg-audit verify --trust ~/.config/agentcfg/agentcfg-signing.pub
```

Trusted keys come from `--trust` (PEM file or base64), `AGENTCFG_TRUSTED_KEYS`, and `~/.config/agentcfg/trusted_keys` (one per line). In CI:

```yaml
- run: npx @codai/agentcfg-audit scan --sarif > agentcfg.sarif
- uses: github/codeql-action/upload-sarif@v4
  with: { sarif_file: agentcfg.sarif }
- run: npx @codai/agentcfg-audit verify
  env: { AGENTCFG_TRUSTED_KEYS: ${{ vars.AGENTCFG_TRUSTED_KEYS }} }
```

Run `verify` before opening a cloned repository in an agent, or as the first hook, so unsigned or changed config is caught before anything in it runs.

## Threat model

**Protects against**

- A malicious or compromised contributor adding instructions, hooks or MCP servers that exfiltrate data or run remote code.
- Content hidden from human review (tag characters, bidi, zero-width, HTML comments).
- Config that silently drifts after review: an edited hook, a new skill, a removed guard rule.
- A forged manifest: the repository cannot make its own signer trusted. Trust comes only from keys you configure outside the repo.

**Does not protect against**

- A determined attacker who writes instructions in plain prose the rules do not recognise. Pattern rules raise the cost; they are not a proof of safety. Read what you sign.
- An unpinned MCP server or package whose behaviour changes without its config changing. Pin versions (ACA012) and use [mcp-lock](https://github.com/dragoscv/mcp-lock) for tool descriptions.
- A stolen signing key. Keep it out of the repo, rotate it by replacing the trusted key, and re-sign.
- Config outside the scanned paths. Pass `~/.claude`, `~/.copilot` or other user-level directories explicitly.
- Files larger than 2 MB, which are skipped.

## Roadmap

- Editor gate: a VS Code extension that runs `verify` before a workspace's agent config loads.
- Sigstore keyless signing as an alternative to local keys.
- Rule packs from a URL, with a pinned hash.

## Status

0.1: scan, sign and verify work and are tested. Rule ids are stable; severities may move before 1.0. Part of the agent tooling at [dragoscatalin.ro/lab](https://dragoscatalin.ro/lab). MIT licensed.
