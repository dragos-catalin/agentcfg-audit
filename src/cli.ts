#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { parseArgs } from "node:util";
import { discover } from "./discover.ts";
import { formatSarif, formatText } from "./report.ts";
import { scanAll } from "./scan.ts";
import {
    DEFAULT_MANIFEST,
    createManifest,
    entries,
    generateKeys,
    loadPrivateKey,
    parseManifest,
    verifyManifest,
    verifyOk,
} from "./sign.ts";
import { trustedKeys } from "./trust.ts";
import { atLeast, isSeverity } from "./types.ts";

export const VERSION = "0.2.0";

const HELP = `agentcfg-audit ${VERSION} — scan and sign agent configuration

Usage:
  agentcfg-audit scan   [paths...] [--json | --sarif] [--fail-on <severity>]
  agentcfg-audit keygen [--out <dir>]
  agentcfg-audit sign   [paths...] --key <private.pem> [--manifest <file>]
  agentcfg-audit verify [paths...] [--trust <key>...] [--manifest <file>] [--json]

  scan     find AGENTS.md, CLAUDE.md, *.instructions.md, SKILL.md (+ its scripts),
           hooks, Claude/VS Code settings and mcp.json under paths (default .)
           and report risky content
  keygen   write an ed25519 key pair (private key 0600, never commit it)
  sign     hash every config file found and write a signed manifest
  verify   check the manifest signature, that the signer is trusted, and that
           no config file was changed, added or removed since signing

Options:
  --fail-on   lowest severity that fails scan: info|low|medium|high|critical (default high)
  --manifest  manifest path (default ${DEFAULT_MANIFEST})
  --key       private key PEM (or env AGENTCFG_SIGNING_KEY with the PEM text)
  --trust     trusted public key: PEM file, or base64 SPKI; repeatable. Also read from
              env AGENTCFG_TRUSTED_KEYS and ~/.config/agentcfg/trusted_keys (one per line).
              The repository's own manifest never makes its signer trusted.

Exit codes: 0 ok, 1 findings at/above --fail-on or verification failed, 2 usage error.`;

async function main(argv: string[]): Promise<number> {
    const { values, positionals } = parseArgs({
        args: argv,
        allowPositionals: true,
        options: {
            json: { type: "boolean", default: false },
            sarif: { type: "boolean", default: false },
            "fail-on": { type: "string", default: "high" },
            out: { type: "string", default: "." },
            key: { type: "string" },
            manifest: { type: "string", default: DEFAULT_MANIFEST },
            trust: { type: "string", multiple: true },
            help: { type: "boolean", short: "h", default: false },
            version: { type: "boolean", short: "v", default: false },
        },
    });
    if (values.version) {
        console.log(VERSION);
        return 0;
    }
    const [cmd, ...rest] = positionals;
    if (values.help || !cmd || !["scan", "keygen", "sign", "verify"].includes(cmd)) {
        console.log(HELP);
        return values.help ? 0 : 2;
    }
    const targets = rest.length ? rest : ["."];

    if (cmd === "scan") {
        const failOn = values["fail-on"];
        if (!isSeverity(failOn)) {
            console.error(`agentcfg-audit: --fail-on must be one of info, low, medium, high, critical`);
            return 2;
        }
        const report = scanAll(discover(targets));
        if (values.sarif) console.log(formatSarif(report, VERSION));
        else if (values.json) console.log(JSON.stringify(report.findings, null, 2));
        else console.log(formatText(report));
        return report.findings.some((f) => atLeast(f.severity, failOn)) ? 1 : 0;
    }

    if (cmd === "keygen") {
        const priv = join(values.out, "agentcfg-signing.key");
        const pub = join(values.out, "agentcfg-signing.pub");
        if (existsSync(priv)) {
            console.error(`agentcfg-audit: ${priv} exists; refusing to overwrite`);
            return 2;
        }
        const k = generateKeys();
        mkdirSync(values.out, { recursive: true });
        writeFileSync(priv, k.privatePem, { mode: 0o600 });
        writeFileSync(pub, k.publicPem);
        console.log(`wrote ${priv} (keep secret) and ${pub}\nfingerprint ${k.fingerprint}`);
        return 0;
    }

    if (cmd === "sign") {
        const pem = values.key ? readFileSync(values.key, "utf8") : process.env["AGENTCFG_SIGNING_KEY"];
        if (!pem) {
            console.error("agentcfg-audit: sign needs --key <private.pem> or AGENTCFG_SIGNING_KEY");
            return 2;
        }
        const files = discover(targets);
        const m = createManifest(entries(files), loadPrivateKey(pem));
        mkdirSync(dirname(values.manifest), { recursive: true });
        writeFileSync(values.manifest, `${JSON.stringify(m, null, 2)}\n`);
        console.log(`signed ${files.length} file(s) into ${values.manifest} (${m.signer.fingerprint})`);
        return 0;
    }

    // verify
    if (!existsSync(values.manifest)) {
        console.error(`agentcfg-audit: ${values.manifest} not found; run "agentcfg-audit sign" first`);
        return 2;
    }
    const m = parseManifest(readFileSync(values.manifest, "utf8"));
    const r = verifyManifest(m, entries(discover(targets)), trustedKeys(values.trust ?? []));
    if (values.json) console.log(JSON.stringify({ ok: verifyOk(r), ...r }, null, 2));
    else {
        console.log(
            `signer ${r.fingerprint}: signature ${r.signatureValid ? "valid" : "INVALID"}, ${r.trusted ? "trusted" : "NOT TRUSTED"}`,
        );
        for (const p of r.changed) console.log(`  changed  ${p}`);
        for (const p of r.added) console.log(`  added    ${p}`);
        for (const p of r.removed) console.log(`  removed  ${p}`);
        console.log(verifyOk(r) ? "ok" : "verification failed");
    }
    return verifyOk(r) ? 0 : 1;
}

main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e: unknown) => {
        console.error(`agentcfg-audit: ${(e as Error).message}`);
        process.exit(2);
    },
);
