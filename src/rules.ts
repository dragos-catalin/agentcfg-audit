import type { ConfigFile, Finding, Severity } from "./types.ts";

/**
 * Rules for text an agent reads as instructions (AGENTS.md, SKILL.md, rules)
 * and for command strings inside hooks and MCP server definitions.
 * Each pattern is matched per line; ids are stable and documented in the README.
 */
interface LineRule {
    id: string;
    severity: Severity;
    /** Severity when the line is a command that runs (hook, MCP server). */
    commandSeverity?: Severity;
    message: string;
    pattern: RegExp;
    /** The line is not a finding when this also matches (protective phrasing). */
    unless?: RegExp;
}

export const LINE_RULES: readonly LineRule[] = [
    {
        id: "ACA003",
        severity: "high",
        message: "Prompt-injection phrasing: tells the agent to override or hide from its instructions",
        pattern:
            /\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|system)\s+(instructions|prompts?|rules)\b|\b(do\s+not|don'?t|never)\s+(tell|inform|mention\s+(this\s+)?to|show)\s+(the\s+)?user\b/i,
    },
    {
        id: "ACA003",
        severity: "medium",
        message: "Tells the agent to act without the user's knowledge",
        pattern:
            /\b(silently|secretly|quietly)\s+(run|execute|send|upload|install|delete)\b|\bwithout\s+(asking|telling|notifying)\s+(the\s+)?user\b/i,
        // "Never deploy without asking the user" is a safeguard, not an injection.
        unless: /\b(never|not|don'?t|must\s+not|avoid|ask\s+(first|before))\b[^.]*\bwithout\s+(asking|telling|notifying)\b/i,
    },
    {
        id: "ACA004",
        severity: "high",
        commandSeverity: "critical",
        message: "Downloads and executes remote code",
        pattern:
            /\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n]*\|\s*(iex|Invoke-Expression)\b|\b(iex|Invoke-Expression)\s*\(?\s*\(?\s*(New-Object\s+Net\.WebClient|iwr|irm|Invoke-WebRequest)/i,
    },
    {
        id: "ACA005",
        severity: "high",
        message: "Reads credentials or key material",
        pattern:
            /(~|\$HOME|%USERPROFILE%|\$env:USERPROFILE)[\\/]\.(ssh|aws|gnupg|docker|kube|npmrc|netrc|git-credentials)\b|\bid_(rsa|ed25519|ecdsa)\b|\.aws[\\/]credentials\b|\bsecurity\s+find-generic-password\b|\bLogin\s+Data\b|\bcat\s+[^\n]*\.env\b/i,
    },
    {
        id: "ACA006",
        severity: "high",
        commandSeverity: "critical",
        message: "Sends data to a known exfiltration or tunnelling endpoint",
        pattern:
            /\b(webhook\.site|requestbin\.(com|net)|pipedream\.net|ngrok(-free)?\.(io|app)|trycloudflare\.com|interact\.sh|oast\.(fun|pro|live|site|online|me)|burpcollaborator\.net|pastebin\.com|transfer\.sh|discord(app)?\.com\/api\/webhooks)\b/i,
    },
    {
        id: "ACA007",
        severity: "medium",
        commandSeverity: "high",
        message: "Decodes and runs an encoded payload",
        pattern:
            /\bbase64\s+(-d|--decode)\b[^\n]*\|\s*(ba|z)?sh\b|\bFromBase64String\b|-(e|enc|EncodedCommand)\s+[A-Za-z0-9+/=]{40,}|\beval\s*\(\s*atob\s*\(/i,
    },
    {
        id: "ACA008",
        severity: "critical",
        message: "Contains a literal secret",
        pattern:
            /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b|\bsk-(ant-|proj-)?[A-Za-z0-9_-]{32,}\b|\bAKIA[0-9A-Z]{16}\b|\bxox[abpors]-[A-Za-z0-9-]{10,}\b|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    },
    {
        id: "ACA009",
        severity: "medium",
        commandSeverity: "high",
        message: "Disables a safety control (permission prompts, TLS verification, sandbox)",
        pattern:
            /--dangerously-skip-permissions\b|--no-sandbox\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|\bcurl\b[^\n]*\s(-k|--insecure)\b|\bgit\s+config\s+[^\n]*http\.sslVerify\s+false/i,
    },
];

/** Invisible characters that hide text from a human reviewer but not from a model. */
const HIDDEN: { re: RegExp; severity: Severity; what: string }[] = [
    { re: /[\u{E0000}-\u{E007F}]/u, severity: "critical", what: "Unicode tag characters (invisible ASCII smuggling)" },
    { re: /[\u202A-\u202E\u2066-\u2069]/u, severity: "critical", what: "bidirectional override characters" },
    { re: /[\u200B-\u200D\u2060\u180E]/u, severity: "high", what: "zero-width characters" },
    { re: /\uFEFF/u, severity: "high", what: "a byte-order mark inside the text" },
];

const IMPERATIVE =
    /\b(you\s+must|always|never|ignore|run|execute|send|upload|curl|fetch|read|delete|do\s+not|don'?t|instead)\b/i;

function excerpt(line: string): string {
    const t = line.trim();
    return t.length > 120 ? `${t.slice(0, 117)}...` : t;
}

/** Text rules over `text`, reporting 1-based lines starting at `firstLine`. */
export function scanText(
    file: string,
    text: string,
    opts: { asCommand?: boolean; firstLine?: number } = {},
): Finding[] {
    const out: Finding[] = [];
    const first = opts.firstLine ?? 1;
    const lines = text.split(/\r?\n/);
    lines.forEach((line, i) => {
        const ln = first + i;
        for (const r of LINE_RULES) {
            if (r.pattern.test(line) && !r.unless?.test(line)) {
                out.push({
                    rule: r.id,
                    severity: (opts.asCommand && r.commandSeverity) || r.severity,
                    file,
                    line: ln,
                    message: r.message,
                    excerpt: excerpt(line),
                });
            }
        }
        // Skip the BOM rule for a leading BOM: editors write it, it hides nothing.
        const body = i === 0 ? line.replace(/^\uFEFF/, "") : line;
        for (const h of HIDDEN) {
            if (h.re.test(body)) {
                out.push({
                    rule: "ACA001",
                    severity: h.severity,
                    file,
                    line: ln,
                    message: `Hidden text: ${h.what}`,
                });
            }
        }
    });
    return out;
}

/** Markdown-only: HTML comments are invisible when rendered but the model reads them. */
export function scanMarkdownComments(file: string, text: string): Finding[] {
    const out: Finding[] = [];
    const re = /<!--([\s\S]*?)-->/g;
    for (let m = re.exec(text); m; m = re.exec(text)) {
        const body = m[1] ?? "";
        // Generated-section markers (BEGIN:x / END:x) are not instructions.
        if (!IMPERATIVE.test(body) || /^\s*(BEGIN|END)[:\s]/.test(body)) continue;
        out.push({
            rule: "ACA002",
            severity: "medium",
            file,
            line: lineAt(text, m.index),
            message: "Instruction-like text inside an HTML comment (hidden when rendered, read by the model)",
            excerpt: excerpt(body),
        });
    }
    return out;
}

export function lineAt(text: string, index: number): number {
    let n = 1;
    for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
    return n;
}

/** First line containing `needle` (JSON keys/values), else 1. */
export function lineOf(text: string, needle: string): number {
    const i = text.indexOf(needle);
    return i < 0 ? 1 : lineAt(text, i);
}

export type { ConfigFile };
