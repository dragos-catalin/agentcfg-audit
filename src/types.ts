export type Kind = "instructions" | "skill" | "script" | "settings" | "hooks" | "mcp";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export const SEVERITIES: readonly Severity[] = ["info", "low", "medium", "high", "critical"];

export interface ConfigFile {
    /** Path relative to the scan root, forward slashes. */
    path: string;
    abs: string;
    kind: Kind;
}

export interface Finding {
    rule: string;
    severity: Severity;
    file: string;
    line: number;
    message: string;
    excerpt?: string;
}

export function isSeverity(s: string): s is Severity {
    return (SEVERITIES as readonly string[]).includes(s);
}

export function atLeast(s: Severity, min: Severity): boolean {
    return SEVERITIES.indexOf(s) >= SEVERITIES.indexOf(min);
}
