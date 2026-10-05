import {
    createHash,
    createPrivateKey,
    createPublicKey,
    generateKeyPairSync,
    sign,
    verify,
    type KeyObject,
} from "node:crypto";
import { readFileSync } from "node:fs";
import type { ConfigFile, Kind } from "./types.ts";

export const MANIFEST_VERSION = 1;
export const DEFAULT_MANIFEST = "agentcfg.lock.json";

export interface ManifestEntry {
    path: string;
    kind: Kind;
    sha256: string;
}

export interface Manifest {
    version: number;
    created: string;
    signer: { alg: "ed25519"; publicKey: string; fingerprint: string };
    files: ManifestEntry[];
    signature: string;
}

/** CRLF -> LF before hashing, so a Windows checkout with autocrlf matches the signed bytes. */
export function hashContent(buf: Buffer): string {
    const text = buf.toString("utf8").replace(/\r\n/g, "\n");
    return createHash("sha256").update(text, "utf8").digest("hex");
}

export function canonical(v: unknown): string {
    if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
    if (v && typeof v === "object") {
        const o = v as Record<string, unknown>;
        return `{${Object.keys(o)
            .filter((k) => o[k] !== undefined)
            .sort()
            .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
            .join(",")}}`;
    }
    return JSON.stringify(v);
}

export function publicKeyB64(key: KeyObject): string {
    const pub = key.type === "public" ? key : createPublicKey(key);
    return pub.export({ format: "der", type: "spki" }).toString("base64");
}

export function fingerprint(publicKeyBase64: string): string {
    return `SHA256:${createHash("sha256").update(Buffer.from(publicKeyBase64, "base64")).digest("base64url").slice(0, 32)}`;
}

export function generateKeys(): { privatePem: string; publicPem: string; fingerprint: string } {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    return {
        privatePem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
        publicPem: publicKey.export({ format: "pem", type: "spki" }).toString(),
        fingerprint: fingerprint(publicKeyB64(publicKey)),
    };
}

export function loadPrivateKey(pem: string): KeyObject {
    const k = createPrivateKey(pem);
    if (k.asymmetricKeyType !== "ed25519") throw new Error(`expected an ed25519 key, got ${k.asymmetricKeyType}`);
    return k;
}

/** A trusted key: PEM text, or a bare base64 SPKI string as stored in a manifest. */
export function parsePublicKey(text: string): string {
    const t = text.trim();
    const k = t.startsWith("-----BEGIN")
        ? createPublicKey(t)
        : createPublicKey({ key: Buffer.from(t, "base64"), format: "der", type: "spki" });
    if (k.asymmetricKeyType !== "ed25519") throw new Error(`expected an ed25519 key, got ${k.asymmetricKeyType}`);
    return publicKeyB64(k);
}

const payload = (m: Omit<Manifest, "signature">): Buffer => Buffer.from(canonical(m), "utf8");

export function entries(files: ConfigFile[], read: (abs: string) => Buffer = (p) => readFileSync(p)): ManifestEntry[] {
    return files.map((f) => ({ path: f.path, kind: f.kind, sha256: hashContent(read(f.abs)) }));
}

export function createManifest(files: ManifestEntry[], privateKey: KeyObject, now = new Date()): Manifest {
    const pub = publicKeyB64(privateKey);
    const body: Omit<Manifest, "signature"> = {
        version: MANIFEST_VERSION,
        created: now.toISOString(),
        signer: { alg: "ed25519", publicKey: pub, fingerprint: fingerprint(pub) },
        files: [...files].sort((a, b) => (a.path < b.path ? -1 : 1)),
    };
    return { ...body, signature: sign(null, payload(body), privateKey).toString("base64") };
}

export function parseManifest(text: string): Manifest {
    const m = JSON.parse(text) as Partial<Manifest>;
    if (m.version !== MANIFEST_VERSION) throw new Error(`unsupported manifest version ${String(m.version)}`);
    if (!m.signer?.publicKey || !m.signature || !Array.isArray(m.files))
        throw new Error("manifest is missing signer, signature or files");
    return m as Manifest;
}

export interface VerifyResult {
    signatureValid: boolean;
    trusted: boolean;
    fingerprint: string;
    changed: string[];
    added: string[];
    removed: string[];
}

export function verifyManifest(m: Manifest, live: ManifestEntry[], trustedKeys: string[]): VerifyResult {
    const { signature, ...body } = m;
    let signatureValid = false;
    try {
        const key = createPublicKey({ key: Buffer.from(m.signer.publicKey, "base64"), format: "der", type: "spki" });
        signatureValid =
            key.asymmetricKeyType === "ed25519" && verify(null, payload(body), key, Buffer.from(signature, "base64"));
    } catch {
        signatureValid = false;
    }
    const signed = new Map(m.files.map((f) => [f.path, f.sha256]));
    const now = new Map(live.map((f) => [f.path, f.sha256]));
    return {
        signatureValid,
        trusted: trustedKeys.includes(m.signer.publicKey),
        fingerprint: fingerprint(m.signer.publicKey),
        changed: [...now].filter(([p, h]) => signed.has(p) && signed.get(p) !== h).map(([p]) => p),
        added: [...now.keys()].filter((p) => !signed.has(p)),
        removed: [...signed.keys()].filter((p) => !now.has(p)),
    };
}

export function verifyOk(r: VerifyResult): boolean {
    return r.signatureValid && r.trusted && r.changed.length + r.added.length + r.removed.length === 0;
}
