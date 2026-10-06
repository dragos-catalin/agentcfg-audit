export { classify, discover } from "./discover.ts";
export { RULES, formatSarif, formatText } from "./report.ts";
export { scanAll, scanFile, type Report } from "./scan.ts";
export {
    DEFAULT_MANIFEST,
    createManifest,
    entries,
    generateKeys,
    hashContent,
    loadPrivateKey,
    parseManifest,
    parsePublicKey,
    verifyManifest,
    verifyOk,
    type Manifest,
    type ManifestEntry,
    type VerifyResult,
} from "./sign.ts";
export { stripJsonc } from "./structured.ts";
export { trustedKeys } from "./trust.ts";
export type { ConfigFile, Finding, Kind, Severity } from "./types.ts";
