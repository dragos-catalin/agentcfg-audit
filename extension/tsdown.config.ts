import { defineConfig } from "tsdown";

export default defineConfig({
    entry: ["src/extension.ts"],
    format: "cjs",
    platform: "node",
    target: "node22",
    dts: false,
    clean: true,
    deps: { neverBundle: ["vscode"] },
});
