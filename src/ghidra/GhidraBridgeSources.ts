/** Required packaged sources, selected by their runtime role rather than order. */
export const GHIDRA_BRIDGE_SOURCES = Object.freeze({
  workspace: "ReaGhidraWorkspace.java",
  reconstruction: "ReaGhidraReconstruction.java",
  bridge: "ReaGhidraBridge.java",
  bundleActivator: "ReaGhidraBundleActivator.java",
  extensions: "ReaGhidraExtensions.java",
  prepareCom: "ReaGhidraPrepareCom.java",
  prepareRaw: "ReaGhidraPrepareRaw.java",
  applySeeds: "ReaGhidraApplySeeds.java",
  analysisOptions: "ReaGhidraAnalysisOptions.java",
  noReturnFix: "ReaGhidraNoReturnFix.java",
  mipsSoftFloat: "ReaGhidraMipsSoftFloat.java",
} as const);
