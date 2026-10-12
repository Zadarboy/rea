import {
  inspectWasmArtifactInputSchema,
  wasmArtifactSchema,
} from "../../domain/wasm/wasmArtifact.js";
import {
  inspectWasmComponentInputSchema,
  wasmComponentSchema,
} from "../../domain/wasm/wasmComponent.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import {
  analysisDetailSchema,
  analysisDetailOutputSchemaOf,
} from "../analysisDetail.js";
import { wasmArtifactSummaryViewResultSchema } from "../../domain/analysisView/analysisView.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Delivery selection does not change the provider input or original Evidence. */
export const wasmArtifactInspectionInputSchema =
  inspectWasmArtifactInputSchema.extend({
    detail: analysisDetailSchema.unwrap().optional(),
  });
/** Optional caller-supplied WABT capability with target-free CLI/MCP parity. */
export const INSPECT_WASM_ARTIFACT_CONTRACT = {
  name: "inspect_wasm_artifact",
  ...toolContractMetadata("inspect_wasm_artifact"),
  kind: "artifact-provider",
  description:
    'Validate an explicit local WASM artifact with caller-supplied WABT 1.0.42. Omitted or complete detail returns exact byte SHA-256, sections, upstream import/export WAT forms and decoded WAT inline as Evidence. For counts, validation and WAT identity without WAT text, pass detail: "summary" on this first call; it retains the complete original Evidence and returns the same typed summary as inspect_analysis_view, avoiding oversized complete delivery. Read exact imports/exports or WAT pages with inspect_analysis_view using normalized_result.parent_evidence_id. Delivery selection does not change analysis, provider inputs or source identity. Optionally associate selected JavaScript glue literals with explicit local candidates while preserving ambiguous URL/basename matches. Configure absolute REA_WABT_BIN_DIRECTORY. No installation, implicit fetch, WASM execution or original-source claim.',
  inputSchema: wasmArtifactInspectionInputSchema,
  outputSchema: analysisDetailOutputSchemaOf(
    wasmArtifactSchema,
    wasmArtifactSummaryViewResultSchema,
  ),
  examples: [
    {
      title: "Inspect a selected local WASM module",
      input: {
        path: "/artifacts/module.wasm",
        glue_paths: [],
        candidate_paths: [],
      },
    },
  ],
} as const satisfies ToolContract;

/** Keep the public catalog in its existing order, using its named contract. */
export const WASM_TOOL_CONTRACTS = [INSPECT_WASM_ARTIFACT_CONTRACT] as const;

/** Bundled in-process component decoder; independent of WABT and binary sessions. */
export const INSPECT_WASM_COMPONENT_CONTRACT = {
  name: "inspect_wasm_component",
  ...toolContractMetadata("inspect_wasm_component"),
  kind: "artifact-provider",
  description:
    "Decode an explicit local WebAssembly component (component-model binary version 0xd, layer 1) in process. Returns the file SHA-256, section ranges, typed imports and exports with name attributes, type definitions, embedded core modules (range, SHA-256, import/export names), instances, aliases and canonical definitions inline as Evidence. Canonical lifts are traced to the core exports they wrap, and lowers to their imports and the core imports they are bound to. Reports per-section coverage and the gated features observed; sections it cannot decode are listed and later indices in affected sorts become null. Structural decoding only: it never validates, instantiates or executes the component or its modules and needs no WABT or other tools. Core modules (layer 0) use inspect_wasm_artifact. Files are bounded to 8 MiB.",
  inputSchema: inspectWasmComponentInputSchema,
  outputSchema: evidenceResultOf(wasmComponentSchema),
  examples: [
    {
      title: "Decode a selected local component",
      input: { path: "/artifacts/component.wasm" },
    },
  ],
} as const satisfies ToolContract;

export const WASM_COMPONENT_TOOL_CONTRACTS = [
  INSPECT_WASM_COMPONENT_CONTRACT,
] as const;
