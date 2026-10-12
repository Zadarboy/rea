import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type { WasmComponentPort } from "../application/wasm/WasmComponentPort.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  WASM_COMPONENT_GRAMMAR,
  wasmComponentSchema,
  type InspectWasmComponentInput,
  type WasmComponent,
} from "../domain/wasm/wasmComponent.js";
import { decodeWasmComponent } from "./WasmComponentDecoder.js";
import { WasmComponentFormatFailure } from "./WasmComponentReader.js";

/** Bundled decoder identity; the admitted grammar is pinned separately. */
export const WASM_COMPONENT_PROVIDER_IDENTITY = {
  id: "wasm-component-binary",
  name: "REA WebAssembly component decoder",
  version: "1",
} as const;
const OPERATION = "inspect_wasm_component";
const INPUT_BYTES = 8 * 1024 * 1024;
const OUTPUT_BYTES = 8 * 1024 * 1024;

const isAbort = (cause: unknown, signal?: AbortSignal): boolean =>
  signal?.aborted === true ||
  (cause instanceof Error && cause.name === "AbortError");

const failureFor = (
  cause: unknown,
  path: string,
  signal?: AbortSignal,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  if (isAbort(cause, signal)) return new AnalysisCancelledError(OPERATION);
  if (cause instanceof WasmComponentFormatFailure)
    return cause.kind === "unsupported"
      ? new AnalysisUnsupportedTargetError(OPERATION, path, cause.message, {
          cause,
          ...(cause.message.includes("inspect_wasm_artifact")
            ? {
                remediationAction:
                  "Inspect core WebAssembly modules with inspect_wasm_artifact.",
              }
            : {}),
        })
      : new AnalysisInputError(OPERATION, { cause }, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: `Selected artifact ${path}: ${cause.message}`,
          },
        ]);
  if (cause instanceof ArtifactReaderFailure) {
    if (cause.reason === "integrity")
      return new AnalysisArtifactChangedError(OPERATION, path, cause.message, {
        cause,
      });
    if (cause.reason === "cancelled")
      return new AnalysisCancelledError(OPERATION);
    if (cause.reason === "limit")
      return new AnalysisResourceConstraintError(
        OPERATION,
        "file-size",
        cause.message,
        { maximum_input_bytes: INPUT_BYTES },
        { cause },
      );
    if (cause.reason === "path")
      return new AnalysisInputError(OPERATION, { cause }, [
        { path: ["path"], reason: "invalid_format", message: cause.message },
      ]);
  }
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
        cause,
      });
    if (
      ["ENOENT", "ENOTDIR", "ELOOP", "ENAMETOOLONG"].includes(
        String(cause.code),
      )
    )
      return new AnalysisInputError(OPERATION, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected artifact could not be read (${String(cause.code)}): ${path}.`,
        },
      ]);
  }
  return new ProviderAdapterError(
    WASM_COMPONENT_PROVIDER_IDENTITY.id,
    OPERATION,
    {
      cause,
      diagnostics: {
        path,
        reason: cause instanceof Error ? cause.message : String(cause),
      },
    },
  );
};

const LIMITATIONS = [
  "Decoding is structural against the pinned component-model Binary.md grammar. Type correctness, name uniqueness, index bounds and canonical ABI rules are not validated, so a decoded component can still be invalid.",
  "Embedded core modules are identified by byte range and SHA-256; only their import and export sections are read. No component or module is instantiated or executed.",
  "Lift and lower relationships follow index-space origins inside one component. Outer aliases, values and instantiated nested components are not traced.",
  "Value-section payloads are retained by type and byte range only.",
];

/** Read one selected component in process, without subprocesses, temporary files or execution. */
export class WasmComponentProvider implements WasmComponentPort {
  readonly identity = WASM_COMPONENT_PROVIDER_IDENTITY;

  async inspect(
    input: InspectWasmComponentInput,
    options?: ExecutionOptions,
  ): Promise<Result<WasmComponent, AnalysisError>> {
    try {
      const snapshot = await readStableArtifact(
        input.path,
        INPUT_BYTES,
        options?.signal,
      );
      options?.signal?.throwIfAborted();
      const decoded = await decodeWasmComponent(
        snapshot.bytes,
        options?.signal,
      );
      const invalidNames = decoded.components.some(
        (component) => component.names?.status === "invalid",
      );
      const report = {
        artifact: {
          path: input.path,
          sha256: snapshot.sha256,
          bytes: snapshot.bytes.length,
        },
        decoder: {
          id: WASM_COMPONENT_PROVIDER_IDENTITY.id,
          version: WASM_COMPONENT_PROVIDER_IDENTITY.version,
          grammar: WASM_COMPONENT_GRAMMAR.source,
          admitted_version: WASM_COMPONENT_GRAMMAR.version,
          admitted_layer: WASM_COMPONENT_GRAMMAR.layer,
        },
        validation: "not_performed",
        components: decoded.components,
        type_scopes: decoded.typeScopes,
        gated_features: decoded.features,
        coverage: {
          status: decoded.notDecoded.length === 0 ? "complete" : "partial",
          not_decoded: decoded.notDecoded,
        },
        limitations: [
          ...LIMITATIONS,
          ...(decoded.notDecoded.length === 0
            ? []
            : [
                "Some sections were not decoded (see coverage.not_decoded). Indices that sections in those sorts define afterwards are null because their positions are unknown.",
              ]),
          ...(invalidNames
            ? [
                "A component-name section could not be decoded completely; names decoded before the failure are retained.",
              ]
            : []),
        ],
      };
      if (Buffer.byteLength(JSON.stringify(report), "utf8") > OUTPUT_BYTES)
        throw new AnalysisResourceConstraintError(
          OPERATION,
          "transport",
          `Decoded component facts for ${input.path} exceed the inline output budget; no partial success is returned.`,
          { maximum_output_bytes: OUTPUT_BYTES },
        );
      const parsed = wasmComponentSchema.safeParse(report);
      if (!parsed.success)
        throw new AnalysisOutputError(
          OPERATION,
          "Component decoder produced invalid ranges or report values.",
          { cause: parsed.error },
        );
      options?.signal?.throwIfAborted();
      return ok(parsed.data);
    } catch (cause: unknown) {
      return err(failureFor(cause, input.path, options?.signal));
    }
  }
}
