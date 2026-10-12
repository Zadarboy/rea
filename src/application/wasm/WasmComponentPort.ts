import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Result } from "../../domain/result.js";
import type {
  InspectWasmComponentInput,
  WasmComponent,
} from "../../domain/wasm/wasmComponent.js";

/** Replaceable offline component decoder with no instantiation or execution authority. */
export interface WasmComponentPort {
  readonly identity: ProviderIdentity;
  inspect(
    input: InspectWasmComponentInput,
    options?: ExecutionOptions,
  ): Promise<Result<WasmComponent, AnalysisError>>;
}
