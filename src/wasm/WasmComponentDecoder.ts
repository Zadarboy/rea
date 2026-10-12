import { createHash } from "node:crypto";

import {
  WASM_COMPONENT_GRAMMAR,
  type DecodedComponent,
  type GatedFeature,
} from "../domain/wasm/wasmComponent.js";
import type {
  ComponentSort,
  TypeScope,
} from "../domain/wasm/wasmComponentTypes.js";
import {
  isCoreWasmModule,
  readWasmPreamble,
} from "../domain/wasm/wasmPreamble.js";
import { decodeCanon } from "./WasmComponentCanons.js";
import { ComponentIndexSpaces } from "./WasmComponentIndexSpaces.js";
import {
  aliasOrigin,
  decodeCoreInstance,
  decodeExport,
  decodeInstance,
  decodeStart,
} from "./WasmComponentDefinitions.js";
import { decodeCustomSection } from "./WasmComponentNames.js";
import {
  WasmComponentFormatFailure,
  WasmComponentReader,
} from "./WasmComponentReader.js";
import { resolveCanonRelationships } from "./WasmComponentRelationships.js";
import type { TypeDecodeContext } from "./WasmComponentTypeContext.js";
import {
  decodeAlias,
  decodeComponentType,
  decodeExternType,
  decodeNameAttributes,
  decodeValType,
} from "./WasmComponentTypes.js";
import {
  coreModuleVersion,
  decodeCoreModuleInterface,
} from "./WasmCoreModuleInterface.js";
import { decodeCoreType } from "./WasmCoreTypes.js";

/** Bounds component nesting; deeper components are reported as not decoded. */
export const MAX_COMPONENT_DEPTH = 16;
const SECTIONS_PER_YIELD = 64;

const SECTION_KINDS = [
  "custom",
  "core module",
  "core instance",
  "core type",
  "component",
  "instance",
  "alias",
  "type",
  "canon",
  "start",
  "import",
  "export",
  "value",
] as const;

/**
 * Sorts whose index-space counts become unknown when a section is not fully
 * decoded; `all` when the sort varies per entry. Core module and component
 * sections add their single index before anything inside can fail.
 */
const SECTION_SORTS: Readonly<
  Record<number, readonly ComponentSort[] | "all">
> = {
  0: [],
  1: [],
  2: ["core instance"],
  3: ["core type"],
  4: [],
  5: ["instance"],
  6: "all",
  7: ["type"],
  8: ["func", "core func"],
  9: ["value"],
  10: "all",
  11: "all",
  12: ["value"],
};

interface Range {
  start: number;
  end: number;
}

/** Facts produced by decoding one selected component. */
export interface WasmComponentDecoding {
  readonly components: DecodedComponent[];
  readonly typeScopes: TypeScope[];
  readonly features: GatedFeature[];
  readonly notDecoded: { component: number; range: Range; reason: string }[];
}

interface DecodeState {
  readonly bytes: Uint8Array;
  readonly components: DecodedComponent[];
  readonly types: TypeDecodeContext;
  readonly notDecoded: WasmComponentDecoding["notDecoded"];
  readonly signal: AbortSignal | undefined;
  sectionsSinceYield: number;
}

/** Placement of one component scope inside the selected file. */
interface ComponentPlacement {
  readonly range: Range;
  readonly parent: number | null;
  readonly index: number | null;
  readonly depth: number;
}

/** Everything one section decoder may read or extend. */
interface SectionContext {
  readonly state: DecodeState;
  readonly component: DecodedComponent;
  readonly spaces: ComponentIndexSpaces;
  readonly depth: number;
}

const sha256 = (bytes: Uint8Array, range: Range): string =>
  createHash("sha256")
    .update(bytes.subarray(range.start, range.end))
    .digest("hex");

/**
 * Admitted component preamble, or a typed failure naming the observed bytes.
 * A core module (layer 0) is unsupported here and points to the WABT lane.
 */
export const readComponentPreamble = (
  bytes: Uint8Array,
  start: number,
  end: number,
): void => {
  if (end - start < 8)
    throw new WasmComponentFormatFailure(
      "malformed",
      start,
      "Truncated WebAssembly preamble",
    );
  const preamble = readWasmPreamble(bytes, start, end);
  if (preamble === undefined)
    throw new WasmComponentFormatFailure(
      "unsupported",
      start,
      "Not a WebAssembly binary (missing \\0asm magic)",
    );
  if (isCoreWasmModule(preamble))
    throw new WasmComponentFormatFailure(
      "unsupported",
      start,
      "Core WebAssembly module (layer 0), not a component; use inspect_wasm_artifact",
    );
  const { version, layer } = preamble;
  if (
    version !== WASM_COMPONENT_GRAMMAR.version ||
    layer !== WASM_COMPONENT_GRAMMAR.layer
  )
    throw new WasmComponentFormatFailure(
      "unsupported",
      start + 4,
      `Component binary version 0x${version.toString(16)} layer 0x${layer.toString(16)} is not admitted; only version 0xd layer 0x1 is decoded`,
    );
};

const emptyComponent = (
  id: number,
  placement: ComponentPlacement,
  digest: string,
): DecodedComponent => ({
  id,
  parent: placement.parent,
  index: placement.index,
  range: placement.range,
  sha256: digest,
  sections: [],
  core_modules: [],
  core_instances: [],
  core_types: [],
  instances: [],
  aliases: [],
  types: [],
  canons: [],
  start: null,
  imports: [],
  exports: [],
  values: [],
  names: null,
  custom_sections: [],
  lifts: [],
  lowers: [],
});

/** Decode one admitted component without validating, instantiating or executing it. */
export const decodeWasmComponent = async (
  bytes: Uint8Array,
  signal?: AbortSignal,
): Promise<WasmComponentDecoding> => {
  readComponentPreamble(bytes, 0, bytes.length);
  const features = new Set<GatedFeature>();
  const state: DecodeState = {
    bytes,
    components: [],
    types: { scopes: [], features, depth: 0 },
    notDecoded: [],
    signal,
    sectionsSinceYield: 0,
  };
  await decodeComponentAt(state, {
    range: { start: 0, end: bytes.length },
    parent: null,
    index: null,
    depth: 0,
  });
  return {
    components: state.components,
    typeScopes: state.types.scopes,
    features: [...features].sort(),
    notDecoded: state.notDecoded,
  };
};

/** Yield to the event loop periodically so cancellation can be observed. */
const checkpoint = async (state: DecodeState): Promise<void> => {
  state.signal?.throwIfAborted();
  state.sectionsSinceYield += 1;
  if (state.sectionsSinceYield < SECTIONS_PER_YIELD) return;
  state.sectionsSinceYield = 0;
  await new Promise((resolve) => setImmediate(resolve));
  state.signal?.throwIfAborted();
};

const decodeComponentAt = async (
  state: DecodeState,
  placement: ComponentPlacement,
): Promise<void> => {
  const component = emptyComponent(
    state.components.length,
    placement,
    sha256(state.bytes, placement.range),
  );
  state.components.push(component);
  const context: SectionContext = {
    state,
    component,
    spaces: new ComponentIndexSpaces(),
    depth: placement.depth,
  };
  const reader = new WasmComponentReader(
    state.bytes,
    placement.range.start + 8,
    placement.range.end,
  );
  while (!reader.atEnd) {
    await checkpoint(state);
    const id = reader.byte("section id");
    const section = reader.sub(reader.u32("section size"), "section");
    await decodeRecordedSection(context, id, section);
  }
  const relationships = resolveCanonRelationships(component, context.spaces);
  component.lifts = relationships.lifts;
  component.lowers = relationships.lowers;
};

/** Record one section and its coverage; unsupported content leaves later indices unknown. */
const decodeRecordedSection = async (
  context: SectionContext,
  id: number,
  section: WasmComponentReader,
): Promise<void> => {
  const payload = { start: section.offset, end: section.end };
  const entry: DecodedComponent["sections"][number] = {
    id,
    kind: SECTION_KINDS[id] ?? "unknown",
    range: payload,
    status: "decoded",
  };
  context.component.sections.push(entry);
  try {
    const decode = SECTION_DECODERS.get(id);
    if (decode === undefined)
      throw section.unsupported(`Unknown section id ${String(id)}`);
    await decode(context, section);
  } catch (cause: unknown) {
    if (!(cause instanceof WasmComponentFormatFailure)) throw cause;
    if (cause.kind === "malformed") throw cause;
    entry.status = "not_decoded";
    context.spaces.invalidate(SECTION_SORTS[id] ?? "all");
    context.state.notDecoded.push({
      component: context.component.id,
      range: { start: Math.max(cause.offset, payload.start), end: payload.end },
      reason: cause.message,
    });
  }
};

/** Decode `vec(T)` that must fill its section exactly. */
const decodeVector = (
  reader: WasmComponentReader,
  context: string,
  decode: () => unknown,
): void => {
  const count = reader.count(context);
  for (let index = 0; index < count; index += 1) decode();
  reader.expectEnd(`${context} section`);
};

type SectionDecoder = (
  context: SectionContext,
  reader: WasmComponentReader,
) => void | Promise<void>;

const decodeCoreModuleSection: SectionDecoder = (
  { state, component, spaces },
  reader,
) => {
  const range = { start: reader.offset, end: reader.end };
  component.core_modules.push({
    index: spaces.add("core module", { kind: "other" }),
    range,
    sha256: sha256(state.bytes, range),
    core_version: coreModuleVersion(state.bytes, range.start, range.end),
    interface: decodeCoreModuleInterface(state.bytes, range.start, range.end),
  });
};

const decodeNestedComponent: SectionDecoder = async (
  { state, component, spaces, depth },
  reader,
) => {
  const range = { start: reader.offset, end: reader.end };
  const index = spaces.add("component", { kind: "other" });
  if (depth + 1 >= MAX_COMPONENT_DEPTH)
    throw reader.unsupported(
      `Component nesting exceeds ${String(MAX_COMPONENT_DEPTH)} levels`,
    );
  readComponentPreamble(state.bytes, range.start, range.end);
  await decodeComponentAt(state, {
    range,
    parent: component.id,
    index,
    depth: depth + 1,
  });
};

/** Decoders for each admitted section id. */
const SECTION_DECODERS = new Map<number, SectionDecoder>([
  [0, ({ component }, reader) => decodeCustomSection(component, reader)],
  [1, decodeCoreModuleSection],
  [
    2,
    ({ component, spaces }, reader) =>
      decodeVector(reader, "core instances", () =>
        component.core_instances.push(decodeCoreInstance(reader, spaces)),
      ),
  ],
  [
    3,
    ({ state, component, spaces }, reader) =>
      decodeVector(reader, "core types", () => {
        const start = reader.offset;
        const type = decodeCoreType(reader, state.types);
        component.core_types.push({
          index: spaces.add("core type", { kind: "other" }),
          range: { start, end: reader.offset },
          type,
        });
      }),
  ],
  [4, decodeNestedComponent],
  [
    5,
    ({ state, component, spaces }, reader) =>
      decodeVector(reader, "instances", () =>
        component.instances.push(decodeInstance(reader, state.types, spaces)),
      ),
  ],
  [
    6,
    ({ state, component, spaces }, reader) =>
      decodeVector(reader, "aliases", () => {
        const start = reader.offset;
        const { sort, target } = decodeAlias(reader, state.types);
        component.aliases.push({
          range: { start, end: reader.offset },
          sort,
          target,
          defines: { sort, index: spaces.add(sort, aliasOrigin(target)) },
        });
      }),
  ],
  [
    7,
    ({ state, component, spaces }, reader) =>
      decodeVector(reader, "types", () => {
        const start = reader.offset;
        const type = decodeComponentType(reader, state.types);
        component.types.push({
          index: spaces.add("type", { kind: "other" }),
          range: { start, end: reader.offset },
          type,
        });
      }),
  ],
  [
    8,
    ({ state, component, spaces }, reader) =>
      decodeVector(reader, "canonical definitions", () => {
        const canon = decodeCanon(reader, state.types);
        canon.defines.index = spaces.add(canon.defines.sort, {
          kind: "canon",
          canon: component.canons.length,
        });
        component.canons.push(canon);
      }),
  ],
  [
    9,
    ({ state, component, spaces }, reader) =>
      decodeStart(reader, state.types, component, spaces),
  ],
  [
    10,
    ({ state, component, spaces }, reader) =>
      decodeVector(reader, "imports", () => {
        const start = reader.offset;
        const { name, attributes } = decodeNameAttributes(reader, state.types);
        const type = decodeExternType(reader, state.types);
        component.imports.push({
          range: { start, end: reader.offset },
          name,
          attributes,
          type,
          defines: {
            sort: type.sort,
            index: spaces.add(type.sort, { kind: "import", name }),
          },
        });
      }),
  ],
  [
    11,
    ({ state, component, spaces }, reader) =>
      decodeVector(reader, "exports", () =>
        decodeExport(reader, state.types, component, spaces),
      ),
  ],
  [
    12,
    ({ state, component, spaces }, reader) => {
      state.types.features.add("values-and-start");
      decodeVector(reader, "values", () => {
        const start = reader.offset;
        const type = decodeValType(reader, state.types);
        reader.range(reader.u32("value length"), "value bytes");
        component.values.push({
          index: spaces.add("value", { kind: "other" }),
          range: { start, end: reader.offset },
          type,
        });
      });
    },
  ],
]);
