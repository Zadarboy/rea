import { describe, expect, it } from "vitest";

import { decodeWasmComponent } from "./WasmComponentDecoder.js";
import {
  component,
  coreModule,
  externName,
  gatedFeatureComponent,
  name,
  nestedComponent,
  representativeComponent,
  section,
  u32,
  vec,
  withPreamble,
} from "./WasmComponentBinary.fixture.js";
import { WasmComponentFormatFailure } from "./WasmComponentReader.js";

const failureOf = async (bytes: Uint8Array) => {
  try {
    await decodeWasmComponent(bytes);
  } catch (cause: unknown) {
    if (cause instanceof WasmComponentFormatFailure) return cause;
    throw cause;
  }
  throw new Error("Expected a component format failure");
};

const decodeRepresentative = async () => {
  const bytes = representativeComponent();
  const decoded = await decodeWasmComponent(bytes);
  const [root] = decoded.components;
  if (root === undefined) throw new Error("Missing root component");
  return { bytes, decoded, root };
};

describe("decodeWasmComponent index spaces", () => {
  it("assigns definition indices across interleaved sections", async () => {
    const { bytes, decoded, root } = await decodeRepresentative();
    expect(decoded.notDecoded).toEqual([]);
    expect(root).toMatchObject({
      id: 0,
      parent: null,
      index: null,
      range: { start: 0, end: bytes.length },
    });
    expect(
      root.imports.map(({ name, defines }) => ({ name, defines })),
    ).toEqual([
      { name: "log", defines: { sort: "func", index: 0 } },
      { name: "wasi:fs/types@0.2.0", defines: { sort: "instance", index: 0 } },
    ]);
    expect(root.exports).toEqual([
      expect.objectContaining({
        name: "run",
        target: { sort: "func", index: 1 },
        type: null,
        defines: { sort: "func", index: 3 },
      }),
    ]);
    expect(root.core_modules).toEqual([
      expect.objectContaining({
        index: 0,
        core_version: 1,
        interface: {
          status: "decoded",
          reason: null,
          imports: [
            { module: "host", name: "log", type: { kind: "func", type: 0 } },
          ],
          exports: [
            { name: "run", kind: "func", index: 1 },
            { name: "memory", kind: "memory", index: 0 },
          ],
        },
      }),
    ]);
    expect(root.canons.map(({ kind, defines }) => ({ kind, defines }))).toEqual(
      [
        { kind: "lower", defines: { sort: "core func", index: 0 } },
        { kind: "lift", defines: { sort: "func", index: 1 } },
        { kind: "lower", defines: { sort: "core func", index: 2 } },
      ],
    );
    expect(root.canons[2]?.options).toEqual([
      { kind: "memory", core_memory: 0 },
      { kind: "string-encoding", encoding: "utf8" },
    ]);
    const module = root.core_modules[0];
    if (module === undefined) throw new Error("Missing core module");
    expect(bytes.subarray(module.range.start, module.range.start + 8)).toEqual(
      Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]),
    );
  });
});

describe("decodeWasmComponent relationships", () => {
  it("traces canonical lifts and lowers through the component index spaces", async () => {
    const { decoded, root } = await decodeRepresentative();
    expect(root.lifts).toEqual([
      {
        canon: 1,
        func: 1,
        core_func: 1,
        type: 1,
        core_source: {
          core_instance: 1,
          name: "run",
          core_module: 0,
          declared_by_module: true,
        },
        exported_as: ["run"],
      },
    ]);
    expect(root.lowers).toEqual([
      {
        canon: 0,
        func: 0,
        core_func: 0,
        component_source: { kind: "import", name: "log" },
        satisfies: [
          {
            core_instance: 1,
            core_module: 0,
            import_module: "host",
            import_name: "log",
            declared_by_module: true,
          },
        ],
      },
      {
        canon: 2,
        func: 2,
        core_func: 2,
        component_source: {
          kind: "instance-export",
          instance: 0,
          name: "[method]file.name",
          instance_import: "wasi:fs/types@0.2.0",
        },
        satisfies: [],
      },
    ]);
    expect(root.names).toMatchObject({
      status: "decoded",
      component: "demo",
      sorts: [
        {
          sort: "func",
          names: [
            { index: 0, name: "log" },
            { index: 1, name: "run" },
          ],
        },
      ],
    });
    expect(root.types[2]?.type).toEqual({ kind: "instance", scope: 0 });
    expect(decoded.typeScopes).toEqual([
      expect.objectContaining({
        scope: 0,
        kind: "instance",
        declarations: [
          expect.objectContaining({
            kind: "export",
            name: "file",
            type: { sort: "type", bound: { kind: "sub-resource" } },
          }),
          expect.objectContaining({
            kind: "type",
            type: { kind: "borrow", resource: 0 },
          }),
          expect.objectContaining({
            kind: "type",
            type: {
              kind: "func",
              async: false,
              params: [{ name: "self", type: { type: 1 } }],
              result: "string",
            },
          }),
          expect.objectContaining({
            kind: "export",
            name: "[method]file.name",
            type: { sort: "func", type: 2 },
          }),
        ],
      }),
    ]);
  });
});

describe("decodeWasmComponent gated and nested encodings", () => {
  it("reports gated encodings it decodes", async () => {
    const decoded = await decodeWasmComponent(gatedFeatureComponent());
    const [root] = decoded.components;
    expect(decoded.features).toEqual([
      "async",
      "error-context",
      "fixed-size-list",
      "map",
      "version-suffix",
    ]);
    expect(root?.types.map(({ type }) => type)).toEqual([
      { kind: "stream", element: "u8" },
      { kind: "map", key: "string", value: "u32" },
      { kind: "list", element: "u8", length: 4 },
      {
        kind: "func",
        async: true,
        params: [{ name: "s", type: { type: 0 } }],
        result: "error-context",
      },
    ]);
    expect(root?.imports[0]?.attributes).toEqual([
      { kind: "version-suffix", suffix: "-rc1" },
    ]);
    expect(root?.canons.map(({ kind }) => kind)).toEqual([
      "task.return",
      "stream.new",
    ]);
    expect(root?.canons[0]).toMatchObject({
      result: "u32",
      options: [{ kind: "async" }],
    });
  });

  it("decodes nested components and stops at the nesting bound", async () => {
    const inner = component(section(7, vec([0x40, ...vec(), 0x01, 0x00])));
    const decoded = await decodeWasmComponent(nestedComponent(2, inner));
    expect(
      decoded.components.map(({ id, parent, index }) => ({
        id,
        parent,
        index,
      })),
    ).toEqual([
      { id: 0, parent: null, index: null },
      { id: 1, parent: 0, index: 0 },
      { id: 2, parent: 1, index: 0 },
    ]);
    expect(decoded.components[2]?.types).toHaveLength(1);

    const deep = await decodeWasmComponent(nestedComponent(16, inner));
    expect(deep.components).toHaveLength(16);
    expect(deep.notDecoded).toEqual([
      expect.objectContaining({
        component: 15,
        reason: expect.stringContaining("Component nesting exceeds 16 levels"),
      }),
    ]);
  });
});

describe("decodeWasmComponent partial coverage", () => {
  it("records unsupported constructs and keeps later indices unknown", async () => {
    const decoded = await decodeWasmComponent(
      component(
        section(7, vec([0x40, ...vec(), 0x01, 0x00])),
        section(10, vec([...externName("first"), 0x01, ...u32(0)])),
        section(13, [0x01, 0x02]),
        section(10, vec([...externName("second"), 0x01, ...u32(0)])),
        section(3, vec([0x5f, ...vec()])),
      ),
    );
    const [root] = decoded.components;
    expect(root?.sections.map(({ id, status }) => ({ id, status }))).toEqual([
      { id: 7, status: "decoded" },
      { id: 10, status: "decoded" },
      { id: 13, status: "not_decoded" },
      { id: 10, status: "decoded" },
      { id: 3, status: "not_decoded" },
    ]);
    expect(root?.imports.map(({ defines }) => defines)).toEqual([
      { sort: "func", index: 0 },
      { sort: "func", index: null },
    ]);
    expect(decoded.notDecoded.map(({ reason }) => reason)).toEqual([
      expect.stringContaining("Unknown section id 13"),
      expect.stringContaining("Core type opcode 0x5f"),
    ]);
  });

  it("keeps decoding when the name section is invalid or a module is not core", async () => {
    const decoded = await decodeWasmComponent(
      component(
        section(1, [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00]),
        section(0, [...name("component-name"), ...section(0, [0x05, 0x61])]),
        section(1, coreModule(section(2, [0x01, 0x7f]))),
      ),
    );
    const [root] = decoded.components;
    expect(root?.names).toMatchObject({
      status: "invalid",
      reason: expect.stringContaining("component name"),
    });
    expect(
      root?.core_modules.map(({ index, core_version, interface: face }) => ({
        index,
        core_version,
        status: face.status,
      })),
    ).toEqual([
      { index: 0, core_version: null, status: "not_decoded" },
      { index: 1, core_version: 1, status: "not_decoded" },
    ]);
  });
});

describe("decodeWasmComponent rejections", () => {
  it.each([
    [
      "a section extending past the file",
      component([0x07, 0x05, 0x00]),
      "section extends past its enclosing range",
    ],
    [
      "an overlong LEB128 count",
      component(section(7, [0x80, 0x80, 0x80, 0x80, 0x80, 0x00])),
      "Invalid u32 LEB128",
    ],
    [
      "invalid UTF-8 in an import name",
      component(section(10, vec([0x00, 0x01, 0xff, 0x01, 0x00]))),
      "Invalid UTF-8 in extern name",
    ],
    [
      "trailing bytes in a section",
      component(section(7, [...vec([0x7f]), 0x00])),
      "Unexpected trailing bytes in types section",
    ],
    ["a truncated preamble", Uint8Array.from([0x00, 0x61, 0x73]), "Truncated"],
  ])("fails closed on %s", async (_label, bytes, message) => {
    const failure = await failureOf(bytes);
    expect(failure.kind).toBe("malformed");
    expect(failure.message).toContain(message);
  });

  it.each([
    [
      "a core module",
      Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]),
      "use inspect_wasm_artifact",
    ],
    [
      "an older component version",
      withPreamble(representativeComponent(), 0x0c, 0x01),
      "version 0xc layer 0x1 is not admitted",
    ],
    [
      "a non-WebAssembly file",
      Uint8Array.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]),
      "missing",
    ],
  ])("rejects %s before decoding", async (_label, bytes, message) => {
    const failure = await failureOf(bytes);
    expect(failure.kind).toBe("unsupported");
    expect(failure.message).toContain(message);
  });

  it("stops before decoding when cancelled", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      decodeWasmComponent(representativeComponent(), controller.signal),
    ).rejects.toThrow();
  });
});
