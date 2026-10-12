# Offline WebAssembly artifacts

`inspect_wasm_artifact` / `inspect-wasm-artifact` inspects explicitly selected
local WASM bytes using caller-supplied WABT 1.0.42. No active binary target is
required. REA does not install tools or fetch artifacts and does not execute WASM.

`open_binary` is not the WASM inspection route. A recognized WASM v1 header
returns `target_unavailable` with category `unsupported_target` and constraint
`wasm_requires_static_inspection`, including the selected path in a valid
`inspect_wasm_artifact` call. Use that target-free tool or
`rea inspect-wasm-artifact <path> --format json` with the toolchain below.
Check `binary_session` for configured capability availability. A recognized
header is not validation of the complete module; missing WABT is reported
separately as an unavailable capability, not as missing native engine support.
A [component](#webassembly-components) header returns the constraint
`wasm_component_requires_static_inspection` from `open_binary`, and
`unsupported_target` from `inspect_wasm_artifact` before any WABT command runs.

Set `REA_WABT_BIN_DIRECTORY` to an absolute directory containing executable
`wasm-validate`, `wasm-objdump` and `wasm2wat` (with `.exe` on Windows). Missing
executables, unsupported banners and inaccessible tools produce actionable
unavailable diagnostics. Capability discovery reports configured availability;
execution validates tool files and version banners. Host process-ownership and
private-workspace controls must also be available. The real-tool profile has
been exercised on macOS arm64; other hosts require their own verification.

```bash
REA_WABT_BIN_DIRECTORY=/absolute/wabt/bin rea inspect-wasm-artifact \
  /artifacts/module.wasm --glue_paths /artifacts/glue.js \
  --candidate_paths /artifacts/other/module.wasm --format json
```

Equivalent MCP input:

```json
{
  "name": "inspect_wasm_artifact",
  "arguments": {
    "path": "/artifacts/module.wasm",
    "glue_paths": ["/artifacts/glue.js"],
    "candidate_paths": ["/artifacts/other/module.wasm"]
  }
}
```

Each selected regular file is read through the existing stable artifact reader;
symlinks, changing files and files over 8 MiB fail closed. WASM bytes are copied
into a private workspace as read-only `module.wasm`; its digest is rechecked
before and after each tool. WABT validates with `--enable-all`,
reports sections through `wasm-objdump -h -x`, and decodes through
`wasm2wat --enable-all`. The result retains selected byte SHA-256 and size,
section payload ranges, full header/detail output (including module-name
preambles), exact import/export WAT
forms, decoded WAT and its UTF-8 SHA-256. Producer format drift and invalid or
truncated modules are failures, with validation diagnostics and partial Evidence
retaining selected byte identity and tool provenance.

The tool profile preserves upstream release/source identity, resolved executable
paths, executable digests, exact banners and arguments. Executable digests are
checked again after each command. Caller-supplied tools are trusted programs;
version and digest recording are not publisher authentication or an OS sandbox.
Each subprocess has a 30-second deadline and 32 MiB combined output budget;
truncation fails. All commands use existing owned-process cancellation and
cleanup. Workspace cleanup failures remain explicit errors with resource paths.

WAT is a decoded representation, not original source or proof of runtime
behavior. Custom annotations can preserve payloads, but WAT does not establish original
binary layout or round-trip byte identity. Original byte identity and objdump
output retain that distinction. Import/export forms retain exact escaped WAT names. Unescaped objdump display
names are not parsed as unambiguous identifiers.

Optional JavaScript glue uses the existing Babel parser and AST traversal. It
retains `.wasm` string literals and literal templates with source coordinates,
selected glue byte identity and parser status. Relative filesystem matches become
local path candidates. URLs, query/fragment variants and unmatched paths retain
basename candidates, including multiple matches, or remain unresolved. These are
literal associations, not proven data flow, runtime loading or URL-to-file
identity. Computed strings, aliases and dynamic imports require further evidence.
Candidates are caller-selected files; their identity does not imply validation.

Both CLI and MCP use the same typed port and application service. MCP publishes
SDK-compatible schemas and records Evidence for `get_evidence_bundle` readback.
See [WABT provenance](https://github.com/morluto/rea/blob/main/third_party/wabt/README.md) and
[testing](testing.md#offline-wasm-artifacts) for real-tool verification.

## WebAssembly components

`inspect_wasm_component` / `inspect-wasm-component` decodes one explicitly
selected component-model binary in process. It needs no WABT or other tool, no
active binary target and no network, and it never instantiates or executes the
component or its embedded modules.

```bash
rea inspect-wasm-component /artifacts/component.wasm --json
```

```json
{
  "name": "inspect_wasm_component",
  "arguments": { "path": "/artifacts/component.wasm" }
}
```

The decoder admits only the preamble `00 61 73 6D 0D 00 01 00` (version `0xd`,
layer `1`). Its grammar is pinned to component-model
[`Binary.md` at `06e3db0`](https://github.com/WebAssembly/component-model/blob/06e3db039e38588e2643a9417bf5d03100feafde/design/mvp/Binary.md).
Other versions or layers return `unsupported_target` with the observed bytes. A
core module returns `unsupported_target` and points to `inspect_wasm_artifact`.

The result keeps the selected file's SHA-256 and size and an exclusive byte
range for every decoded entry. It lists:

- sections with their payload ranges and status;
- imports and exports, with name attributes (`implements`, `versionsuffix`,
  `external-id`) and extern types;
- type definitions, with component, instance and core module type declarations
  in the flat `type_scopes` list;
- embedded core modules, by range, SHA-256, header version and their import
  and export names only;
- core and component instances, aliases, canonical definitions and their
  options, the start function and value sections;
- the `component-name` section and other custom sections by name;
- nested components as further entries in `components`, linked by `parent`.

Every definition reports the index it defines in its sort. `lifts` trace each
canonical lift to the core export it wraps, and `lowers` trace each lower to its
component import and to the core module imports it is bound to.
`declared_by_module` says whether the module's own import or export section
declares that name; it is null when that interface was not decoded.

`validation` is always `not_performed`. Decoding checks LEB128 encodings,
lengths, UTF-8 and opcodes, not type correctness, name uniqueness, index bounds
or the canonical ABI. A decoded component can still be invalid. Malformed
framing fails with `invalid_request` and the file offset. A well-framed construct
the decoder does not handle, such as a GC core type, an unknown section or an
unknown opcode, is listed in `coverage.not_decoded` with its range. Decoding
continues with the next section, and indices that later definitions add to the
affected sorts are null, because their positions are unknown. `gated_features`
lists the feature gates of encodings actually present, such as `async` or
`fixed-size-list`.

Inputs are limited to 8 MiB, nested components to 16 levels and nested type
declarations to 32 levels. Complete results are inline and limited to 8 MiB.
Cancellation is checked between sections. Apart from the stable file read, the
decoder owns no processes, temporary files or other resources.
