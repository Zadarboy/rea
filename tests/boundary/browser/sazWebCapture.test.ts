import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { Uint8ArrayReader, Uint8ArrayWriter, ZipWriter } from "@zip.js/zip.js";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it, onTestFinished } from "vitest";
import { z } from "zod";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { webNetworkCaptureSchema } from "../../../src/domain/webNetworkCapture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

// Synthetic member fixtures based on Telerik's SAZ layout; not a real-producer golden.
const compressedBody = gzipSync(Buffer.from("stored compressed body"));
const members = (): [string, Buffer][] => [
  [
    "raw/0042_s.txt",
    Buffer.concat([
      Buffer.from(
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nSet-Cookie: server-credential\r\n\r\n",
      ),
      compressedBody,
    ]),
  ],
  [
    "raw/7_c.txt",
    Buffer.concat([
      Buffer.from("POST /bytes HTTP/2.0\r\n:authority: example.test\r\n\r\n"),
      Buffer.from([0xff, 0, 0x80]),
    ]),
  ],
  [
    "raw/0042_c.txt",
    Buffer.from(
      "GET https://user:password@example.test/a HTTP/1.1\r\nAuthorization: Bearer client-credential\r\nCookie: cookie-credential\r\nX-Duplicate: one\r\nX-Duplicate: two\r\nX-Text: unicode-\u03b2\r\n\r\n",
    ),
  ],
  [
    "raw/0042_m.xml",
    Buffer.from(
      '<Session SID="0042"><SessionTimers ClientConnected="2026-10-13T00:00:00Z"/><SessionFlags><SessionFlag N="x-processinfo" V="fixture:1"/></SessionFlags><Unknown value="01"><![CDATA[retained metadata]]></Unknown></Session>',
    ),
  ],
  ["raw/0042_w.txt", Buffer.from("opaque websocket message file")],
  ["raw/7_g.txt", Buffer.from([0, 1, 2])],
  ["[Content_Types].xml", Buffer.from("<Types/>")],
];
const archive = async (entries = members(), password?: string, level = 6) => {
  const writer = new ZipWriter(new Uint8ArrayWriter(), {
    useWebWorkers: false,
    level,
    ...(password === undefined ? {} : { password }),
  });
  for (const [name, bytes] of entries)
    await writer.add(name, new Uint8ArrayReader(bytes));
  return Buffer.from(await writer.close());
};
const fixture = async (bytes: Buffer) => {
  const root = await createTestTempDirectory("rea-saz-capture-");
  const path = join(root, "capture.saz");
  await writeFile(path, bytes);
  return path;
};
const entrypoint = fileURLToPath(
  new URL("../../../scripts/rea.mjs", import.meta.url),
);
const cliResponse = async (path: string, extra: string[] = []) => {
  try {
    const { stdout } = await promisify(execFile)(
      process.execPath,
      [
        entrypoint,
        "inspect-web-network-capture",
        path,
        "saz",
        "--json",
        ...extra,
      ],
      { timeout: 40_000, maxBuffer: 4 * 1024 * 1024 },
    );
    return { ok: true, stdout };
  } catch (cause: unknown) {
    if (
      cause instanceof Error &&
      "stdout" in cause &&
      typeof cause.stdout === "string"
    )
      return { ok: false, stdout: cause.stdout };
    throw cause;
  }
};
const cli = async (path: string, extra: string[] = []) => {
  const result = await cliResponse(path, extra);
  expect(result.ok, result.stdout).toBe(true);
  return parseEvidence(JSON.parse(result.stdout));
};

it("inspects native SAZ through the public CLI and MCP with equal evidence, bytes and archive coordinates", async () => {
  const bytes = await archive();
  const path = await fixture(bytes);
  const evidence = await cli(path, ["--record", "1", "--record", "0"]);
  const capture = webNetworkCaptureSchema.parse(evidence.normalized_result);
  expect(capture).toMatchObject({
    format: "saz",
    total_records: 2,
    runtime_attribution: "unknown",
    records: [
      { ordinal: 1, reported: { session_id: "7", response: null } },
      {
        ordinal: 0,
        reported: {
          session_id: "0042",
          request: { url: "https://example.test/a" },
          response: { status: "200" },
        },
      },
    ],
  });
  expect(capture.records[1]?.location).toEqual({
    kind: "archive-members",
    members: [
      "raw/0042_s.txt",
      "raw/0042_c.txt",
      "raw/0042_m.xml",
      "raw/0042_w.txt",
    ],
  });
  expect(capture.records[1]?.binary_fields).toContainEqual({
    pointer: "/response/body",
    representation: "producer-bytes",
    state: "retained",
    content_base64: compressedBody.toString("base64"),
    bytes: compressedBody.length,
    sha256: createHash("sha256").update(compressedBody).digest("hex"),
  });
  expect(capture.records[0]?.binary_fields).toContainEqual(
    expect.objectContaining({
      pointer: "/request/body",
      content_base64: "/wCA",
    }),
  );
  expect(capture.records[1]?.binary_fields).toContainEqual(
    expect.objectContaining({
      pointer: "/request/body",
      bytes: 0,
      content_base64: "",
    }),
  );
  expect(capture.records[1]?.reported).toMatchObject({
    request: {
      headers: [
        { name: "Authorization", value: null },
        { name: "Cookie", value: null },
        { name: "X-Duplicate", value: " one" },
        { name: "X-Duplicate", value: " two" },
        { name: "X-Text" },
      ],
    },
  });
  expect(JSON.stringify(capture)).toContain("retained metadata");
  for (const secret of [
    "user:password",
    "client-credential",
    "server-credential",
    "cookie-credential",
  ])
    expect(JSON.stringify(capture)).not.toContain(secret);
  expect(capture.artifact.sha256).toBe(
    createHash("sha256").update(bytes).digest("hex"),
  );
  expect(await readFile(path)).toEqual(bytes);

  const client = new Client({ name: "saz-boundary", version: "1" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    cwd: process.cwd(),
    env: {
      PATH: process.env.PATH ?? "",
      NODE_OPTIONS: "--max-old-space-size=512 --max-semi-space-size=8",
    },
    stderr: "pipe",
  });
  onTestFinished(async () => {
    await client.close();
    await transport.close();
  });
  await client.connect(transport);
  const tool = (await client.listTools()).tools.find(
    (item) => item.name === "inspect_web_network_capture",
  );
  if (tool?.outputSchema === undefined)
    throw new Error("Missing capture schema");
  const args = { capture_path: path, format: "saz", record_ordinals: [1, 0] };
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  expect(ajv.validate(tool.inputSchema, args)).toBe(true);
  const response = await client.callTool({
    name: "inspect_web_network_capture",
    arguments: args,
  });
  expect(response.isError, JSON.stringify(response)).not.toBe(true);
  expect(
    ajv.validate(
      z.record(z.string(), z.unknown()).parse(tool.outputSchema),
      response.structuredContent,
    ),
    JSON.stringify(ajv.errors),
  ).toBe(true);
  const fromMcp = parseEvidence(response.structuredContent);
  expect(fromMcp.normalized_result).toEqual(evidence.normalized_result);
  const bundle = await client.callTool({
    name: "get_evidence_bundle",
    arguments: { detail: "complete" },
  });
  const records = z
    .object({ result: z.object({ records: z.array(z.unknown()) }) })
    .parse(bundle.structuredContent)
    .result.records.map(parseEvidence);
  expect(
    records.find((record) => record.evidence_id === fromMcp.evidence_id),
  ).toEqual(fromMcp);
}, 60_000);

it("excludes explicit literals from XML, HTTP byte views, member coordinates and binary sidecars", async () => {
  const path = await fixture(await archive());
  const result = await cli(path, [
    "--sensitive-value",
    "0042",
    "--sensitive-value",
    "unicode-\u03b2",
    "--sensitive-value",
    compressedBody.toString("base64"),
    "--sensitive-value",
    "retained metadata",
  ]);
  const capture = webNetworkCaptureSchema.parse(result.normalized_result);
  expect(capture.records[0]?.location).toEqual({
    kind: "unknown",
    reason: "explicit-sensitive-value",
  });
  expect(capture.records[0]?.binary_fields).toContainEqual({
    pointer: "/response/body",
    representation: "producer-bytes",
    state: "redacted",
    bytes: null,
    sha256: null,
    content_base64: null,
  });
  const text = JSON.stringify(result);
  for (const secret of [
    "0042",
    "unicode-",
    "retained metadata",
    compressedBody.toString("base64"),
    createHash("sha256").update(compressedBody).digest("hex"),
  ])
    expect(text).not.toContain(secret);
});

it("retains folded headers, stored chunk framing and BOM-marked UTF-16 metadata", async () => {
  const body = "3\r\none\r\n0\r\n\r\n";
  const path = await fixture(
    await archive([
      [
        "raw/1_s.txt",
        Buffer.from(
          `HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Folded: first\r\n second\r\n\r\n${body}`,
        ),
      ],
      [
        "raw/1_m.xml",
        Buffer.from(
          '\ufeff<?xml version="1.0" encoding="utf-16"?><Session><Note>\u03b2</Note></Session>',
          "utf16le",
        ),
      ],
      [
        "raw/2_c.txt",
        Buffer.from(
          "CONNECT example.test:443 HTTP/1.1\nHost: example.test:443\n\n",
        ),
      ],
    ]),
  );
  const evidence = await cli(path);
  const capture = webNetworkCaptureSchema.parse(evidence.normalized_result);
  expect(capture.records[0]?.reported).toMatchObject({
    request: null,
    response: {
      body,
      headers: [
        { name: "Transfer-Encoding", value: " chunked" },
        { name: "X-Folded", value: " first\r\n second" },
      ],
    },
  });
  expect(capture.records[0]?.binary_fields).toContainEqual(
    expect.objectContaining({
      pointer: "/response/body",
      content_base64: Buffer.from(body).toString("base64"),
    }),
  );
  expect(JSON.stringify(capture.records[0]?.reported)).toContain("\u03b2");
  expect(capture.records[1]?.reported).toMatchObject({
    request: { method: "CONNECT", url: "example.test:443", body: "" },
  });
});

it.each([
  "bad-http",
  "bad-xml",
  "dtd",
  "unknown-member",
  "encrypted",
  "duplicate",
  "crc",
  "expanded-limit",
])("rejects %s before returning a selected subset", async (variant) => {
  let entries = members();
  if (variant === "bad-http")
    entries.push(["raw/8_c.txt", Buffer.from("malformed-private-input")]);
  if (variant === "bad-xml")
    entries.push(["raw/8_m.xml", Buffer.from("<Session><Broken></Session>")]);
  if (variant === "dtd")
    entries.push([
      "raw/8_m.xml",
      Buffer.from(
        '<!DOCTYPE Session [<!ENTITY external SYSTEM "file:///private-input">]><Session>&external;</Session>',
      ),
    ]);
  if (variant === "unknown-member")
    entries.push(["raw/8_unknown.txt", Buffer.from("unknown extension")]);
  if (variant === "duplicate")
    entries = [
      ["raw/8_c.txt", Buffer.from("GET /a HTTP/1.1\r\n\r\n")],
      ["raw/9_c.txt", Buffer.from("GET /b HTTP/1.1\r\n\r\n")],
    ];
  let bytes = await archive(
    entries,
    variant === "encrypted" ? "fixture-password" : undefined,
    variant === "crc" ? 0 : 6,
  );
  if (variant === "duplicate")
    bytes = Buffer.from(
      bytes.toString("latin1").replaceAll("raw/9_c.txt", "raw/8_c.txt"),
      "latin1",
    );
  if (variant === "crc") {
    const offset = bytes.indexOf(Buffer.from("HTTP/1.1 200 OK"));
    expect(offset).toBeGreaterThan(0);
    bytes[offset + 9] = 0x35;
  }
  if (variant === "expanded-limit") {
    const central = bytes.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    bytes.writeUInt32LE(33 * 1024 * 1024, central + 24);
  }
  const path = await fixture(bytes);
  const result = await cliResponse(path, ["--record", "0"]);
  expect(result.ok, result.stdout).toBe(false);
  expect(JSON.parse(result.stdout).category).toBe(
    ["encrypted", "unknown-member", "dtd"].includes(variant)
      ? "unsupported_provider"
      : variant === "expanded-limit"
        ? "execution_failure"
        : "invalid_input",
  );
  if (variant === "expanded-limit")
    expect(JSON.parse(result.stdout).code).toBe("unreadable_output");
  expect(JSON.stringify(result)).not.toContain("malformed-private-input");
});
