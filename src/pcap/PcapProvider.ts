import type {
  ExecutionOptions,
  ProviderAvailability,
} from "../application/AnalysisProvider.js";
import {
  createAnalysisExecution,
  type AnalysisExecution,
} from "../application/AnalysisProvider.js";
import {
  pcapResultSchemas,
  type PcapRequest,
  type PcapOperation,
} from "../domain/pcap/pcapAnalysis.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisProtocolError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { err, ok, type Result } from "../domain/result.js";
import type { ProviderProcessSupervisor } from "../process/ProviderProcess.js";
import {
  PcapConfigurationFailure,
  inspectPcapClient,
  resolvePcapTools,
  pcapConfigurationAvailability,
  type PcapToolSelection,
} from "./PcapConfiguration.js";
import {
  parseCapinfosOutput,
  parseTsharkJsonOutput,
  TSHARK_JSON_MAX_BYTES,
} from "./PcapOutput.js";
import { runPcapCommand, type PcapCommandLimits } from "./PcapCommand.js";
import { PcapSnapshot } from "./PcapSnapshot.js";

export const PCAP_PROVIDER_IDENTITY = {
  id: "pcap",
  name: "Packet capture analysis",
  version: null,
} as const;
const LIMITS = {
  maxEndpoints: 200,
  maxDnsQueries: 100,
  maxSniValues: 50,
  maxProtocols: 50,
  maxHttpUris: 50,
};
const FIELDS = [
  "frame.number",
  "frame.protocols",
  "ip.src",
  "ip.dst",
  "ipv6.src",
  "ipv6.dst",
  "dns.flags.response",
  "dns.qry.name",
  "dns.a",
  "dns.aaaa",
  "tls.handshake.extensions_server_name",
  "http.request.full_uri",
];

export interface PcapProviderOptions {
  readonly environment?: Readonly<Record<string, string | undefined>>;
}

/** Inspect saved captures through bounded, owned tool processes and one stable input copy. */
export class PcapProvider {
  private readonly environment: Readonly<Record<string, string | undefined>>;
  private readonly snapshots = new Set<PcapSnapshot>();
  private readonly commands = new Map<
    ProviderProcessSupervisor,
    { snapshot: PcapSnapshot | undefined; resources: readonly string[] }
  >();

  constructor(options: PcapProviderOptions = {}) {
    this.environment = options.environment ?? process.env;
  }

  private run(
    operation: PcapOperation,
    command: string,
    args: readonly string[],
    limits: PcapCommandLimits,
    signal: AbortSignal | undefined,
    snapshot?: PcapSnapshot,
    inputPath?: string,
  ) {
    return runPcapCommand({
      operation,
      command,
      arguments: args,
      limits,
      signal,
      environment: this.environment,
      ...(inputPath === undefined ? {} : { inputPath }),
      retain: (owner, resources) => {
        this.commands.set(owner, { snapshot, resources });
      },
    });
  }

  private async client(operation: PcapOperation, signal?: AbortSignal) {
    const selection = resolvePcapTools(this.environment);
    const identity = await inspectPcapClient(
      selection,
      async (command) =>
        (
          await this.run(
            operation,
            command,
            ["--version"],
            { timeoutMs: 20_000, maxOutputBytes: 64 * 1024 },
            signal,
          )
        ).stdout,
    );
    for (const [name, version] of [
      ["tshark", identity.tsharkVersion],
      ["capinfos", identity.capinfosVersion],
    ] as const)
      if (version === null)
        throw new PcapConfigurationFailure(
          `${name}_version_unresolved`,
          `The selected ${name} command did not report a version. Set REA_${name.toUpperCase()}_COMMAND to its absolute executable path.`,
        );
    return {
      selection,
      client: {
        tshark_command: selection.tshark.command,
        tshark_source: selection.tshark.source,
        tshark_version: identity.tsharkVersion,
        capinfos_command: selection.capinfos.command,
        capinfos_source: selection.capinfos.source,
        capinfos_version: identity.capinfosVersion,
      },
    };
  }

  async inspectAvailability(
    signal?: AbortSignal,
  ): Promise<ProviderAvailability> {
    try {
      const { client } = await this.client("inspect_pcap_client", signal);
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: client,
      };
    } catch (cause) {
      if (signal?.aborted || cause instanceof AnalysisCancelledError)
        throw new AnalysisCancelledError("inspect_pcap_client", { cause });
      if (cause instanceof PcapConfigurationFailure)
        return pcapConfigurationAvailability(cause);
      return {
        status: "unavailable",
        code:
          cause instanceof AnalysisCapabilityUnavailableError
            ? "executable_missing"
            : "version_unresolved",
        reason: cause instanceof Error ? cause.message : String(cause),
        diagnostics: {},
      };
    }
  }

  private async discard(
    snapshot: PcapSnapshot,
  ): Promise<AnalysisError | undefined> {
    try {
      if (
        [...this.commands.values()].some(
          (command) => command.snapshot === snapshot,
        )
      )
        throw new Error(
          "An unreleased command still owns the capture snapshot",
        );
      await snapshot.close();
      this.snapshots.delete(snapshot);
      return undefined;
    } catch (cause) {
      return new AnalysisResourceConstraintError(
        "inspect_pcap_capture",
        "file-size",
        "Capture snapshot cleanup failed",
        null,
        {
          cause,
          cleanup: {
            reason: cause instanceof Error ? cause.message : String(cause),
            resources: [snapshot.path],
          },
        },
      );
    }
  }

  async close(): Promise<void> {
    const failures: unknown[] = [];
    for (const owner of this.commands.keys()) {
      try {
        const result = await owner.stop();
        if (result.status === "incomplete") failures.push(result.reason);
        else if (result.status === "not-owned")
          failures.push("Command ownership remains unresolved");
        else this.commands.delete(owner);
      } catch (cause) {
        failures.push(cause);
      }
    }
    for (const snapshot of this.snapshots) {
      const failure = await this.discard(snapshot);
      if (failure !== undefined) failures.push(failure);
    }
    if (failures.length > 0)
      throw new AnalysisResourceConstraintError(
        "pcap.close",
        "file-size",
        "Packet-capture resources remain owned after cleanup failed",
        null,
        {
          cause: new AggregateError(failures),
          cleanup: {
            reason: "Owned process or snapshot cleanup failed",
            resources: [...this.snapshots]
              .map((snapshot) => snapshot.path)
              .concat(
                [...this.commands.values()].flatMap(
                  (command) => command.resources,
                ),
              ),
          },
        },
      );
  }

  async execute(
    request: PcapRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    let snapshot: PcapSnapshot | undefined;
    let result: Result<AnalysisExecution, AnalysisError>;
    try {
      signal?.throwIfAborted();
      const { selection, client } = await this.client(
        request.operation,
        signal,
      );
      const provider = {
        ...PCAP_PROVIDER_IDENTITY,
        version: client.tshark_version,
      };
      if (request.operation === "inspect_pcap_client")
        result = ok(
          createAnalysisExecution(
            pcapResultSchemas.inspect_pcap_client.parse({ client }),
            provider,
          ),
        );
      else {
        snapshot = await PcapSnapshot.create();
        this.snapshots.add(snapshot);
        const identity = await snapshot.capture(request.input.path, signal);
        const captured = await this.inspectCapture(
          selection,
          snapshot,
          request.input.path,
          identity,
          signal,
        );
        const data = pcapResultSchemas.inspect_pcap_capture.parse({
          client,
          ...captured.result,
        });
        result = ok(
          createAnalysisExecution(data, provider, {
            subject: {
              path: request.input.path,
              format: "file",
              sha256: identity.sha256,
            },
            limitations: captured.limitations,
          }),
        );
      }
    } catch (cause) {
      result = err(
        cause instanceof AnalysisError
          ? cause
          : signal?.aborted
            ? new AnalysisCancelledError(request.operation, { cause })
            : cause instanceof PcapConfigurationFailure
              ? new AnalysisCapabilityUnavailableError(
                  "pcap",
                  request.operation,
                  cause.message,
                  { cause },
                )
              : new AnalysisProtocolError(
                  `Packet-capture analysis failed: ${cause instanceof Error ? cause.message : String(cause)}`,
                  { cause },
                ),
      );
    }
    if (signal?.aborted && result.ok)
      result = err(
        new AnalysisCancelledError(request.operation, { cause: signal.reason }),
      );
    if (snapshot !== undefined) {
      const cleanup = await this.discard(snapshot);
      if (signal?.aborted && result.ok)
        result = err(
          new AnalysisCancelledError(request.operation, {
            cause: signal.reason,
          }),
        );
      if (cleanup !== undefined)
        result = result.ok
          ? ok({
              ...result.value,
              limitations: [
                ...result.value.limitations,
                `Owned capture cleanup is pending: ${snapshot.path}; provider close will retry`,
              ],
            })
          : err(
              analysisErrorWithCleanupFailure(
                result.error,
                cleanup,
                request.operation,
              ),
            );
    }
    return result;
  }

  private async inspectCapture(
    selection: PcapToolSelection,
    snapshot: PcapSnapshot,
    path: string,
    identity: { bytes: number; sha256: string },
    signal: AbortSignal | undefined,
  ) {
    const info = await this.run(
      "inspect_pcap_capture",
      selection.capinfos.command,
      ["-M", "--", snapshot.path],
      { timeoutMs: 60_000, maxOutputBytes: 64 * 1024 },
      signal,
      snapshot,
      path,
    );
    const metadata = parseCapinfosOutput(info.stdout);
    if (metadata.sha256 !== null && metadata.sha256 !== identity.sha256)
      throw new AnalysisProtocolError(
        "capinfos SHA256 disagrees with the owned capture snapshot",
      );
    const dissected = await this.run(
      "inspect_pcap_capture",
      selection.tshark.command,
      [
        "-n",
        "-r",
        snapshot.path,
        "-T",
        "json",
        ...FIELDS.flatMap((field) => ["-e", field]),
      ],
      { timeoutMs: 300_000, maxOutputBytes: TSHARK_JSON_MAX_BYTES },
      signal,
      snapshot,
      path,
    );
    const fields = await parseTsharkJsonOutput(
      dissected.stdout,
      LIMITS,
      signal,
    );
    if (fields.packetCount !== metadata.packetCount)
      throw new AnalysisProtocolError(
        `capinfos counted ${String(metadata.packetCount)} packets but tshark returned ${String(fields.packetCount)}`,
      );
    return {
      result: {
        target: { path, ...identity },
        file_type: metadata.fileType,
        encapsulation: metadata.encapsulation,
        packet_count: metadata.packetCount,
        capture_start: metadata.captureStart,
        capture_end: metadata.captureEnd,
        capture_duration_seconds: metadata.captureDurationSeconds,
        snapshot_length: metadata.snapshotLength,
        endpoints: fields.endpoints,
        endpoint_count: fields.endpointCount,
        dns_queries: fields.dnsQueries,
        dns_query_count: fields.dnsQueryCount,
        tls_sni_values: fields.tlsSniValues,
        tls_sni_count: fields.tlsSniCount,
        protocol_distribution: fields.protocolDistribution,
        protocol_count: fields.protocolCount,
        http_request_uris: fields.httpRequestUris,
        http_request_uri_count: fields.httpRequestUriCount,
        http_uri_redaction_count: fields.httpUriRedactionCount,
        unattributed_dns_addresses: fields.unattributedDnsAddresses,
        unattributed_dns_address_count: fields.unattributedDnsAddressCount,
        unattributed_dns_packet_count: fields.unattributedDnsPackets,
        coverage: fields.partial ? "partial" : "complete",
      },
      limitations: [
        "Both tools read one owned snapshot; target identity comes from its admitted source descriptor",
        "DNS address values are associated only with a single question in the same response packet; values may include additional DNS records, not only final resolution answers",
        "Only bytes present in the saved capture are examined; encryption and capture truncation can hide higher-level fields",
        ...(fields.partial
          ? [
              "One or more projected categories were capped, credential-bearing URIs were omitted or coalesced, or DNS address attribution remains unresolved; counts retain the examined totals",
            ]
          : []),
        ...(fields.httpUriRedactionCount > 0
          ? [
              "HTTP transport credentials were excluded; ambiguous credential spans cause the URI to be omitted",
            ]
          : []),
        ...(fields.unattributedDnsPackets > 0
          ? [
              `DNS address attribution was unresolved in ${String(fields.unattributedDnsPackets)} packet(s); unattributed addresses are retained separately`,
            ]
          : []),
      ],
    };
  }
}
