# Packet capture analysis

REA inspects saved pcap and pcapng capture files through the caller's
tshark and capinfos binaries from the Wireshark suite. It answers analyst
questions about observed hosts, DNS, TLS, and protocol distributions from
a local capture file, complementing the HTTP-level HAR and mitmproxy
family with the packet layer below it.

REA never captures traffic itself and never installs the Wireshark suite;
both operations read an already-saved file.

## Supply tools

Use tshark and capinfos from any Wireshark installation (verified with
4.6.6). Select them through the environment:

```sh
# Optional: absolute paths; without them, both resolve from PATH.
export REA_TSHARK_COMMAND=/absolute/path/tshark
export REA_CAPINFOS_COMMAND=/absolute/path/capinfos
```

Readiness is `rea inspect-pcap-client`: it runs `--version` on both
binaries and reports their selected commands, selection sources, and
versions. Both binaries must be usable. Missing or invalid tools report
`capability_unavailable`; select them with `REA_TSHARK_COMMAND` and
`REA_CAPINFOS_COMMAND`.

## Answer an analyst question

```sh
rea inspect-pcap-client
rea inspect-pcap-capture /captures/session.pcap
```

Equivalent MCP methods are `inspect_pcap_client` and
`inspect_pcap_capture` with the same `path`.

## Interpret the result

- **`target.sha256`** binds the observation to the exact capture file.
- **`file_type`** distinguishes pcap from pcapng as capinfos reports it;
  **`encapsulation`** names the link-layer format (Ethernet, Linux
  cooked-mode, etc.).
- **`packet_count`**, **`capture_start`**/**`capture_end`**, and
  **`capture_duration_seconds`** describe the capture window.
- **`endpoints`** lists IPv4 and IPv6 addresses, counting an address at
  most once per packet. It retains 200 entries with the exact `endpoint_count`.
- **`dns_queries`** retains 100 observed question names. Address values are
  associated only with a single question in the same response packet; they
  may include additional DNS records, not just final resolution answers.
  Each query retains 100 addresses and its exact `response_address_count`.
  Multi-question and missing-question address records remain in
  `unattributed_dns_addresses` with explicit address/packet counts.
- **`tls_sni_values`** reports Server Name Indication from TLS
  handshakes — the hostname evidence in encrypted traffic.
- **`protocol_distribution`** counts each `frame.protocols` value.
- **`http_request_uris`** lists plain-text HTTP requests, bounded to 50.
  Transport credentials are excluded without changing other URL bytes;
  ambiguous credential-bearing URLs are omitted. `http_uri_redaction_count`
  counts affected distinct source URIs and `http_request_uri_count` counts
  all distinct observed URIs before redaction or projection limits.
- SNI and protocol lists retain 50 values each, with `tls_sni_count` and
  `protocol_count` exposing the full examined totals.
- **`coverage: "partial"`** appears when any category is truncated or DNS
  address attribution remains unresolved, including URIs omitted or coalesced
  after credential exclusion.
- The capture's own SHA-256 from capinfos is compared against REA's
  snapshot digest; a mismatch is a protocol refusal.

## Resource and lifecycle limits

- tshark output is budgeted at 8 MiB to bound JSON expansion; its selected-field
  shape and a conservative 128 MiB expansion estimate are checked before
  decoding. Retained facts have a separate 16 MiB
  estimated-memory budget. capinfos output is bounded at 64 KiB; both tools
  run with a timeout (300 s for tshark, 60 s for capinfos).
- The capture is copied from one admitted regular-file descriptor into an
  owned read-only snapshot, bounded at 2 GiB. Identity is rechecked after the
  copy, and both tools consume those same bytes. Source permission and change
  errors remain typed; failed cleanup stays owned for retry on close.
- Commands use shared process supervision. Cancellation reaches probes,
  snapshot acquisition, tool execution and JSON processing. `tshark -n`
  disables name resolution, and `capinfos -M` supplies exact numeric values.
- REA runs no subprocess for `inspect_pcap_client` beyond `--version`.

## Companion flows

With the ADB family, a complete Android triage is one session:
`pull_adb_file` retrieves a capture produced on-device by tcpdump or
iptables NFLOG, then `inspect_pcap_capture` decodes it. The network
capture roadmap documents per-app filtering through iptables owner match
feeding NFLOG with per-packet UID attribution.

## Platform coverage

Cross-platform fixtures exercise the provider contract through `.cmd`
(Windows) and `.sh` (POSIX) scripts. Windows batch files use the shared
explicit cmd.exe invocation boundary and require REA's native ownership controls.

Real-engine verification covers Linux with Wireshark 4.6.6 and a macOS Sonoma
14.8.9 x86-64 guest with Wireshark 4.6.9 and Node 24.18.0. The macOS runs check
real CLI/MCP capture results, DNS attribution, IPv6, projection bounds, exact
packet counts, pcapng and owned cleanup; 47 focused pcap tests and 22 native
process-reader tests also pass there. Windows 11 x64 build 26300.9457 is verified
with Node 24.18.0 and Wireshark 4.6.9 under a non-administrator account: real
CLI/MCP capture checks, all six semantic captures, 32 focused tests and the
native-control conformance lane pass. The 15 POSIX process-fixture tests remain
skipped on Windows; they are covered by the Linux/macOS runs.

macOS process ownership requires the Apple command-line tools. Initial Swift
SDK-cache preparation is separate from the tool's execution timeout and has a
120-second compiler budget; subsequent preparations reuse the SDK cache. The
fresh VM's cold compiler took 88 seconds, versus about two seconds when warm.
An isolated empty SDK-cache check also completed within the revised budget.

## Real verification

`npm run verify:pcap -- --pcap PATH` exercises compiled CLI and stdio MCP,
validates their named output schemas, compares Evidence and checks input
identity and snapshot cleanup. Without `--pcap`, capture inspection is
explicitly reported as unverified. Record: tshark/capinfos 4.6.6 (Alpine Docker image)
against two real captures: a 50-packet Docker-captured pcap with DNS,
TLS, and HTTP traffic, and a 30-packet Android emulator capture (tcpdump
on-device, pulled via `adb pull`) containing DNS, mDNS, ICMP, and Google
endpoints — file type, encapsulation, packet count, SHA-256 digest
agreement, endpoint inventory, DNS queries, TLS SNI values, protocol
distribution and HTTP URIs where present. Additional generated captures cover
interleaved DNS replies, IPv6, SNI truncation and large packet counts. A pcapng
conversion of the 50-packet capture also passes the same CLI/MCP verifier.
Synthetic process fixtures verify failure and cancellation behavior; they
do not establish real-engine behavior on untested hosts.

Verifier workspaces are shared temporary parents, not leased provider runtimes;
each child owns its own snapshots. Cleanup must finish and leave that parent
empty before verification succeeds. Unreleased resources are retained for
inspection instead of being recursively removed by the verifier.
