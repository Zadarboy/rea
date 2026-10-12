import { describe, expect, it, vi } from "vitest";

import { CdpBrowserProvider } from "../../../src/browser/CdpBrowserProvider.js";
import {
  inspectWebPageInputSchema,
  listBrowserTargetsInputSchema,
} from "../../../src/domain/browserObservation.js";
import { startFakeCdpBrowser } from "../../fixtures/fakeCdpBrowser.js";
import { trackBrowser } from "./cdpBrowserProvider.support.js";

describe("CdpBrowserProvider: browser socket without HTTP discovery", () => {
  it("discovers and inspects a page through one browser socket", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const provider = new CdpBrowserProvider();
    const throughHttp = await provider.listTargets(
      listBrowserTargetsInputSchema.parse({ cdp_endpoint: browser.endpoint }),
    );
    if (!throughHttp.ok) throw throughHttp.error;
    const httpRequests = browser.httpRequests.length;
    const openedBefore = browser.openedConnectionCount();

    const listed = await provider.listTargets(
      listBrowserTargetsInputSchema.parse({
        cdp_endpoint: browser.browserWebSocketUrl,
      }),
    );
    if (!listed.ok) throw listed.error;
    expect(listed.value.targets).toEqual(throughHttp.value.targets);
    expect(listed.value.excluded).toEqual(throughHttp.value.excluded);
    expect(listed.value.browser).toEqual({
      ...throughHttp.value.browser,
      revision: "@fake-revision",
    });

    const commandsBefore = browser.commands.length;
    const inspected = await provider.inspectPage(
      inspectWebPageInputSchema.parse({
        cdp_endpoint: browser.browserWebSocketUrl,
        target_id: "allowed-page",
        observation_ms: 0,
      }),
    );
    if (!inspected.ok) throw inspected.error;
    expect(inspected.value.target.origin).toBe(browser.allowedOrigin);
    expect(
      browser.commands
        .slice(commandsBefore, commandsBefore + 3)
        .map(({ method, params }) => ({ method, params })),
    ).toEqual([
      { method: "Browser.getVersion", params: {} },
      { method: "Target.getTargets", params: {} },
      {
        method: "Target.attachToTarget",
        params: { targetId: "allowed-page", flatten: true },
      },
    ]);
    expect(browser.httpRequests).toHaveLength(httpRequests);
    expect(browser.openedConnectionCount()).toBe(openedBefore + 2);
    await vi.waitFor(() => expect(browser.activeConnectionCount()).toBe(0));
  });

  it("closes an unadopted browser socket when the target is missing", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const result = await new CdpBrowserProvider().inspectPage(
      inspectWebPageInputSchema.parse({
        cdp_endpoint: browser.browserWebSocketUrl,
        target_id: "missing",
        observation_ms: 0,
      }),
    );

    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "BrowserObservationError", reason: "target_not_found" },
    });
    expect(browser.commands.map(({ method }) => method)).toEqual([
      "Browser.getVersion",
      "Target.getTargets",
    ]);
    await vi.waitFor(() => expect(browser.activeConnectionCount()).toBe(0));
  });

  it("rejects malformed browser-socket discovery and closes the socket", async () => {
    const browser = await startFakeCdpBrowser({
      commandResult: ({ method }) =>
        method === "Browser.getVersion"
          ? { product: "FakeChrome/1.0" }
          : undefined,
    });
    trackBrowser(browser);
    const result = await new CdpBrowserProvider().listTargets(
      listBrowserTargetsInputSchema.parse({
        cdp_endpoint: browser.browserWebSocketUrl,
      }),
    );

    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "BrowserObservationError",
        operation: "list_browser_targets",
        reason: "invalid_endpoint_response",
      },
    });
    await vi.waitFor(() => expect(browser.activeConnectionCount()).toBe(0));
  });

  it("reports a refused browser socket as unreachable", async () => {
    const browser = await startFakeCdpBrowser();
    trackBrowser(browser);
    const result = await new CdpBrowserProvider().listTargets(
      listBrowserTargetsInputSchema.parse({
        cdp_endpoint: browser.browserWebSocketUrl.replace(
          /fake$/u,
          "not-this-browser",
        ),
      }),
    );

    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "BrowserObservationError",
        reason: "endpoint_unreachable",
      },
    });
    expect(JSON.stringify(result)).not.toContain("not-this-browser");
  });

  it("cancels browser-socket discovery and releases the socket", async () => {
    const browser = await startFakeCdpBrowser({
      hangOnMethod: "Target.getTargets",
    });
    trackBrowser(browser);
    const controller = new AbortController();
    const pending = new CdpBrowserProvider().inspectPage(
      inspectWebPageInputSchema.parse({
        cdp_endpoint: browser.browserWebSocketUrl,
        target_id: "allowed-page",
        observation_ms: 0,
      }),
      { signal: controller.signal },
    );
    await vi.waitFor(() =>
      expect(browser.commands.map(({ method }) => method)).toContain(
        "Target.getTargets",
      ),
    );
    controller.abort();

    expect(await pending).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError", operation: "inspect_web_page" },
    });
    expect(browser.commands.map(({ method }) => method)).not.toContain(
      "Target.attachToTarget",
    );
    await vi.waitFor(() => expect(browser.activeConnectionCount()).toBe(0));
  });
});
