import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { connectMcpClient, disposeMcpClient, McpClientConnectTimeoutError } from "./mcp-client-lifecycle.js";
import { OpenClawStdioClientTransport } from "./mcp-stdio-transport.js";
import { createAgentCleanupScope } from "./run-cleanup-timeout.js";

const identityLoss = () => new Error(
  "service child cleanup identity lost: anchor channel closed without a matching closing receipt",
);

/** Model failed owned-process extinction, without spawning a process or contacting Pricelabs. */
class CleanupFixture extends OpenClawStdioClientTransport {
  private fixtureClosing?: Promise<void>;

  constructor(
    private readonly failure?: Error,
    private readonly delayMs = 0,
    private readonly initialization: "silent" | "fail" | "success" = "silent",
  ) {
    super({ command: "unused-owned-process-fixture" });
  }

  override async start(): Promise<void> {}

  override async send(message: JSONRPCMessage): Promise<void> {
    if (!("method" in message) || message.method !== "initialize" || !("id" in message)) {
      return;
    }
    if (this.initialization === "silent") {
      return;
    }
    queueMicrotask(() => this.onmessage?.(
      this.initialization === "fail"
        ? { jsonrpc: "2.0", id: message.id, error: { code: -32603, message: "fixture initialization refused" } }
        : { jsonrpc: "2.0", id: message.id, result: {
            protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "fixture", version: "1" },
          } },
    ));
  }

  override close(): Promise<void> {
    this.fixtureClosing ??= new Promise((resolve, reject) => setTimeout(() => {
      if (this.failure) {
        reject(this.failure);
      } else {
        resolve();
      }
    }, this.delayMs));
    // The existing transport observes its own promise; the SDK's derived promise is the leak.
    void this.fixtureClosing.catch(() => {});
    return this.fixtureClosing;
  }

  override forceClose(): Promise<void> {
    return this.close();
  }
}

describe("SDK initialization cleanup rejection ownership", () => {
  it.each([0, 60])("contains identity-loss rejection after timeout (delay %dms)", async (delayMs) => {
    const failure = identityLoss();
    const transport = new CleanupFixture(failure, delayMs);
    const client = new Client({ name: "cleanup-regression", version: "1" });
    const receipt = createAgentCleanupScope();
    const unhandled: unknown[] = [];
    const listener = (error: unknown) => { unhandled.push(error); };
    process.on("unhandledRejection", listener);
    try {
      await receipt.run(async () => {
        await expect(connectMcpClient({ client, transport, timeoutMs: 20 })).rejects.toBeInstanceOf(McpClientConnectTimeoutError);
        const observedClose = client.close;
        await expect(connectMcpClient({ client, transport, timeoutMs: 20 })).rejects.toThrow();
        expect(client.close).toBe(observedClose);
        await expect(client.close()).rejects.toBe(failure);
        await expect(disposeMcpClient({ client, transport, transportType: "stdio" }, 10)).resolves.toBe("uncertain");
        await new Promise((resolve) => setTimeout(resolve, 100));
      });
      expect(receipt.outcome).toBe("uncertain");
      expect(unhandled).toEqual([]);
    } finally {
      process.off("unhandledRejection", listener);
    }
  });

  it("contains cleanup rejection after a non-timeout SDK initialize error", async () => {
    const transport = new CleanupFixture(identityLoss(), 0, "fail");
    const client = new Client({ name: "cleanup-regression", version: "1" });
    const receipt = createAgentCleanupScope();
    await receipt.run(async () => {
      await expect(connectMcpClient({ client, transport, timeoutMs: 1000 })).rejects.toThrow("fixture initialization refused");
      await expect(disposeMcpClient({ client, transport, transportType: "stdio" })).resolves.toBe("uncertain");
      await new Promise((resolve) => setImmediate(resolve));
    });
    expect(receipt.outcome).toBe("uncertain");
  });

  it("preserves close promise identity and receiver binding", async () => {
    const failure = identityLoss();
    const closing = Promise.reject(failure);
    void closing.catch(() => {});
    const client = {
      connect: async () => { throw new Error("fixture initialize failure"); },
      close() { expect(this).toBe(client); return closing; },
    };
    const transport = new CleanupFixture();
    await expect(connectMcpClient({ client, transport, timeoutMs: 1000 })).rejects.toThrow("fixture initialize failure");
    expect(client.close()).toBe(closing);
    await expect(client.close()).rejects.toBe(failure);
  });

  it("reports successful initialization and cleanup as closed", async () => {
    const transport = new CleanupFixture(undefined, 0, "success");
    const client = new Client({ name: "cleanup-regression", version: "1" });
    const receipt = createAgentCleanupScope();
    await receipt.run(async () => {
      await connectMcpClient({ client, transport, timeoutMs: 1000 });
      await expect(disposeMcpClient({ client, transport, transportType: "stdio" })).resolves.toBe("closed");
    });
    expect(receipt.outcome).toBe("closed");
  });
});
