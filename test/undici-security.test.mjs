import assert from "node:assert/strict";
import { once } from "node:events";
import http from "node:http";
import { createRequire } from "node:module";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

// Commit this file under test/. Resolve from its repository location so a
// generic native dispatcher may invoke it from any working directory.
const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const projectOverride = process.env.UNDICI_TEST_PROJECT;
if (projectOverride !== undefined) {
  assert.ok(projectOverride.trim(), "UNDICI_TEST_PROJECT must be nonempty");
}
const project = path.resolve(projectOverride ?? repositoryRoot);
const require = createRequire(path.join(project, "package.json"));
const undici = require("undici");

async function withServer(handler, check) {
  const server = http.createServer(handler);
  const agent = new undici.Agent({ connections: 1, pipelining: 1, allowH2: false });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    await check(`http://127.0.0.1:${server.address().port}/`, agent);
  } finally {
    await agent.destroy();
    server.closeAllConnections();
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
}

void test("actual installed Undici is the minimum fixed 8.12.2", () => {
  assert.equal(require("undici/package.json").version, "8.12.2");
});

void test(
  "plain and compressed responses preserve fetch, Agent and JSON APIs",
  { timeout: 3000 },
  async () => {
    let count = 0;
    await withServer(
      (_req, res) => {
        const bytes = Buffer.from('{"ok":true}');
        const compressed = count++ > 0;
        res.writeHead(
          200,
          compressed
            ? { "content-encoding": "gzip", "content-type": "application/json" }
            : { "content-type": "application/json" },
        );
        res.end(compressed ? zlib.gzipSync(bytes) : bytes);
      },
      async (url, dispatcher) => {
        for (let i = 0; i < 2; i++) {
          assert.deepEqual(await (await undici.fetch(url, { dispatcher })).json(), { ok: true });
        }
      },
    );
  },
);

void test(
  "the supported five-coding boundary still decodes normally",
  { timeout: 3000 },
  async () => {
    let bytes = Buffer.from('{"ok":true}');
    for (let i = 0; i < 5; i++) {
      bytes = zlib.gzipSync(bytes);
    }
    assert.ok(bytes.length < 1024);
    await withServer(
      (_req, res) => {
        res.writeHead(200, { "content-encoding": Array(5).fill("gzip").join(",") });
        res.end(bytes);
      },
      async (url, dispatcher) =>
        assert.deepEqual(await (await undici.fetch(url, { dispatcher })).json(), { ok: true }),
    );
  },
);

void test(
  "six content codings plus early connection close rejects without an orphan stream error",
  { timeout: 3000 },
  async () => {
    await withServer(
      (_req, res) => {
        res.writeHead(200, {
          "content-encoding": Array(6).fill("gzip").join(","),
          "content-length": "1",
        });
        res.flushHeaders();
        setTimeout(() => res.destroy(), 10).unref();
      },
      async (url, dispatcher) => {
        await assert.rejects(undici.fetch(url, { dispatcher }), (error) => {
          assert.match(error.cause?.message ?? error.message, /too many content-encodings.*6.*5/);
          return true;
        });
        // Let a late unhandled stream error reach node:test; never intercept it.
        await new Promise((resolve) => {
          setTimeout(resolve, 30);
        });
      },
    );
  },
);
