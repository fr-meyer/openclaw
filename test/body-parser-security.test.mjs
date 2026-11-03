import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { once } from "node:events";
import http from "node:http";
import { createRequire } from "node:module";
import path from "node:path";
import test from "node:test";
import zlib from "node:zlib";

const project = path.resolve(process.env.BODY_PARSER_TEST_PROJECT ?? process.cwd());
const projectRequire = createRequire(path.join(project, "package.json"));
const express = projectRequire("express");
const expressRequire = createRequire(projectRequire.resolve("express/package.json"));
const parser = process.env.BODY_PARSER_TEST_MODULE
  ? projectRequire(process.env.BODY_PARSER_TEST_MODULE)
  : expressRequire("body-parser");

async function withServer(handler, operation) {
  const server = http.createServer(handler);
  server.requestTimeout = 2000;
  server.headersTimeout = 2000;
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    return await operation(server.address().port);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

function request(port, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const client = http.request(
      {
        host: "127.0.0.1",
        port,
        path: "/",
        method: "POST",
        agent: false,
        headers: { "content-type": "application/json", "content-length": body.length, ...headers },
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("error", reject);
        response.on("end", () =>
          resolve({
            status: response.statusCode,
            body: JSON.parse(Buffer.concat(chunks)),
            headers: response.headers,
          }),
        );
      },
    );
    client.on("error", reject);
    client.setTimeout(1500, () => client.destroy(new Error("synthetic request timeout")));
    client.end(body);
  });
}

function appFor(middleware) {
  const app = express();
  app.use(middleware);
  app.post("/", (req, res) => res.json(req.body));
  app.use((error, _req, res, _next) => res.status(error.status || 500).json({ type: error.type }));
  return app;
}

test("exact actual Express/parser/qs dependency identity", () => {
  assert.equal(projectRequire("express/package.json").version, "5.2.1");
  assert.equal(expressRequire("body-parser/package.json").version, "2.4.0");
  const parserRequire = createRequire(expressRequire.resolve("body-parser/package.json"));
  assert.equal(parserRequire("qs/package.json").version, "6.16.1");
  assert.equal(expressRequire("qs/package.json").version, "6.16.1");
});

test("plain and leading-whitespace JSON preserve ordinary data", { timeout: 3000 }, async () => {
  await withServer(appFor(parser.json()), async (port) => {
    for (const json of ['{"a":1}', ' \r\n\t{"a":1}']) {
      const result = await request(port, Buffer.from(json));
      assert.equal(result.status, 200);
      assert.deepEqual(result.body, { a: 1 });
    }
  });
});

test("strict scalar and malformed JSON remain rejected", { timeout: 3000 }, async () => {
  await withServer(appFor(parser.json()), async (port) => {
    for (const json of ["1", "{bad}"]) {
      const result = await request(port, Buffer.from(json));
      assert.equal(result.status, 400);
      assert.equal(result.body.type, "entity.parse.failed");
    }
  });
});

const compressors = [
  ["gzip", zlib.gzipSync],
  ["deflate", zlib.deflateSync],
  ["br", zlib.brotliCompressSync],
  ...(zlib.zstdCompressSync ? [["zstd", zlib.zstdCompressSync]] : []),
];
for (const [encoding, compress] of compressors) {
  test(`normal ${encoding} JSON remains supported`, { timeout: 3000 }, async () => {
    const body = compress(Buffer.from('{"a":1}'));
    await withServer(appFor(parser.json()), async (port) => {
      const result = await request(port, body, { "content-encoding": encoding });
      assert.equal(result.status, 200);
      assert.deepEqual(result.body, { a: 1 });
    });
  });
}

test("identity and compressed JSON size limits remain enforced", { timeout: 3000 }, async () => {
  await withServer(appFor(parser.json({ limit: 8 })), async (port) => {
    const json = Buffer.from('{"a":"123456789"}');
    for (const [body, headers] of [
      [json, {}],
      [zlib.gzipSync(json), { "content-encoding": "gzip" }],
    ]) {
      const result = await request(port, body, headers);
      assert.equal(result.status, 413);
      assert.equal(result.body.type, "entity.too.large");
    }
  });
});

test("malformed compression is handled without process failure", { timeout: 3000 }, async () => {
  await withServer(appFor(parser.json()), async (port) => {
    const result = await request(port, Buffer.from("bad"), { "content-encoding": "gzip" });
    assert.equal(result.status, 400);
  });
});

test(
  "finished compressed decoder is detached, destroyed and guarded before downstream middleware",
  { timeout: 3000 },
  async () => {
    let observed;
    const app = express();
    app.use((req, res, next) => {
      let decoder;
      const detached = [];
      const originalPipe = req.pipe;
      const originalUnpipe = req.unpipe;
      req.pipe = function (destination, ...args) {
        decoder = destination;
        return originalPipe.call(this, destination, ...args);
      };
      req.unpipe = function (destination) {
        detached.push(destination);
        return originalUnpipe.call(this, destination);
      };
      parser.json()(req, res, (error) => {
        if (error) return next(error);
        observed = {
          destroyed: decoder.destroyed,
          detachedOnlyDecoder: detached.includes(decoder),
          terminalErrorHandler: decoder.listenerCount("error") > 0,
        };
        next();
      });
    });
    app.post("/", (req, res) => res.json(req.body));
    await withServer(app, async (port) => {
      const result = await request(port, zlib.gzipSync(Buffer.from('{"a":1}')), {
        "content-encoding": "gzip",
      });
      assert.equal(result.status, 200);
      assert.deepEqual(result.body, { a: 1 });
      assert.deepEqual(observed, {
        destroyed: true,
        detachedOnlyDecoder: true,
        terminalErrorHandler: true,
      });
    });
  },
);

test(
  "unsupported charset with verify returns 415 before an orphan decoder exists",
  { timeout: 3000 },
  async () => {
    let verified = false;
    await withServer(
      appFor(
        parser.json({
          verify() {
            verified = true;
          },
        }),
      ),
      async (port) => {
        const body = Buffer.concat([
          zlib.gzipSync(Buffer.from('{"a":1}')),
          Buffer.from([0]),
          Buffer.alloc(1024, 0x58),
        ]);
        const result = await request(port, body, {
          "content-type": "application/json; charset=utf-999",
          "content-encoding": "gzip",
        });
        assert.equal(result.status, 415);
        assert.equal(result.body.type, "charset.unsupported");
        assert.equal(verified, false);
        await new Promise((resolve) => setTimeout(resolve, 20));
      },
    );
  },
);

test(
  "urlencoded nested data, parameter and depth limits remain enforced",
  { timeout: 3000 },
  async () => {
    const contentType = { "content-type": "application/x-www-form-urlencoded" };
    await withServer(
      appFor(parser.urlencoded({ extended: true, parameterLimit: 3, depth: 2 })),
      async (port) => {
        const valid = await request(
          port,
          Buffer.from("user[name]=Ada&tags[]=a&tags[]=b"),
          contentType,
        );
        assert.equal(valid.status, 200);
        assert.deepEqual(valid.body, { user: { name: "Ada" }, tags: ["a", "b"] });
        const tooMany = await request(port, Buffer.from("a=1&b=2&c=3&d=4"), contentType);
        assert.equal(tooMany.status, 413);
        assert.equal(tooMany.body.type, "parameters.too.many");
        const tooDeep = await request(port, Buffer.from("a[b][c][d]=1"), contentType);
        assert.equal(tooDeep.status, 400);
        assert.equal(tooDeep.body.type, "querystring.parse.rangeError");
      },
    );
  },
);

test("compressed urlencoded and simple form data remain supported", { timeout: 3000 }, async () => {
  await withServer(appFor(parser.urlencoded({ extended: false })), async (port) => {
    const result = await request(port, zlib.gzipSync(Buffer.from("name=Ada&role=ops")), {
      "content-type": "application/x-www-form-urlencoded",
      "content-encoding": "gzip",
    });
    assert.equal(result.status, 200);
    assert.deepEqual(result.body, { name: "Ada", role: "ops" });
  });
});

async function trailingDeflate(preserveSecondConsumer) {
  const first = Buffer.concat([zlib.deflateSync(Buffer.from('{"a":1}')), Buffer.from([0])]);
  const trailing = Buffer.alloc(1024);
  const expectedHash = createHash("sha256").update(first).update(trailing).digest("hex");
  let client;
  const app = express();
  app.use((req, res, next) => {
    const hash = preserveSecondConsumer ? createHash("sha256") : null;
    if (hash) req.pipe(hash);
    parser.json()(req, res, (error) => {
      if (error) return next(error);
      if (hash)
        hash.once("finish", () => {
          res.setHeader("X-Body-SHA256", hash.digest("hex"));
          next();
        });
      else req.once("end", next);
      // The trailing bytes are deliberately released only after the parser has
      // finished, matching the vendor's focused lifecycle regression.
      client.end(trailing);
    });
  });
  app.post("/", (req, res) => res.json(req.body));
  app.use((error, _req, res, _next) => res.status(error.status || 500).json({ type: error.type }));
  try {
    await withServer(app, async (port) => {
      const result = await new Promise((resolve, reject) => {
        client = http.request(
          {
            host: "127.0.0.1",
            port,
            method: "POST",
            agent: false,
            headers: {
              "content-type": "application/json",
              "content-encoding": "deflate",
              "content-length": first.length + trailing.length,
            },
          },
          (response) => {
            const chunks = [];
            response.on("data", (chunk) => chunks.push(chunk));
            response.on("error", reject);
            response.on("end", () =>
              resolve({
                status: response.statusCode,
                body: JSON.parse(Buffer.concat(chunks)),
                headers: response.headers,
              }),
            );
          },
        );
        client.on("error", reject);
        client.setTimeout(1500, () =>
          client.destroy(new Error("finished-decoder lifecycle timeout")),
        );
        client.write(first);
      });
      assert.equal(result.status, 200);
      assert.deepEqual(result.body, { a: 1 });
      if (preserveSecondConsumer) assert.equal(result.headers["x-body-sha256"], expectedHash);
    });
  } finally {
    client?.destroy();
  }
}

test(
  "finished deflate decoder drains the remaining request without a hang",
  { timeout: 3000 },
  () => trailingDeflate(false),
);
test("finished decoder cleanup preserves an independent piped consumer", { timeout: 3000 }, () =>
  trailingDeflate(true),
);
