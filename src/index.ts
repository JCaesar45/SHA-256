import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, extname, join, normalize, sep } from "node:path";

type Seal = {
  id: number;
  digest: string;
  label: string;
  sealedAt: string;
  prev: string;
  chain: string;
};

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

const PORT = Number(process.env.PORT ?? 8787);
const ROOT = process.cwd();
const PUBLIC_DIR = join(ROOT, "public");
const LEDGER_FILE = join(ROOT, "data", "ledger.json");
const GENESIS = "0".repeat(64);
const HEX64 = /^[0-9a-f]{64}$/;
const MAX_BODY = 1_000_000;
const MAX_TEXT = 500_000;

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

const sha256 = (input: string): string =>
  createHash("sha256").update(input, "utf8").digest("hex");

const linkHash = (prev: string, digest: string, sealedAt: string): string =>
  sha256(`${prev}|${digest}|${sealedAt}`);

class Ledger {
  private seals: Seal[] = [];
  private writing: Promise<void> = Promise.resolve();

  async load(): Promise<void> {
    if (!existsSync(LEDGER_FILE)) return;
    const raw = await readFile(LEDGER_FILE, "utf8");
    this.seals = JSON.parse(raw) as Seal[];
  }

  private persist(): Promise<void> {
    const snapshot = JSON.stringify(this.seals, null, 2);
    this.writing = this.writing
      .then(async () => {
        await mkdir(dirname(LEDGER_FILE), { recursive: true });
        await writeFile(LEDGER_FILE, snapshot, "utf8");
      })
      .catch((err) => console.error("Ledger write failed:", err));
    return this.writing;
  }

  async append(digest: string, label: string): Promise<Seal> {
    const prev = this.seals.at(-1)?.chain ?? GENESIS;
    const sealedAt = new Date().toISOString();
    const seal: Seal = {
      id: this.seals.length + 1,
      digest,
      label,
      sealedAt,
      prev,
      chain: linkHash(prev, digest, sealedAt),
    };
    this.seals.push(seal);
    await this.persist();
    return seal;
  }

  find(digest: string): Seal | undefined {
    return this.seals.find((s) => s.digest === digest);
  }

  recent(limit: number): Seal[] {
    return this.seals.slice(-limit).reverse();
  }

  get count(): number {
    return this.seals.length;
  }

  get head(): string {
    return this.seals.at(-1)?.chain ?? GENESIS;
  }

  isIntact(): boolean {
    let prev = GENESIS;
    for (const s of this.seals) {
      if (s.prev !== prev) return false;
      if (s.chain !== linkHash(s.prev, s.digest, s.sealedAt)) return false;
      prev = s.chain;
    }
    return true;
  }
}

const ledger = new Ledger();

function send(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
  });
  res.end(payload);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let dead = false;
    req.on("data", (chunk: Buffer) => {
      if (dead) return;
      size += chunk.length;
      if (size > MAX_BODY) {
        dead = true;
        chunks.length = 0;
        reject(new HttpError(413, "Request body is too large."));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (!dead) resolve(Buffer.concat(chunks).toString("utf8"));
    });
    req.on("error", reject);
  });
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const raw = await readBody(req);
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("not an object");
    }
    return parsed as Record<string, unknown>;
  } catch {
    throw new HttpError(400, "Body must be a JSON object.");
  }
}

async function serveStatic(pathname: string, method: string, res: ServerResponse): Promise<void> {
  const rel = pathname === "/" ? "/index.html" : pathname;
  const full = normalize(join(PUBLIC_DIR, rel));
  if (!full.startsWith(PUBLIC_DIR + sep)) throw new HttpError(403, "Forbidden.");
  let data: Buffer;
  try {
    data = await readFile(full);
  } catch {
    throw new HttpError(404, "Not found.");
  }
  res.writeHead(200, {
    "Content-Type": MIME[extname(full).toLowerCase()] ?? "application/octet-stream",
    "Content-Length": data.length,
    "X-Content-Type-Options": "nosniff",
  });
  res.end(method === "HEAD" ? undefined : data);
}

async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const method = req.method ?? "GET";
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  const pathname = decodeURIComponent(url.pathname);

  if (method === "GET" && pathname === "/api/health") {
    return send(res, 200, { status: "ok", seals: ledger.count });
  }

  if (method === "POST" && pathname === "/api/seal") {
    const body = await readJson(req);
    const label = typeof body.label === "string" ? body.label.trim().slice(0, 120) : "";
    let digest: string;
    if (typeof body.digest === "string") {
      digest = body.digest.trim().toLowerCase();
      if (!HEX64.test(digest)) {
        throw new HttpError(400, "digest must be 64 hexadecimal characters.");
      }
    } else if (typeof body.text === "string") {
      if (body.text.length > MAX_TEXT) throw new HttpError(413, "text is too long.");
      digest = sha256(body.text);
    } else {
      throw new HttpError(400, "Send either digest or text.");
    }
    return send(res, 201, await ledger.append(digest, label));
  }

  if (method === "GET" && pathname.startsWith("/api/verify/")) {
    const digest = pathname.slice("/api/verify/".length).toLowerCase();
    if (!HEX64.test(digest)) {
      throw new HttpError(400, "digest must be 64 hexadecimal characters.");
    }
    const seal = ledger.find(digest);
    return seal
      ? send(res, 200, { verified: true, seal })
      : send(res, 404, { verified: false, error: "No seal exists for this digest." });
  }

  if (method === "GET" && pathname === "/api/ledger") {
    return send(res, 200, {
      intact: ledger.isIntact(),
      count: ledger.count,
      head: ledger.head,
      recent: ledger.recent(20),
    });
  }

  if (pathname.startsWith("/api/")) throw new HttpError(404, "Unknown endpoint.");

  if (method === "GET" || method === "HEAD") return serveStatic(pathname, method, res);

  throw new HttpError(405, "Method not allowed.");
}

async function main(): Promise<void> {
  await ledger.load();
  const server = createServer((req, res) => {
    route(req, res).catch((err: unknown) => {
      if (res.headersSent) {
        res.end();
        return;
      }
      if (err instanceof HttpError) return send(res, err.status, { error: err.message });
      if (err instanceof URIError) return send(res, 400, { error: "Malformed URL." });
      console.error(err);
      send(res, 500, { error: "Internal server error." });
    });
  });
  server.listen(PORT, () => console.log(`Aurum Seal listening on http://localhost:${PORT}`));
  process.on("SIGINT", () => server.close(() => process.exit(0)));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
