import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import config from "../vite.config.ts";

const proxy = config.server.proxy;

test("vite dev server stays on 5175 and proxies API, health, and protocol routes", () => {
  assert.equal(config.server.port, 5175);
  assert.equal(config.server.strictPort, true);
  for (const prefix of [
    "/api",
    "/health",
    "/.well-known",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/revoke",
    "/oauth/userinfo",
    "/auth/external",
  ]) {
    assert.equal(
      proxy[prefix],
      "http://127.0.0.1:3000",
      `missing proxy for ${prefix}`
    );
  }
});

test("vite proxy covers every non-API backend route used by the SPA", () => {
  const repoRoot = new URL("../..", import.meta.url);
  const apiSource = readFileSync(new URL("src/api.rs", repoRoot), "utf8");
  const backendRoutes = [...apiSource.matchAll(/\.route\("([^"]+)"/g)].map((match) => match[1]);
  const protocolRoutes = backendRoutes.filter(
    (route) => !route.startsWith("/api") && !route.startsWith("/health") && !route.startsWith("/admin")
  );

  assert.ok(protocolRoutes.length > 0);
  for (const route of protocolRoutes) {
    const proxied = Object.keys(proxy).some(
      (prefix) => route === prefix || route.startsWith(`${prefix}/`)
    );
    assert.ok(proxied, `proxy does not cover backend route ${route}`);
  }
});
