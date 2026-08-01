import test from "node:test";
import assert from "node:assert/strict";
import { protocolUrl } from "../src/utils/endpoints.ts";

test("protocolUrl keeps protocol endpoints on the serving origin", () => {
  const origin = "http://127.0.0.1:5175";
  assert.equal(
    protocolUrl("/.well-known/openid-configuration", origin),
    `${origin}/.well-known/openid-configuration`
  );
  assert.equal(
    protocolUrl("/oauth/authorize?client_id=abc&scope=openid", origin),
    `${origin}/oauth/authorize?client_id=abc&scope=openid`
  );
});
