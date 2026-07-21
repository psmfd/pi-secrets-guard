/**
 * Detection-logic tests (#796, ADR-0111) — direct coverage of the exported
 * checkers (checkWriteLikeCall / checkBashCall), which the tool_call handler
 * delegates to. Fixture literals are synthetic and none is a real
 * credential; pattern-shaped strings are assembled at runtime (split
 * literals / repeat()) so the guard layers scanning THIS source file see no
 * contiguous secret pattern.
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import { __testing, checkBashCall, checkWriteLikeCall } from "../index.ts";

const NO_ALLOW: string[] = [];

// Assembled at runtime — see the header note.
const PEM_RSA = ["-----BEGIN RSA", "PRIVATE KEY-----"].join(" ");
const PEM_PKCS8 = ["-----BEGIN ENCRYPTED", "PRIVATE KEY-----"].join(" ");
const AWS_KEY = ["AKIA", "ABCDEFGHIJKLMNOP"].join("");
const GH_TOKEN = `ghp_${"a".repeat(36)}`;
const GH_PAT = `github_pat_${"a".repeat(82)}`;
const JWT = `eyJ${"a".repeat(20)}.eyJ${"b".repeat(20)}.${"c".repeat(20)}`;
const BEARER = `Authorization: Bearer ${"t".repeat(24)}`;

function write(path: string, content: string, allowlist: string[] = NO_ALLOW): string | null {
  return checkWriteLikeCall("write", { path, content }, allowlist);
}

// --- One blocked write per content-pattern class -----------------------------

test("write blocked for each of the six content-pattern classes", () => {
  const fixtures: Array<[string, string]> = [
    ["pem-private-key", `${PEM_RSA}\nMIIB...`],
    ["pem-private-key", `${PEM_PKCS8}\nMIIB...`],
    ["aws-access-key", `aws_access_key_id = ${AWS_KEY}`],
    ["github-token", `token = ${GH_TOKEN}`],
    ["github-pat-fine-grained", `token = ${GH_PAT}`],
    ["signed-jwt", `bearer ${JWT}`],
    ["authorization-bearer", BEARER],
  ];
  for (const [name, content] of fixtures) {
    const reason = write("notes/config.txt", content);
    assert.ok(reason?.includes(name), `${name}: ${String(reason)}`);
  }
});

test("clean content is allowed", () => {
  assert.equal(write("notes/config.txt", "just ordinary text"), null);
});

// --- Vault naming -------------------------------------------------------------

test("vault-named plaintext blocked; $ANSIBLE_VAULT header allowed", () => {
  assert.ok(write("group_vars/all/vault.yml", "password: hunter2")?.includes("vault-naming"));
  assert.equal(
    write("group_vars/all/vault.yml", "$ANSIBLE_VAULT;1.1;AES256\n3939..."),
    null,
  );
});

test("vault anywhere in the basename is caught (#796 drift fix)", () => {
  // Previously start-anchored: these two sailed through the in-session layer
  // while the pre-commit hook caught them.
  assert.ok(write("secrets/prod-vault.yml", "password: hunter2")?.includes("vault-naming"));
  assert.ok(write("myvault.yaml", "password: hunter2")?.includes("vault-naming"));
  // A vault-named path under tests/ is still a skip path.
  assert.equal(write("tests/prod-vault.yml", "password: hunter2"), null);
});

// --- Sensitive paths ----------------------------------------------------------

test("sensitive basenames are hard-refused, including FIDO2 keys", () => {
  for (const p of ["id_rsa", ".ssh/id_ed25519", "keys/id_ed25519_sk", "id_ecdsa_sk", "server.pem", "tls.key"]) {
    assert.ok(write(p, "anything")?.includes("sensitive file"), p);
  }
});

// --- Skip patterns and allowlist -----------------------------------------------

test("skip patterns and allowlist suppress the content scan", () => {
  const secret = `token = ${GH_TOKEN}`;
  assert.equal(write("config.example", secret), null);
  assert.equal(write("fixtures/token.txt", secret), null);
  assert.equal(write("real/config.txt", secret, ["real/*.txt"]), null);
  assert.ok(write("real/config.txt", secret) !== null);
});

// --- Fail-toward-scanning on missing path (#796) --------------------------------

test("missing path still runs the content scan instead of failing open", () => {
  assert.ok(
    checkWriteLikeCall("write", { content: `token = ${GH_TOKEN}` }, NO_ALLOW)?.includes(
      "github-token",
    ),
  );
  assert.equal(checkWriteLikeCall("write", { content: "clean" }, NO_ALLOW), null);
});

// --- Edit shape -----------------------------------------------------------------

test("edit newText is scanned; oldText (removal) is not", () => {
  assert.ok(
    checkWriteLikeCall(
      "edit",
      { path: "a.txt", edits: [{ oldText: "x", newText: GH_TOKEN }] },
      NO_ALLOW,
    )?.includes("github-token"),
  );
  assert.equal(
    checkWriteLikeCall(
      "edit",
      { path: "a.txt", edits: [{ oldText: GH_TOKEN, newText: "<REDACTED>" }] },
      NO_ALLOW,
    ),
    null,
  );
});

// --- Bash branch ------------------------------------------------------------------

test("bash: inline literals and sensitive-path reads blocked; public keys allowed", () => {
  assert.ok(checkBashCall({ command: `echo ${GH_TOKEN}` })?.includes("github-token"));
  assert.ok(checkBashCall({ command: "cat ~/.aws/credentials" })?.includes("sensitive credential"));
  assert.ok(checkBashCall({ command: "cat ~/.ssh/id_ed25519" })?.includes("sensitive credential"));
  assert.ok(checkBashCall({ command: "cat ~/.ssh/id_ed25519_sk" })?.includes("sensitive credential"));
  // Public keys are not secrets (#796): reading .pub is legitimate.
  assert.equal(checkBashCall({ command: "cat ~/.ssh/id_ed25519.pub" }), null);
  assert.equal(checkBashCall({ command: "ls -la" }), null);
  assert.equal(checkBashCall({}), null);
});

// --- Helper invariants ---------------------------------------------------------------

test("pattern helpers agree with the documented six-detector set", () => {
  assert.deepEqual(
    __testing.SECRET_PATTERNS.map((p) => p.name),
    [
      "pem-private-key",
      "aws-access-key",
      "github-token",
      "github-pat-fine-grained",
      "signed-jwt",
      "authorization-bearer",
    ],
  );
});
