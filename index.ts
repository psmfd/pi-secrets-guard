/**
 * secrets-guard — pi extension
 *
 * Blocks tool calls (write, edit, bash) that would commit or surface secrets.
 * Companion to the git pre-commit hook of the same name. Both layers share
 * the same pattern set (defined in this file) and override mechanisms.
 *
 * What it blocks:
 *   - PEM private-key headers in write/edit content or bash heredoc bodies
 *   - AWS access key IDs (AKIA/ASIA/ABIA/ACCA + 16 alnum)
 *   - GitHub personal access tokens (ghp_*, github_pat_*)
 *   - Vault-named files written without the $ANSIBLE_VAULT header
 *   - Sensitive file paths (id_rsa, *.pem, *.key) being written
 *   - bash commands referencing sensitive file paths in unsafe ways
 *     (cat ~/.aws/credentials, etc.)
 *
 * Override mechanisms (lowest blast radius first):
 *   - SKIP_SECRETS_GUARD=1 in pi's env  (disables this extension session-wide)
 *   - .secrets-guard-allowlist at repo root (per-path glob allowlist)
 *
 * Skip patterns: *.example, *.sample, *.template, *.j2; molecule/, tests/,
 * spec/, fixtures/.
 *
 * Source rule: agent/rules/secrets-guard.md
 */

import { existsSync, readFileSync } from "node:fs";
import { basename } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

// --- Shared pattern set -----------------------------------------------------
// Keep this in lockstep with hooks/secrets-guard.sh.

const SECRET_PATTERNS: Array<{ name: string; re: RegExp }> = [
  {
    name: "pem-private-key",
    re: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP |)PRIVATE KEY/,
  },
  {
    name: "aws-access-key",
    re: /(^|[^A-Z0-9])(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}([^A-Z0-9]|$)/,
  },
  { name: "github-pat-classic", re: /ghp_[A-Za-z0-9]{36}/ },
  { name: "github-pat-fine-grained", re: /github_pat_[A-Za-z0-9_]{82}/ },
];

const VAULT_HEADER_RE = /^\$ANSIBLE_VAULT;[0-9]+\.[0-9]+;[A-Z0-9]+/;

const SKIP_PATH_GLOBS = [
  /\.example$/,
  /\.sample$/,
  /\.template$/,
  /\.j2$/,
  /(^|\/)(molecule|tests|spec|fixtures)\//,
];

const SENSITIVE_BASENAMES = new Set([
  "id_rsa",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
  "id_rsa.pem",
  "id_dsa.pem",
  "id_ecdsa.pem",
  "id_ed25519.pem",
]);

const SENSITIVE_EXT_RE = /\.(pem|key)$/i;

const VAULT_NAME_RES = [
  /(^|\/)vault[^/]*\.ya?ml$/,
  /(^|\/)host_vars\/[^/]+\/vault/,
  /(^|\/)group_vars\/[^/]+\/vault/,
];

// Bash command patterns that surface secrets even if the content itself is
// not in the diff. These catch e.g. `cat ~/.aws/credentials` or
// `echo $GITHUB_TOKEN | curl ...`. Conservative — only obvious read-and-leak
// paths. Heavy lifting stays in the content scan above.
const BASH_SENSITIVE_PATH_RE =
  /(^|[^a-zA-Z0-9_/])(\$HOME|~|\$\{HOME\})?\/?\.?(aws\/credentials|aws\/config|ssh\/id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|kube\/config|netrc|pgpass|docker\/config\.json)(\s|$|;|\||&)/;

// --- Helpers ----------------------------------------------------------------

function matchesAnyGlob(path: string, patterns: string[]): boolean {
  // Minimal glob: support `*` and `**`. Translate to RegExp.
  for (const pat of patterns) {
    const re = new RegExp(
      "^" +
        pat
          .replace(/[.+^${}()|[\]\\]/g, "\\$&")
          .replace(/\*\*/g, "\u0000")
          .replace(/\*/g, "[^/]*")
          .replace(/\u0000/g, ".*") +
        "$",
    );
    if (re.test(path)) return true;
  }
  return false;
}

function loadAllowlist(repoRoot: string): string[] {
  const file = `${repoRoot}/.secrets-guard-allowlist`;
  if (!existsSync(file)) return [];
  try {
    return readFileSync(file, "utf8")
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith("#"));
  } catch {
    return [];
  }
}

function isSkipPath(path: string): boolean {
  return SKIP_PATH_GLOBS.some((re) => re.test(path));
}

function isSensitivePath(path: string): boolean {
  const base = basename(path);
  if (SENSITIVE_BASENAMES.has(base)) return true;
  if (SENSITIVE_EXT_RE.test(path)) return true;
  return false;
}

function isVaultNamed(path: string): boolean {
  return VAULT_NAME_RES.some((re) => re.test(path));
}

function findContentSecret(content: string): string | null {
  // Cap at 512 KB to bound CPU.
  const sample = content.length > 524288 ? content.slice(0, 524288) : content;
  for (const { name, re } of SECRET_PATTERNS) {
    if (re.test(sample)) return name;
  }
  return null;
}

// --- Main -------------------------------------------------------------------

export default function (pi: ExtensionAPI) {
  if (process.env.SKIP_SECRETS_GUARD === "1") {
    // Session-wide bypass. Announce via notify per ADR-0022 § Q5
    // "override cannot be silent" contract (backported from
    // gh-identity-guard — issue #258). Extension loads but installs no
    // tool_call handler.
    pi.on("session_start", (_event, ctx) => {
      if (!ctx.hasUI) return;
      ctx.ui.notify(
        "secrets-guard: bypassed via SKIP_SECRETS_GUARD=1",
        "warning",
      );
    });
    return;
  }

  pi.on("tool_call", async (event, ctx) => {
    const cwd = ctx.cwd;
    const allowlist = loadAllowlist(cwd);

    // ---- write / edit / artifact_review content scan -----------------------
    // artifact_review is the custom tool registered by the artifact-handoff
    // extension (ADR-0006 § Tooling, ADR-0007). It is shaped like `write`
    // (path + content), so it joins the same content-scan branch. Without
    // this, artifact_review would be a bypass for the secrets-guard write
    // coverage.
    if (
      event.toolName === "write" ||
      event.toolName === "edit" ||
      event.toolName === "artifact_review"
    ) {
      const path = (event.input as { path?: string }).path ?? "";
      if (!path) return undefined;

      // Allowlist takes precedence
      if (matchesAnyGlob(path, allowlist)) return undefined;

      // Skip patterns suppress secrets-guard for explicitly non-real content
      if (isSkipPath(path)) return undefined;

      // Sensitive file paths are blocked outright
      if (isSensitivePath(path)) {
        const reason = `secrets-guard: refusing to write ${path} — sensitive file basename or extension.

This is a hard refusal — do not retry with a modified payload. Writing private keys or PEM material from an agent context is never the right action. If the user explicitly requested this, ask them to perform the write directly in their own shell.`;
        if (ctx.hasUI) ctx.ui.notify(reason, "error");
        return { block: true, reason };
      }

      // Build the content payload regardless of write|edit|artifact_review shape
      let content = "";
      if (event.toolName === "write" || event.toolName === "artifact_review") {
        // Defensive type-guard: tools normally pass `content` as a string, but
        // if a caller passes a structured object, `String(obj)` yields
        // "[object Object]" and silently drops the payload from the secrets
        // scan. JSON-serialize as a fallback so embedded secrets still match.
        const raw = (event.input as { content?: unknown }).content;
        if (typeof raw === "string") {
          content = raw;
        } else if (raw == null) {
          content = "";
        } else {
          content = JSON.stringify(raw);
        }
      } else {
        // edit: { path, edits: [{ oldText, newText }, ...] }
        const edits = (event.input as { edits?: Array<{ newText?: string }> }).edits ?? [];
        content = edits.map((e) => e.newText ?? "").join("\n");
      }

      // Vault-named files must be encrypted on write
      if (isVaultNamed(path)) {
        const firstLine = content.split(/\r?\n/, 1)[0] ?? "";
        if (!VAULT_HEADER_RE.test(firstLine)) {
          const reason = `secrets-guard: ${path} matches vault-naming pattern but content is not encrypted ($ANSIBLE_VAULT header missing).

Suggested alternatives:
  - Encrypt the file with \`ansible-vault encrypt ${path}\` before writing (or pipe through \`ansible-vault encrypt_string\`).
  - If the file is intentionally a template scaffold, rename the basename so it ends in \`.template\`, \`.example\`, \`.sample\`, or \`.j2\` (the skip-pattern list — see README).
  - If this is a fixture for tests, place it under \`tests/\`, \`fixtures/\`, \`spec/\`, or \`molecule/\`.`;
          if (ctx.hasUI) ctx.ui.notify(reason, "error");
          return { block: true, reason };
        }
      }

      const hit = findContentSecret(content);
      if (hit) {
        const reason = `secrets-guard: ${path} contains a ${hit} pattern.

Suggested alternatives (in order of preference):
  - **Regenerate the content without the secret literal** — substitute a placeholder like \`<REDACTED>\`, an env-var reference (e.g. \`\${GITHUB_TOKEN}\`), or a config-file pointer. This is the right fix in the overwhelming majority of cases.
  - If this is a **known false positive** (a string that looks like the pattern but is not a real secret), add the specific path to \`.secrets-guard-allowlist\` at the repo root.
  - Only if this is **genuinely non-production fixture data** (not a real credential, not derived from one): rename the file with a \`.example\` / \`.sample\` suffix, or place it under \`tests/\`, \`fixtures/\`, \`spec/\`, or \`molecule/\`. Do not use this route to silence a real secret — the skip patterns exist for authoring test fixtures, not for bypassing the guard.
  - Last resort: set \`SKIP_SECRETS_GUARD=1\` in the pi session env (audits via shell history).`;
        if (ctx.hasUI) ctx.ui.notify(reason, "error");
        return { block: true, reason };
      }

      return undefined;
    }

    // ---- bash command scan ---------------------------------------------------
    if (event.toolName === "bash") {
      const command = String((event.input as { command?: string }).command ?? "");
      if (!command) return undefined;

      // Inline secret literals (e.g. `echo ghp_xxxxx... > token.txt`)
      const hit = findContentSecret(command);
      if (hit) {
        const reason = `secrets-guard: bash command contains a ${hit} pattern (inline literal).

Suggested alternatives:
  - Read the secret from an environment variable instead of inlining it (e.g. \`echo "$GITHUB_TOKEN"\` rather than \`echo ghp_xxx\`).
  - Source it from a file (e.g. \`cat ~/.config/myapp/token\`) so the literal never enters the command line.
  - If the value is a placeholder or test fixture, change the literal so it no longer matches the pattern (e.g. \`ghp_REDACTED\`).
  - Last resort: set \`SKIP_SECRETS_GUARD=1\` in the pi session env.`;
        if (ctx.hasUI) ctx.ui.notify(reason, "error");
        return { block: true, reason };
      }

      // Sensitive-path read attempts
      if (BASH_SENSITIVE_PATH_RE.test(command)) {
        const reason = `secrets-guard: bash command references a sensitive credential file path.

Suggested alternatives:
  - Ask the user to share just the specific field you need (e.g. via an env var they export, or by pasting the value), so you never read the file directly.
  - Ask the user to confirm the file exists or report its permissions in their own shell — do not retry with a different verb against the same path (this rule is path-based, not verb-based).
  - If the user explicitly authorized reading the file, ask them to run the command in their own shell and share the relevant output.`;
        if (ctx.hasUI) ctx.ui.notify(reason, "error");
        return { block: true, reason };
      }

      return undefined;
    }

    return undefined;
  });
}
