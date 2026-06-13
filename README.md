# pi-secrets-guard

> **Distribution mirror.** Developed in a private source-of-truth repo and synced here for distribution
> (current sync: `pi_config@d653613`, 2026-06-12). The `main` branch is force-synced — please don't
> target PRs at it directly; file an [issue](https://github.com/psmfd/pi-secrets-guard/issues)
> instead and fixes will land via the next sync.

Pi extension that blocks tool calls which would write or surface secrets. Companion to `pi-bash-destructive-guard` — together they bracket the two highest-frequency catastrophic outcomes (credential exfiltration and data destruction).

## Install

```bash
pi install git:github.com/psmfd/pi-secrets-guard@v0.1.0
```

Or try it for a single session without installing:

```bash
pi -e git:github.com/psmfd/pi-secrets-guard
```

No build step — pi loads the TypeScript directly. The pi SDK is bundled by pi itself; this extension has no runtime dependencies of its own.

## Hooked events

- **`tool_call` for `write`, `edit`, and `artifact_review`** — scans the content payload for secret patterns; refuses to write to vault-named files lacking the `$ANSIBLE_VAULT` header; refuses to write to sensitive basenames (`id_rsa`, etc.) or sensitive extensions (`*.pem`, `*.key`). `artifact_review` is the custom tool registered by the companion [`pi-artifact-handoff`](https://github.com/psmfd/pi-artifact-handoff) extension; it is shaped like `write` (path + content) and joins the same scan branch.
- **`tool_call` for `bash`** — scans the command for inline secret literals and references to sensitive credential file paths (`~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.kube/config`, `~/.netrc`, etc.).

## Tool-call coverage

Custom tools that write content do **not** inherit `write`/`edit` coverage automatically — the tool-call handler matches on `event.toolName`. When a new write-shaped custom tool is registered, it MUST be added to the content-scan branch in `index.ts`. `artifact_review` is currently the only such tool.

## Patterns blocked

- PEM private-key headers (`-----BEGIN ... PRIVATE KEY`)
- AWS access key IDs (`AKIA|ASIA|ABIA|ACCA` + 16 alphanumerics, with word-boundary anchoring)
- GitHub personal access tokens (`ghp_[A-Za-z0-9]{36}`, `github_pat_[A-Za-z0-9_]{82}`)
- Unencrypted vault files (vault-named YAML lacking the `$ANSIBLE_VAULT` first-line header)
- Writes to sensitive file paths (`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, plus `.pem`/`.key` variants)

The pattern set lives at the top of `index.ts` as the single source of truth. If you pair this extension with a git pre-commit secrets hook, keep the two pattern sets in lockstep.

## Skip patterns (extension does not scan)

Files matching `*.example`, `*.sample`, `*.template`, `*.j2`, or paths under `molecule/`, `tests/`, `spec/`, `fixtures/`.

## Refusal policy (per-rule)

The `damage-control-continue` pattern (from [`disler/pi-vs-claude-code`](https://github.com/disler/pi-vs-claude-code)) distinguishes **hard refusals** — where any retry is wrong and the agent should escalate to the user — from **continue-eligible** blocks, where the agent can recover by trying a modified approach. This extension classifies its rules accordingly; `reason:` payloads carry explicit guidance:

| Rule | Policy | Rationale |
|---|---|---|
| Write to sensitive basename (`id_rsa`, `*.pem`, `*.key`) | **Hard refusal** | Writing private-key material from an agent context is never the right action. `reason:` explicitly instructs the model not to retry and to escalate to the user. (Note: skip-pattern paths — `tests/`, `fixtures/`, `*.example`, `*.sample`, `*.template`, `*.j2` — are evaluated **before** the sensitive-basename check, so a fixture key under `tests/fixtures/fake_key.pem` is allowed. This is intentional.) |
| PEM / AWS-key / GitHub-PAT pattern in write or edit content | Continue-eligible | The agent can rename to a fixture path, regenerate without the literal, or add a known-false-positive to the allowlist. `reason:` enumerates these alternatives. |
| Vault-named file written without `$ANSIBLE_VAULT` header | Continue-eligible | The agent can encrypt first via `ansible-vault`, rename to a non-vault pattern, or relocate to a fixtures directory. |
| Inline secret literal in `bash` command | Continue-eligible | The agent can read from an env var or file instead of inlining the literal. |
| `bash` command references sensitive credential path | Continue-eligible | The agent can ask the user for just the needed field, use `test -f`/`ls -l` for existence checks, or escalate. |

## Override mechanisms

Both surfaces **announce themselves via `ctx.ui.notify` on use** — silent overrides are not supported.

| Override | Scope | Visibility |
|---|---|---|
| `SKIP_SECRETS_GUARD=1` in pi's environment | Whole pi session | Visible in shell history; auditable; announced once at session start via `warning`-level notify |
| `.secrets-guard-allowlist` at repo root | Per-path glob, persistent | Version-controlled; visible in PR review |

The session-wide bypass loads the extension but installs no `tool_call` handler. The session-start announcement names the bypass env var for auditability; in non-UI sessions (e.g. `pi -p`) the notify call is suppressed cleanly via the `ctx.hasUI` guard.

The allowlist accepts one path glob per line (`*` matches a path segment, `**` matches across segments). Lines starting with `#` are comments. Use it for known-false-positives such as `tests/fixtures/fake_key.pem`. Never to suppress a real finding.

## When this extension is bypassed

- `SKIP_SECRETS_GUARD=1` in pi's environment — the extension loads but installs no hook.
- The path matches an allowlist entry — that single tool call is allowed; other calls in the same session are still scanned.
- The path matches a skip pattern — that single tool call is allowed.

## Limitations

- Does not detect inline `!vault |` scalars in partially-encrypted YAML files (would require a YAML parser; out of scope).
- Bash sensitive-path detection is conservative — only obvious read-and-leak filenames are flagged. Sophisticated exfiltration paths are not in scope for a regex-level guard.
- The extension scans the **first 512 KB** of any content payload. Larger payloads are partially scanned.

## Development

```bash
npm install
npm run typecheck
npm test
```

## License

[MIT](LICENSE)
