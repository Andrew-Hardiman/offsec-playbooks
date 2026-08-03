
⚠️ **Build-when-encountered stub.** Walkthrough body not yet built.

⚠️ **Triple-invocation preflight requirement (when body is built).** This walkthrough is referenced from THREE Checksheet steps and must be invocable from any without ambiguity:

- [[Linux Privilege Escalation Checksheet]] Step 1 (Sudo and group privileges, Groups sub-block) — foothold user's membership in the `docker` group grants socket access without sudo.
- [[Linux Privilege Escalation Checksheet]] Step 2 (Container attack surface) — path-based routing on Docker's known socket path (`/var/run/docker.sock`).
- [[Linux Privilege Escalation Checksheet]] Step 9 (AF_UNIX Socket Hijacking) — path-variance backstop routing via `~/scripts/af_unix_sock_enum.sh` allowlist. Fires when Docker daemon is bound to a non-standard socket path that Step 2's path-based routing did not catch.

When the body is built, add two preflight steps at the top so the walkthrough is safe to enter from any invocation path:

1. **Banner-probe daemon identity** via `nc -U <socket>` (or equivalent) to confirm the socket at `<path>` actually speaks the Docker API. Necessary because Step 9 arrives via path-variance and the socket's identity is not implicit from its path. Step 1 and Step 2 arrive with the identity pre-confirmed (group membership implies Docker; standard path is Docker by convention) but the same check adds no material cost and catches misconfigurations.
2. **Verify daemon UID** via `/proc/<pid>/status` (where readable) — confirms the Docker daemon is running as root before the exploit chain proceeds. Applies to all invocation paths.

Both preflights are non-optional. Walkthrough body proceeds only when both succeed.