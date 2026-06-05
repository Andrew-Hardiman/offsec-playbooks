
Identifies a quieter `<drop_dir>` than the default `/tmp` for drop-and-launch technique playbooks. Read-only — no file writes, no setuid creation.

---

## Step 1 — Declare drop-dir requirements

The technique playbook dictates which mount-flag check applies (playbooks are mapped via mode flag):

| Technique playbook drops              | Required checks               | Mode   | Probe form |
| ------------------------------------- | ----------------------------- | ------ | ---------- |
| Script (e.g. PATH-hijack helper)      | write + exec                  | `-`    | A          |
| Setuid binary (e.g. setuid bash copy) | write + exec + **suid-honor** | `suid` | B          |

---

## Step 2 — Deploy probe via xclip-heredoc (on attacker's box)

##### Form A — write + exec only:

`(echo "bash -s <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/drop_dir_probe.sh; echo "EOF") | xclip -selection clipboard`

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.)

Paste into target shell.
##### Form B — write + exec + suid-honor:

`(echo "bash -s suid <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/drop_dir_probe.sh; echo "EOF") | xclip -selection clipboard`

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.)

Paste into target shell.

---

## Step 3 — Interpret output

- `DROP OK: /path/to/dir` → `<drop_dir>` = `/path/to/dir`. Return to technique playbook; substitute for the default `/tmp`.
- No output → no candidate passed required checks. Return to technique playbook; use default `/tmp` (accept high IOC) or abandon if engagement stealth is absolute.