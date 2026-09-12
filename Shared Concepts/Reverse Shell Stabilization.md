
Raw `nc` / `/dev/tcp` reverse shells lack a controlling TTY. Tab completion, arrow keys, `vim`/`nano`, `sudo`, and `su` fail or misbehave. This note covers the canonical stabilization patterns.

---

## Minimum — universal, single command

In the reverse shell:

`script -q /dev/null /bin/bash`

Yields: arrow keys, basic tab completion (filenames, commands by PATH), working `vim`/`nano`/most interactive commands.

---

## Fallback when `script` is unavailable

`script` is from util-linux, present on essentially every Linux system. Confirmed absent only on minimal/embedded targets. **Try in order** — once one works, continue to [[#Full — Ctrl+C handling, terminal size, and TERM setup]] for a fully functional terminal (Ctrl+C, arrow keys, resize, `sudo`/`su`):

`python3 -c 'import pty; pty.spawn("/bin/bash")'`

`python -c 'import pty; pty.spawn("/bin/bash")'`

`/bin/bash -i`

(The last allocates no PTY — minimal improvement; sometimes enough for read-only commands.)

---

## Full — Ctrl+C handling, terminal size, and TERM setup

Before backgrounding, capture attacker's terminal size:

`stty size`

(Run on attacker. Output: `<rows> <cols>` — note both values.)

From the stabilized reverse shell (Minimum or Fallback above), background:

`Ctrl+Z`

In the attacker's local shell (now suspended foreground job):

`stty raw -echo; fg`

(Garbage appears as the target shell redraws.)

In the target shell:

`reset`

`export TERM=xterm-256color`

`stty rows <rows> cols <cols>`

Yields: full TTY — Ctrl+C kills current command only, terminal correctly sized for `vim`/`less`/full-screen tools.

---

## If `su` / `sudo` complains "must be run from a terminal"

Minimum stabilization isn't sufficient. Run the full chain above — the `reset` step is what triggers `su` / `sudo` to recognize the TTY.
