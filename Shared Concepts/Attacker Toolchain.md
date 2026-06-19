
One-time setup for the attacker box (x64 Kali assumed). Covers the toolchain state technique playbooks assume present. Technique playbooks reference this note via preamble when they depend on non-stock prep; they NEVER provision inline.

Per-tier prep required:

| Tier       | Form                                 | Attacker-side prep                  |
| ---------- | ------------------------------------ | ----------------------------------- |
| T0         | dynamic ELF via manylinux container  | Docker engine + image pull(s)       |
| T1         | musl-static                          | `musl-tools` package                |
| T2         | msfvenom `linux/<arch>/exec` payload | None (preinstalled on Kali)         |
| T3         | compile-on-target                    | None (no attacker prep)             |
| T4         | glibc-static                         | AVOIDED per Vault_Strategy line 153 |
| cross-arch | applies to T0/T1                     | `gcc-multilib`                      |

---

## T0 — manylinux container compile chain

##### Install Docker engine

Install via Kali's apt-managed path (per kali.org/docs):

`sudo apt update && sudo apt install -y docker.io`

Start the daemon on-demand (do NOT auto-enable on boot — docker's iptables/bridge state can interfere with engagement VPN routing):

`sudo systemctl start docker`

Add your user to the docker group (avoid `sudo` prefix on every `docker` command):

`sudo usermod -aG docker $USER`

The group change **takes effect on next login**.

Verify daemon and access:

`docker info | head -20`

Expected: Client + Server blocks print without "permission denied".

##### Pull manylinux images 

Two images cover the target glibc range: 

- manylinux2010 (glibc 2.12) — RHEL/CentOS 6, Debian 7, Ubuntu 12.04
- manylinux2014 (glibc 2.17) — RHEL/CentOS 7+, Debian 8+, Ubuntu 14.04+ 
 
Pull both, digest-pinned: 

`docker pull quay.io/pypa/manylinux2010_x86_64@sha256:3b5eb5ab9bc73b93740ae4eda9962078951cd3bb7efe837b770360e78c7366fb` 

`docker pull quay.io/pypa/manylinux2014_x86_64@sha256:87b129514bde0520172d4e319fb579b36e0bf8aa6698d365ed4a64736585b27b` 

Verify both images present: 

`docker images --digests | grep -E 'manylinux2010_x86_64|manylinux2014_x86_64'` 

Expected: two rows, each showing the matching sha256 digest above. 

Verify gcc compile in each container:

`docker run --rm quay.io/pypa/manylinux2010_x86_64 bash -c 'echo "int main(){return 0;}" > /tmp/t.c && gcc /tmp/t.c -o /tmp/t && file /tmp/t'`

`docker run --rm quay.io/pypa/manylinux2014_x86_64 bash -c 'echo "int main(){return 0;}" > /tmp/t.c && gcc /tmp/t.c -o /tmp/t && file /tmp/t'`

Expected: `/tmp/t: ELF 64-bit LSB executable, x86-64 ... dynamically linked ...` from each. 

##### Stop daemon 

When done with toolchain work, stop BOTH the service AND the socket (the socket auto-activates the service on the next docker command if left running): 

`sudo systemctl stop docker.service docker.socket`