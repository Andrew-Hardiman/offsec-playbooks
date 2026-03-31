**Create a directory on your local machine for the specific target, and save the output of each scan in the directory.**

- **Run a full Nmap scan to identify open ports**:  
    `sudo nmap -p- -T4 <target_ip>`
    - **If open ports found**: Proceed to [[Step 4. Service & Version Detection]]
    - **If no open ports found**:
        - Consider possible firewall rules or VPN usage.
        - **Try scanning only specific ports** like 80 (HTTP), 443 (HTTPS), 22 (SSH), 21 (FTP): `sudo nmap -p 80,443,22,21 <target_ip>`

**NB: Scanning all 65,535 (`-p-`) ports can take a long time, if using a moderate speed such as `-T3`. Be patient, or use a faster speed such as `-T4`.**




