- **Ping the target machine**:  
    `ping -c 20 <target_ip>`
    - **If response**: Proceed to [[Step 3. Network Reconnaissance]]
    - **If no response**:
        - Check if ICMP is blocked.
        - **Run a simple Nmap ping sweep**:  
            `nmap -sn <target_ip>`
            - **If response**: Proceed with Nmap scan.
            - **If no response**: Check if the target is down or behind a firewall.