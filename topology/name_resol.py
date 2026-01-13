def fix_hosts(net):
    for h in net.hosts:
        hosts_entries = []
        for other in net.hosts:
            hosts_entries.append(f"{other.IP()} {other.name}")
        h.cmd("echo > /etc/hosts")
        for entry in hosts_entries:
            h.cmd(f"echo '{entry}' >> /etc/hosts")


