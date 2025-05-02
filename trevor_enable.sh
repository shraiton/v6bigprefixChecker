sysctl -w net.ipv6.ip_nonlocal_bind=1
ip route add local 2a01:4f8:c013:bcf5::1/64 dev eth0
