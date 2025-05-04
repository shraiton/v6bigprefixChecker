package main // or main

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// ensureIPv6LocalRoute makes sure that
//
//	ip -6 route add local <prefix> dev <dev>
//
// exists in the “local” routing table.
//
// If dev == "", the function looks at all local interfaces and picks the first
// one that already carries an address inside <prefix>.  (CAP_NET_ADMIN needed.)
func ensureIPv6LocalRoute(prefixCIDR, dev string) error {
	// 1. validate prefix
	_, ipNet, err := net.ParseCIDR(prefixCIDR)
	if err != nil {
		return fmt.Errorf("invalid prefix: %w", err)
	}
	if ipNet.IP.To16() == nil || ipNet.IP.To4() != nil {
		return fmt.Errorf("not an IPv6 prefix")
	}

	// 2. If dev is not supplied, autodetect it
	if dev == "" {
		ifaces, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("list interfaces: %w", err)
		}
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs() // ignore per-iface error; best-effort
			for _, a := range addrs {
				if ipAddrNet, ok := a.(*net.IPNet); ok && ipNet.Contains(ipAddrNet.IP) {
					dev = iface.Name
					break
				}
			}
			if dev != "" {
				break
			}
		}
		if dev == "" {
			return fmt.Errorf("no interface has an address within %s", prefixCIDR)
		}
	}

	// 3. see if the route is already present (any dev counts)
	show := exec.Command("ip", "-6", "route", "show", "table", "local")
	var out bytes.Buffer
	show.Stdout = &out
	if err := show.Run(); err != nil {
		return fmt.Errorf("ip route show: %w", err)
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, "local "+prefixCIDR+" ") {
			return nil // route exists → nothing to do
		}
	}

	// 4. add it
	add := exec.Command("ip", "-6", "route", "add", "local", prefixCIDR, "dev", dev)
	if err := add.Run(); err != nil {
		// tolerate a race in which somebody else added it first
		if ee, ok := err.(*exec.ExitError); ok && bytes.Contains(ee.Stderr, []byte("File exists")) {
			return nil
		}
		return fmt.Errorf("ip route add: %w", err)
	}
	return nil
}
