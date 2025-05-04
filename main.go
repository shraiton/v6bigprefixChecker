// SPDX-License-Identifier: MIT
//
// Compile with:   go get github.com/sirupsen/logrus
//                 go run detect_range.go -debug
//
// Needs Linux (for IP_FREEBIND) and CAP_NET_RAW or root.

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"sync"

	//"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// CLI flags
var (
	debug = flag.Bool("debug", false, "enable debug output")
)

func main() {
	flag.Parse()

	// Console friendly formatting
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pfx, err := DetectUsableIPv6Range(ctx)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	log.Infof("Usable IPv6 range: %s", pfx.String())
}

// DetectUsableIPv6Range returns the largest working global IPv6 prefix.
func DetectUsableIPv6Range(ctx context.Context) (*net.IPNet, error) {
	globals, err := listGlobalIPv6()
	if err != nil {
		return nil, err
	}
	if len(globals) == 0 {
		return nil, errors.New("no global IPv6 addresses found")
	}

	for _, ga := range globals {
		fmt.Println("global ipv6 found is:", ga)
		err := ensureIPv6LocalRoute(ga.String(), "")
		if err != nil {
			fmt.Println("error ensuring:", err.Error())
			continue
		}
		ok, max := probePrefix(ctx, ga)
		if ok {
			return max, nil
		}
	}
	return nil, errors.New("no reachable IPv6 prefixes")
}

// listGlobalIPv6 filters out link-local, loopback and ULA addresses.
func listGlobalIPv6() ([]*net.IPNet, error) {
	var out []*net.IPNet
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To16() != nil && ipnet.IP.To4() == nil {
				if isGlobal(ipnet.IP) {
					log.WithFields(log.Fields{
						"iface": ifc.Name,
						"ip":    ipnet.IP,
						"cidr":  ipnet.String(),
					}).Debug("found global address")
					out = append(out, ipnet)
				}
			}
		}
	}
	return out, nil
}

func isGlobal(ip net.IP) bool {
	switch {
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(),
		ip.IsMulticast(), ip.IsUnspecified(), ip.IsLoopback():
		return false
	case ip[0]&0xfe == 0xfc: // fc00::/7 (ULA)
		return false
	default:
		return true
	}
}

func probePrefix(ctx context.Context, base *net.IPNet) (bool, *net.IPNet) {
	basePlen, _ := base.Mask.Size()

	// --- 0. Sanity check: does the real address reach the Internet? ---
	if !dnsOK(ctx, base.IP) {
		log.WithField("ip", base.IP).Warn("configured address failed DNS probe")
		return false, nil
	}

	// --- 1. Build candidate list ------------------------------------------------
	nCandidates := 128 - basePlen + 1
	cands := make([]*net.IPNet, nCandidates) // index 0 ⇒ /basePlen
	results := make([]bool, nCandidates)

	for i := 0; i < nCandidates; i++ {
		plen := basePlen + i
		cands[i] = &net.IPNet{
			IP:   base.IP.Mask(net.CIDRMask(plen, 128)),
			Mask: net.CIDRMask(plen, 128),
		}
	}

	// --- 2. Launch probes -------------------------------------------------------
	var wg sync.WaitGroup
	wg.Add(nCandidates)

	for idx, cand := range cands {
		idx, cand := idx, cand // capture loop vars
		go func() {
			defer wg.Done()

			plen, _ := cand.Mask.Size()
			var probeIP net.IP
			if plen == 128 {
				// Only member of /128 is the actual address
				probeIP = base.IP
			} else {
				var err error
				probeIP, err = randomInPrefix(cand, plen)
				if err != nil {
					log.WithError(err).Warn("random address generation failed")
					return
				}
			}

			log.WithFields(log.Fields{
				"candidate_prefix": cand.String(),
				"test_ip":          probeIP,
			}).Debug("parallel probe")

			results[idx] = dnsOK(ctx, probeIP)
		}()
	}

	wg.Wait() // block until every goroutine stored its result

	// --- 3. Pick the *narrowest* working prefix ---------------------------------
	for idx, ok := range results {
		if ok {
			best := cands[idx]
			log.WithField("usable_prefix", best.String()).Info("prefix usable")
			return true, best
		}
	}

	// This should never trigger because /128 = real IP already succeeded.
	fallback := &net.IPNet{IP: base.IP, Mask: net.CIDRMask(128, 128)}
	return true, fallback
}

// randomInPrefix returns an IPv6 address inside pfx that is *not*
// contained in the first sub-prefix of length plen+1.
func randomInPrefix(pfx *net.IPNet, plen int) (net.IP, error) {
	hostBits := 128 - plen
	if hostBits <= 0 {
		return nil, errors.New("prefix too small")
	}
	lo := new(big.Int).Lsh(big.NewInt(1), uint(hostBits-1)) // half-way point
	n, err := rand.Int(rand.Reader, lo)
	if err != nil {
		return nil, err
	}
	n = n.Add(n, lo) // shift into second half
	base := pfx.IP
	ip := make(net.IP, 16)
	copy(ip, base)
	for i := 15; i >= 0 && n.BitLen() > 0; i-- {
		ip[i] |= byte(n.Uint64() & 0xff)
		n.Rsh(n, 8)
	}
	return ip, nil
}

// dnsOK sends a single UDP DNS query from src and waits for a reply.
func dnsOK(ctx context.Context, src net.IP) bool {
	dnsServers := []string{
		"[2001:4860:4860::8888]:53",
	}
	question := []byte{0xde, 0xad, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		1, 'a', 0, 0, 1, 0, 1} // "A a."

	for _, ns := range dnsServers {
		logger := log.WithFields(log.Fields{
			"src": src,
			"ns":  ns,
		})
		d := net.Dialer{
			LocalAddr: &net.UDPAddr{IP: src, Zone: "", Port: 0},
			Timeout:   250 * time.Millisecond,
			Control:   setFreebind,
		}
		c, err := d.DialContext(ctx, "udp6", ns)
		if err != nil {
			logger.Debugf("dial: %v", err)
			continue
		}
		_ = c.SetDeadline(time.Now().Add(250 * time.Millisecond))
		_, err = c.Write(question)
		if err != nil {
			logger.Debugf("write: %v", err)
			c.Close()
			continue
		}
		buf := make([]byte, 512)
		_, err = c.Read(buf)
		c.Close()
		if err == nil {
			logger.Debug("reply OK")
			return true
		}
		logger.Debugf("read: %v", err)
	}
	return false
}

const ipFreebind = 15 // value in <linux/in.h> (works for AF_INET6 too)

func setFreebind(network, address string, c syscall.RawConn) error {
	var serr error
	e := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, ipFreebind, 1)
	})
	if e != nil {
		return e
	}
	return serr
}

func init() {
	// Seed math/rand for cosmetic randomness
	var seed int64
	_ = binary.Read(rand.Reader, binary.LittleEndian, &seed)
	mrand.Seed(seed)
}
