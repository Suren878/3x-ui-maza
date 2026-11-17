// Loopback-only interop fixture. Never used by the production panel.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/amneziawgnet"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

func main() {
	if len(os.Args) != 2 {
		panic("configuration path required")
	}
	var cfg struct {
		Port                                   int
		HTTPPort                               int
		MTU                                    int
		PrivateKey, PublicKey, ClientPublicKey string
		Obfuscation                            amneziawg.Obfuscation31
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic("configuration unavailable")
	}
	if json.Unmarshal(data, &cfg) != nil || cfg.Port < 1 || cfg.HTTPPort < 1 {
		panic("invalid test configuration")
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	inst := amneziawg.Instance{Id: 1, Tag: "maza-test", InterfaceName: "maza-test", Listen: "127.0.0.1", ListenPort: cfg.Port,
		PrivateKey: cfg.PrivateKey, PublicKey: cfg.PublicKey, Address: []string{"10.78.0.1/24"}, MTU: cfg.MTU,
		Obfuscation: cfg.Obfuscation, Peers: []amneziawg.Peer{{Email: "test", PublicKey: cfg.ClientPublicKey, AllowedIPs: []string{"10.78.0.2/32"}}}}
	o := cfg.Obfuscation
	dev, err := amneziawgnet.NewDevice(inst, amneziawgnet.DeviceOptions{HeaderProtectionKey: o.HeaderProtectionKey,
		ContentPaddingAddition: o.ContentPaddingAddition, RekeyAfterTime: o.RekeyAfterTime, RejectAfterTime: o.RejectAfterTime,
		RekeyTimeout: o.RekeyTimeout, KeepaliveTimeout: o.KeepaliveTimeout, MaxHandshakeAttempts: o.MaxHandshakeAttempts,
		RandomTrailers: o.RandomTrailers, DisableCookies: o.DisableCookies})
	if err != nil {
		panic("native test peer failed to start")
	}
	defer dev.Close()
	owner := func(ip netip.Addr) (string, bool) { return "test", ip.String() == "10.78.0.2" }
	amneziawgnet.AttachTCPForwarder(dev.Stack, owner, func(c *gonet.TCPConn, src, dst netip.AddrPort) {
		defer c.Close()
		if dst.Addr().String() != "10.78.0.1" || int(dst.Port()) != cfg.HTTPPort {
			return
		}
		remote, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.HTTPPort)), time.Second*3)
		if err != nil {
			return
		}
		defer remote.Close()
		go func() { _, _ = io.Copy(remote, c) }()
		_, _ = io.Copy(c, remote)
	})
	amneziawgnet.AttachUDPHandler(dev.Stack, func(src, dst netip.AddrPort, payload []byte) {
		if src.Addr().String() == "10.78.0.2" && dst.Addr().String() == "10.78.0.1" {
			_ = amneziawgnet.WriteUDPReply(dev.Stack, dst, src, payload)
		}
	})
	fmt.Println("READY")
	_, _ = io.Copy(io.Discard, os.Stdin)
}
