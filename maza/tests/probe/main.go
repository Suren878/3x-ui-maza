// Native handshake probe for an explicitly supplied test profile. No OS routes.
package main

import (
	"encoding/json"
	"fmt"
	core "github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/amneziawgnet"
	wg "github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: probe private-profile.json endpoint")
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		return fmt.Errorf("profile unavailable")
	}
	var p struct {
		Version   int
		Maza      core.MazaParameters
		Wireguard struct {
			Private string `json:"private_key"`
			Public  string `json:"public_key"`
			Address string
		}
	}
	if json.Unmarshal(data, &p) != nil || p.Version != 2 || core.ValidateMazaParameters(p.Maza) != nil {
		return fmt.Errorf("invalid native profile")
	}
	if _, _, err := net.SplitHostPort(os.Args[2]); err != nil {
		return fmt.Errorf("invalid endpoint")
	}
	params := map[string]any{}
	for k, v := range p.Maza {
		if k == "persistentkeepaliveinterval" {
			continue
		}
		if k == "randomtrailers" || k == "disablecookies" {
			params[k] = v == "true"
		} else if k == "s1" || k == "s2" || k == "s3" || k == "s4" || k == "jc" || k == "jmin" || k == "jmax" {
			n, _ := strconv.Atoi(v)
			params[k] = n
		} else {
			params[k] = v
		}
	}
	b, _ := json.Marshal(params)
	var o amneziawg.Obfuscation31
	if json.Unmarshal(b, &o) != nil {
		return fmt.Errorf("parameters invalid")
	}
	dev, err := amneziawgnet.NewDevice(amneziawg.Instance{Tag: "maza-probe", InterfaceName: "maza-probe", Listen: "127.0.0.1", PrivateKey: p.Wireguard.Private, Address: []string{p.Wireguard.Address}, MTU: 1280, Obfuscation: o, Peers: []amneziawg.Peer{{Email: "probe", PublicKey: p.Wireguard.Public, AllowedIPs: []string{"0.0.0.0/0"}}}}, amneziawgnet.DeviceOptions{HeaderProtectionKey: o.HeaderProtectionKey, ContentPaddingAddition: o.ContentPaddingAddition, RekeyAfterTime: o.RekeyAfterTime, RejectAfterTime: o.RejectAfterTime, RekeyTimeout: o.RekeyTimeout, KeepaliveTimeout: o.KeepaliveTimeout, MaxHandshakeAttempts: o.MaxHandshakeAttempts, RandomTrailers: o.RandomTrailers, DisableCookies: o.DisableCookies})
	if err != nil {
		return fmt.Errorf("core initialization failed: %w", err)
	}
	defer dev.Close()
	pub, err := wg.KeyToHex(p.Wireguard.Public)
	if err != nil {
		return fmt.Errorf("invalid peer")
	}
	if dev.IpcSet("public_key="+pub+"\nendpoint="+os.Args[2]+"\npersistent_keepalive_interval=1\n") != nil {
		return fmt.Errorf("peer setup failed")
	}
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		state, err := dev.IpcGet()
		if err != nil {
			return fmt.Errorf("status failed")
		}
		for _, line := range strings.Split(state, "\n") {
			if strings.HasPrefix(line, "last_handshake_time_sec=") && line != "last_handshake_time_sec=0" {
				fmt.Println("PASS: native MAZA authenticated handshake")
				return nil
			}
		}
	}
	return fmt.Errorf("native handshake rejected or timed out")
}
