// Native handshake probe for an explicitly supplied test profile. No OS routes.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	core "github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/amneziawgnet"
	wg "github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 3 && len(os.Args) != 4 {
		return fmt.Errorf("usage: probe private-profile.json endpoint [expected-egress-ip]")
	}
	if len(os.Args) == 4 && net.ParseIP(os.Args[3]).To4() == nil {
		return fmt.Errorf("expected egress must be an IPv4 address")
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
	mtu, err := core.MazaInnerMTU(p.Maza)
	if err != nil {
		return err
	}
	dev, err := amneziawgnet.NewDevice(amneziawg.Instance{Tag: "maza-probe", InterfaceName: "maza-probe", Listen: "127.0.0.1", PrivateKey: p.Wireguard.Private, Address: []string{p.Wireguard.Address}, MTU: mtu, Obfuscation: o, Peers: []amneziawg.Peer{{Email: "probe", PublicKey: p.Wireguard.Public, AllowedIPs: []string{"0.0.0.0/0"}}}}, amneziawgnet.DeviceOptions{HeaderProtectionKey: o.HeaderProtectionKey, ContentPaddingAddition: o.ContentPaddingAddition, RekeyAfterTime: o.RekeyAfterTime, RejectAfterTime: o.RejectAfterTime, RekeyTimeout: o.RekeyTimeout, KeepaliveTimeout: o.KeepaliveTimeout, MaxHandshakeAttempts: o.MaxHandshakeAttempts, RandomTrailers: o.RandomTrailers, DisableCookies: o.DisableCookies})
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
				if len(os.Args) == 4 {
					return checkEgress(dev, os.Args[3])
				}
				return nil
			}
		}
	}
	return fmt.Errorf("native handshake rejected or timed out")
}

// Explicitly opt in to Internet probes. Every socket is on the userspace tunnel
// stack; neither HTTP nor DNS can fall back to the host's network connection.
func checkEgress(dev *amneziawgnet.Device, expectedIP string) error {
	address := func(port uint16) tcpip.FullAddress {
		return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: port}
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
		if network != "tcp" || target != "1.1.1.1:443" {
			return nil, fmt.Errorf("unexpected test destination")
		}
		return gonet.DialContextTCP(ctx, dev.Stack, address(443), ipv4.ProtocolNumber)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get("https://1.1.1.1/cdn-cgi/trace")
	if err != nil {
		return fmt.Errorf("MAZA HTTPS egress: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8192))
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("\nip="+expectedIP+"\n")) {
		return fmt.Errorf("MAZA HTTPS egress did not match expected server")
	}
	fmt.Println("PASS: MAZA HTTPS data through server egress")
	remote := address(53)
	udp, err := gonet.DialUDP(dev.Stack, nil, &remote, ipv4.ProtocolNumber)
	if err != nil {
		return fmt.Errorf("MAZA UDP setup: %w", err)
	}
	defer udp.Close()
	if err := udp.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	query := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if _, err := rand.Read(query[:2]); err != nil {
		return err
	}
	if _, err := udp.Write(query); err != nil {
		return fmt.Errorf("MAZA UDP send: %w", err)
	}
	answer := make([]byte, 4096)
	n, err := udp.Read(answer)
	if err != nil {
		return fmt.Errorf("MAZA UDP DNS: %w", err)
	}
	if n < 12 || !bytes.Equal(answer[:2], query[:2]) || answer[2]&0x80 == 0 || answer[3]&15 != 0 || binary.BigEndian.Uint16(answer[6:8]) == 0 {
		return fmt.Errorf("MAZA UDP DNS response invalid")
	}
	fmt.Println("PASS: MAZA UDP DNS through server egress")
	return nil
}
