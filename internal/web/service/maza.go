package service

// MAZA is a separate transport. Its managed WireGuard inbound is loopback-only;
// no fictitious protocol name is passed to Xray. Desired state is durable before
// reconciliation, so an interrupted operation can be retried after a restart.
import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	wg "github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
	"gorm.io/gorm"
)

const mazaTag = "maza-managed"
const mazaPort = 51829

type MazaClient struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Address     string `json:"address"`
	Created     int64  `json:"created"`
	PrivateKey  string `json:"privateKey"`
	PublicKey   string `json:"publicKey"`
	AuthPrivate string `json:"authPrivate"`
	AuthPublic  string `json:"authPublic"`
}

type mazaState struct {
	Version       int          `json:"version"`
	Owner         int          `json:"owner"`
	ServerPrivate string       `json:"serverPrivate"`
	ServerPublic  string       `json:"serverPublic"`
	Clients       []MazaClient `json:"clients"`
}

type MazaService struct {
	mu                   sync.Mutex
	dir, origin, address string
	state                mazaState
	pending              bool
	activate             func() error
}

// The web server can be restarted in-process by panel settings. Keep one
// reconciler/state owner, so an old handler cannot restore a revoked client.
var mazaOnce sync.Once
var mazaInstance *MazaService
var mazaInitError error

func OpenMazaService() (*MazaService, error) {
	mazaOnce.Do(func() { mazaInstance, mazaInitError = openMazaService() })
	return mazaInstance, mazaInitError
}

func openMazaService() (*MazaService, error) {
	origin := os.Getenv("MAZA_ORIGIN")
	if origin == "" {
		return nil, nil
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("invalid MAZA_ORIGIN")
	}
	address := os.Getenv("MAZA_SERVER_ADDRESS")
	if address != "" {
		if _, err := netip.ParseAddrPort(address); err != nil {
			return nil, errors.New("MAZA_SERVER_ADDRESS must be an IP:port or empty")
		}
	}
	s := &MazaService{dir: filepath.Join(config.GetDBFolderPath(), "maza"), origin: strings.TrimRight(origin, "/"), address: address, pending: true}
	s.activate = func() error { return (&XrayService{}).RestartXray(false) }
	if err := os.MkdirAll(filepath.Join(s.dir, "relay"), 0700); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(s.dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		priv, pub, err := wg.GenerateWireguardKeypair()
		if err != nil {
			return nil, err
		}
		s.state = mazaState{Version: 1, ServerPrivate: priv, ServerPublic: pub, Clients: []MazaClient{}}
		if err := s.save(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if err := json.Unmarshal(b, &s.state); err != nil {
		return nil, err
	}
	if s.state.Version != 1 || len(s.state.Clients) > 64 {
		return nil, errors.New("invalid MAZA state version or client count")
	}
	// Retry only pending changes. Never continuously rewrite/restart Xray.
	go func() {
		for range time.NewTicker(3 * time.Second).C {
			s.mu.Lock()
			if s.pending {
				_ = s.apply()
			}
			s.mu.Unlock()
		}
	}()
	return s, nil
}

func mazaAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".maza-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *MazaService) save() error {
	b, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	return mazaAtomic(filepath.Join(s.dir, "state.json"), b)
}

func (s *MazaService) relayConfig() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "listen = %q\norigin = %q\ncertificate = %q\nprivate_key = %q\nwireguard_endpoint = %q\n", "0.0.0.0:9443", s.origin, "/cert/fullchain.pem", "/cert/privkey.pem", "127.0.0.1:51829")
	if len(s.state.Clients) == 0 {
		b.WriteString("clients = []\n")
	}
	for _, c := range s.state.Clients {
		fmt.Fprintf(&b, "\n[[clients]]\nid = %q\npublic_key = %q\n", c.ID, c.AuthPublic)
	}
	return []byte(b.String())
}

func (s *MazaService) apply() error {
	if s.state.Owner != 0 {
		clients := make([]model.Client, 0, len(s.state.Clients))
		for _, c := range s.state.Clients {
			clients = append(clients, model.Client{Email: "maza-" + c.ID, Comment: c.Name, Enable: true, PublicKey: c.PublicKey, AllowedIPs: []string{c.Address}, KeepAlive: model.KeepAlivePtr(25)})
		}
		settings, err := json.Marshal(map[string]any{"secretKey": s.state.ServerPrivate, "mtu": 1280, "noKernelTun": true, "subnetIp": "10.78.0.0", "subnetCidr": 24, "clients": clients})
		if err != nil {
			return err
		}
		var inbound model.Inbound
		err = database.GetDB().Where("tag = ?", mazaTag).First(&inbound).Error
		isNew := errors.Is(err, gorm.ErrRecordNotFound)
		if err != nil && !isNew {
			return err
		}
		if !isNew && (inbound.Protocol != model.WireGuard || inbound.UserId != s.state.Owner || inbound.Port != mazaPort || inbound.Listen != "127.0.0.1") {
			return errors.New("MAZA backend conflicts with an existing inbound")
		}
		inbound.UserId = s.state.Owner
		inbound.Tag, inbound.Remark = mazaTag, "MAZA backend — manage clients on the MAZA page"
		inbound.Protocol, inbound.Listen, inbound.Port, inbound.Enable = model.WireGuard, "127.0.0.1", mazaPort, true
		inbound.Settings, inbound.StreamSettings, inbound.Sniffing = string(settings), "{}", "{\"enabled\":false}"
		inboundSvc := &InboundService{}
		if isNew {
			_, _, err = inboundSvc.AddInbound(&inbound)
		} else {
			_, _, err = inboundSvc.UpdateInbound(&inbound)
		}
		if err != nil {
			return err
		}
		// Since 3.11, editing an inbound deliberately preserves its stored
		// clients. Use the dedicated client APIs for membership changes.
		clientSvc := &ClientService{}
		stored, err := clientSvc.ListForInbound(nil, inbound.Id)
		if err != nil {
			return err
		}
		wanted := make(map[string]model.Client, len(clients))
		for _, c := range clients {
			wanted[c.Email] = c
		}
		for _, c := range stored {
			if expected, ok := wanted[c.Email]; ok {
				if c.PublicKey != expected.PublicKey || strings.Join(c.AllowedIPs, ",") != strings.Join(expected.AllowedIPs, ",") {
					return errors.New("managed WireGuard peer was changed outside MAZA")
				}
				delete(wanted, c.Email)
			} else if _, err := clientSvc.DelInboundClientByEmail(inboundSvc, inbound.Id, c.Email, false, false); err != nil {
				return err
			}
		}
		missing := make([]model.Client, 0, len(wanted))
		for _, c := range clients {
			if _, ok := wanted[c.Email]; ok {
				missing = append(missing, c)
			}
		}
		if len(missing) != 0 {
			data, err := json.Marshal(map[string]any{"clients": missing})
			if err != nil {
				return err
			}
			if _, err := clientSvc.AddInboundClient(inboundSvc, &model.Inbound{Id: inbound.Id, Protocol: model.WireGuard, Settings: string(data)}); err != nil {
				return err
			}
		}
		if s.activate != nil {
			if err := s.activate(); err != nil {
				return err
			}
		}
	}
	if err := mazaAtomic(filepath.Join(s.dir, "relay", "server.toml"), s.relayConfig()); err != nil {
		return err
	}
	s.pending = false
	return nil
}

func (s *MazaService) allowed(user int) bool { return s.state.Owner == 0 || s.state.Owner == user }

func (s *MazaService) List(user int) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.allowed(user) {
		return nil, errors.New("MAZA belongs to another administrator")
	}
	clients := make([]map[string]any, 0, len(s.state.Clients))
	for _, c := range s.state.Clients {
		clients = append(clients, map[string]any{"id": c.ID, "name": c.Name, "address": c.Address, "created": c.Created})
	}
	return map[string]any{"clients": clients, "origin": s.origin, "pending": s.pending, "limit": 64}, nil
}

func mazaName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 || !utf8.ValidString(name) || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", errors.New("name must contain 1–64 UTF-8 bytes without control characters")
	}
	return name, nil
}

func (s *MazaService) Create(user int, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.allowed(user) || user <= 0 {
		return errors.New("access denied")
	}
	if s.pending && s.state.Owner != 0 {
		return errors.New("previous change is still being applied")
	}
	name, err := mazaName(name)
	if err != nil {
		return err
	}
	if len(s.state.Clients) >= 64 {
		return errors.New("64-client limit reached")
	}
	used := map[string]bool{}
	for _, c := range s.state.Clients {
		if c.Name == name {
			return errors.New("client name already exists")
		}
		used[c.Address] = true
	}
	address := ""
	for i := 2; i < 255; i++ {
		v := fmt.Sprintf("10.78.0.%d/32", i)
		if !used[v] {
			address = v
			break
		}
	}
	priv, pub, err := wg.GenerateWireguardKeypair()
	if err != nil {
		return err
	}
	apub, apriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(apriv)
	if err != nil {
		return err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	c := MazaClient{ID: hex.EncodeToString(id), Name: name, Address: address, Created: time.Now().Unix(), PrivateKey: priv, PublicKey: pub, AuthPrivate: base64.RawURLEncoding.EncodeToString(der), AuthPublic: base64.RawURLEncoding.EncodeToString(apub)}
	old := s.state
	s.state.Clients = append(append([]MazaClient{}, s.state.Clients...), c)
	s.state.Owner = user
	if err := s.save(); err != nil {
		s.state = old
		return err
	}
	s.pending = true
	if err := s.apply(); err != nil {
		return errors.New("client saved; backend update is pending, refresh status before export")
	}
	return nil
}

func (s *MazaService) Delete(user int, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.allowed(user) {
		return errors.New("access denied")
	}
	index := -1
	for i, c := range s.state.Clients {
		if c.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("client not found")
	}
	old := s.state
	next := append([]MazaClient{}, s.state.Clients[:index]...)
	s.state.Clients = append(next, s.state.Clients[index+1:]...)
	if err := s.save(); err != nil {
		s.state = old
		return err
	}
	s.pending = true
	// Remove relay authorization first, including existing TLS sessions on reload.
	if err := mazaAtomic(filepath.Join(s.dir, "relay", "server.toml"), s.relayConfig()); err != nil {
		return errors.New("revocation saved but not yet applied; retry")
	}
	if err := s.apply(); err != nil {
		return errors.New("transport revoked; backend cleanup pending")
	}
	return nil
}

func (s *MazaService) Export(user int, id string) (string, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.allowed(user) || s.pending {
		return "", nil, errors.New("export unavailable while applying changes")
	}
	var c *MazaClient
	for i := range s.state.Clients {
		if s.state.Clients[i].ID == id {
			c = &s.state.Clients[i]
			break
		}
	}
	if c == nil {
		return "", nil, errors.New("client not found")
	}
	profile := map[string]any{"version": 1, "name": c.Name, "origin": s.origin, "server_address": s.address, "wireguard_endpoint": "127.0.0.1:51829", "key_id": c.ID, "auth_private_key": c.AuthPrivate, "wireguard": map[string]any{"private_key": c.PrivateKey, "public_key": s.state.ServerPublic, "address": c.Address, "dns": []string{"1.1.1.1", "1.0.0.1"}, "allowed_ips": []string{"0.0.0.0/0", "::/0"}, "mtu": 1280, "keepalive": 25}}
	if s.address == "" {
		delete(profile, "server_address")
	}
	payload, err := json.Marshal(profile)
	if err != nil {
		return "", nil, err
	}
	link := "maza://" + base64.RawURLEncoding.EncodeToString(payload)
	client := fmt.Sprintf("origin = %q\nlisten = %q\nwireguard_endpoint = %q\nkey_id = %q\nprivate_key = %q\n", s.origin, "127.0.0.1:51821", "127.0.0.1:51829", c.ID, "client.pk8")
	if s.address != "" {
		client += fmt.Sprintf("server_address = %q\n", s.address)
	}
	wgconf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = 1.1.1.1, 1.0.0.1\nMTU = 1280\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 127.0.0.1:51821\nPersistentKeepalive = 25\n", c.PrivateKey, c.Address, s.state.ServerPublic)
	der, err := base64.RawURLEncoding.DecodeString(c.AuthPrivate)
	if err != nil {
		return "", nil, err
	}
	readme := "MAZA client bundle\n\nKeep these credentials private. Run maza-client --config client.toml, then import wireguard.conf into WireGuard.\nBefore enabling a full tunnel, route the MAZA server IP through the physical gateway to prevent a routing loop. The bridge does not configure routes or DNS.\nThe maza:// QR is MAZA profile v1; ordinary WireGuard clients cannot import it. AIRClient integration is a separate step.\n"
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for _, f := range []struct {
		name string
		data []byte
	}{{"profile.maza", []byte(link)}, {"profile.json", payload}, {"client.toml", []byte(client)}, {"client.pk8", der}, {"wireguard.conf", []byte(wgconf)}, {"README.txt", []byte(readme)}} {
		h := &zip.FileHeader{Name: f.name, Method: zip.Deflate}
		h.SetMode(0600)
		w, e := z.CreateHeader(h)
		if e != nil {
			return "", nil, e
		}
		if _, e = w.Write(f.data); e != nil {
			return "", nil, e
		}
	}
	if err := z.Close(); err != nil {
		return "", nil, err
	}
	return link, buf.Bytes(), nil
}
