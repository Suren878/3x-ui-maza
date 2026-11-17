package service

// MAZA runs the vendored native WireGuard/AWG core in the panel process.
// Desired state is durable before reconciliation, allowing interrupted updates
// to be retried. No HTTPS relay, extra authentication keys or proxy hop is used.
import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	mazacore "github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/mhsanaei/3x-ui/v3/internal/config"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	wg "github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
	"gorm.io/gorm"
)

const MazaInboundTag = "maza-managed"
const mazaTag = MazaInboundTag
const mazaPort = 9443

type MazaClient struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Email      string `json:"email,omitempty"`
	Disabled   bool   `json:"disabled,omitempty"`
	Address    string `json:"address"`
	Created    int64  `json:"created"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

func mazaClientEmail(c MazaClient) string {
	if c.Email != "" {
		return c.Email
	}
	return "maza-" + c.ID
}

type mazaState struct {
	Parameters    mazacore.MazaParameters `json:"parameters"`
	Migrate       bool                    `json:"migrate,omitempty"`
	Version       int                     `json:"version"`
	Owner         int                     `json:"owner"`
	Remark        string                  `json:"remark,omitempty"`
	Disabled      bool                    `json:"disabled,omitempty"`
	Deleting      bool                    `json:"deleting,omitempty"`
	Revoked       []string                `json:"revoked,omitempty"`
	ServerPrivate string                  `json:"serverPrivate"`
	ServerPublic  string                  `json:"serverPublic"`
	Clients       []MazaClient            `json:"clients"`
}

type MazaService struct {
	mu          sync.Mutex
	dir, origin string
	state       mazaState
	pending     bool
	activate    func() error
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
	endpoint := os.Getenv("MAZA_ENDPOINT")
	if endpoint == "" {
		return nil, nil
	}
	u, err := url.Parse("udp://" + endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, errors.New("invalid MAZA_ENDPOINT")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("MAZA_ENDPOINT requires a port")
	}
	s := &MazaService{dir: filepath.Join(config.GetDBFolderPath(), "maza"), origin: u.String(), pending: true}
	s.activate = func() error { return (&XrayService{}).RestartXray(false) }
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(s.dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		priv, pub, err := wg.GenerateWireguardKeypair()
		if err != nil {
			return nil, err
		}
		parameters, err := mazacore.GenerateMazaParameters()
		if err != nil {
			return nil, err
		}
		s.state = mazaState{Version: 2, Parameters: parameters, ServerPrivate: priv, ServerPublic: pub, Clients: []MazaClient{}}
		if err := s.save(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if err := json.Unmarshal(b, &s.state); err != nil {
		return nil, err
	}
	if s.state.Version == 1 {
		if len(s.state.Clients) != 0 {
			return nil, errors.New("remove prototype MAZA clients before migrating")
		}
		parameters, err := mazacore.GenerateMazaParameters()
		if err != nil {
			return nil, err
		}
		s.state.Version, s.state.Parameters, s.state.Migrate = 2, parameters, true
		if err := s.save(); err != nil {
			return nil, err
		}
	}
	if err := mazacore.ValidateMazaParameters(s.state.Parameters); err != nil {
		return nil, err
	}
	if s.state.Version != 2 || len(s.state.Clients) > 64 {
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

func (s *MazaService) nativeSettings(clients []model.Client) ([]byte, error) {
	mtu, err := mazacore.MazaInnerMTU(s.state.Parameters)
	if err != nil {
		return nil, err
	}
	server := map[string]any{"privateKey": s.state.ServerPrivate, "publicKey": s.state.ServerPublic,
		"subnetIp": "10.78.0.0", "subnetCidr": 24, "mtu": mtu, "primaryDns": "1.1.1.1", "secondaryDns": "1.0.0.1"}
	names := map[string]string{"headerprotectionkey": "headerProtectionKey", "contentpaddingaddition": "contentPaddingAddition",
		"rekeyaftertime": "rekeyAfterTime", "rejectaftertime": "rejectAfterTime", "rekeytimeout": "rekeyTimeout",
		"keepalivetimeout": "keepaliveTimeout", "maxhandshakeattempts": "maxHandshakeAttempts",
		"randomtrailers": "randomTrailers", "disablecookies": "disableCookies"}
	for k, v := range s.state.Parameters {
		if k == "persistentkeepaliveinterval" {
			continue
		} // Set on the initiating client.
		name := k
		if n, ok := names[k]; ok {
			name = n
		}
		if k == "randomtrailers" || k == "disablecookies" {
			server[name] = (v == "true")
		} else if k == "s1" || k == "s2" || k == "s3" || k == "s4" || k == "jc" || k == "jmin" || k == "jmax" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, errors.New("invalid MAZA parameter")
			}
			server[name] = n
		} else {
			server[name] = v
		}
	}
	return json.Marshal(map[string]any{"server": server, "clients": clients})
}

func (s *MazaService) apply() error {
	if s.state.Migrate {
		var old model.Inbound
		err := database.GetDB().Where("tag = ?", mazaTag).First(&old).Error
		if err == nil && old.Protocol == model.WireGuard {
			peers, e := (&ClientService{}).ListForInbound(nil, old.Id)
			if e != nil {
				return e
			}
			if len(peers) != 0 || old.Listen != "127.0.0.1" || old.Port != 51829 || old.UserId != s.state.Owner {
				return errors.New("prototype MAZA inbound is not empty; migration refused")
			}
			if _, err = (&InboundService{}).DelInbound(old.Id); err != nil {
				return err
			}
		} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		s.state.Migrate = false
		if err := s.save(); err != nil {
			s.state.Migrate = true
			return err
		}
	}
	if s.state.Deleting {
		var inbound model.Inbound
		err := database.GetDB().Where("tag = ?", mazaTag).First(&inbound).Error
		if err == nil {
			if inbound.Protocol != model.AmneziaWG || inbound.UserId != s.state.Owner || inbound.Port != mazaPort || inbound.Listen != "0.0.0.0" {
				return errors.New("MAZA backend conflicts with an existing inbound")
			}
			if _, err = (&InboundService{}).DelInbound(inbound.Id); err != nil {
				return err
			}
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err := s.cleanupRevoked(); err != nil {
			return err
		}
		if s.activate != nil {
			if err := s.activate(); err != nil {
				return err
			}
		}
		old := s.state
		s.state.Owner, s.state.Remark, s.state.Disabled, s.state.Deleting = 0, "", false, false
		s.state.Revoked = nil
		if err := s.save(); err != nil {
			s.state = old
			return err
		}
		s.pending = false
		return nil
	}
	if s.state.Owner != 0 {
		clients := make([]model.Client, 0, len(s.state.Clients))
		for _, c := range s.state.Clients {
			clients = append(clients, model.Client{Email: mazaClientEmail(c), Comment: c.Name, Enable: !c.Disabled, PublicKey: c.PublicKey, AllowedIPs: []string{c.Address}, KeepAlive: model.KeepAlivePtr(0)})
		}
		settings, err := s.nativeSettings(clients)
		if err != nil {
			return err
		}
		var inbound model.Inbound
		err = database.GetDB().Where("tag = ?", mazaTag).First(&inbound).Error
		isNew := errors.Is(err, gorm.ErrRecordNotFound)
		if err != nil && !isNew {
			return err
		}
		if !isNew && (inbound.Protocol != model.AmneziaWG || inbound.UserId != s.state.Owner || inbound.Port != mazaPort || inbound.Listen != "0.0.0.0") {
			return errors.New("MAZA backend conflicts with an existing inbound")
		}
		inbound.UserId = s.state.Owner
		remark := s.state.Remark
		if remark == "" {
			remark = "MAZA"
		}
		inbound.Tag, inbound.Remark = mazaTag, remark
		inbound.Protocol, inbound.Listen, inbound.Port, inbound.Enable = model.AmneziaWG, "0.0.0.0", mazaPort, !s.state.Disabled
		inbound.ExcludeFromSub = false
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
		// Ordinary inbound updates intentionally preserve enable; use its dedicated API.
		if _, err := inboundSvc.SetInboundEnable(inbound.Id, !s.state.Disabled); err != nil {
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
		revoked := make(map[string]bool, len(s.state.Revoked))
		for _, id := range s.state.Revoked {
			revoked[id] = true
			revoked["maza-"+id] = true
		}
		for _, c := range clients {
			wanted[c.Email] = c
		}
		for _, c := range stored {
			if expected, ok := wanted[c.Email]; ok {
				if c.PublicKey != expected.PublicKey || strings.Join(c.AllowedIPs, ",") != strings.Join(expected.AllowedIPs, ",") {
					return errors.New("managed WireGuard peer was changed outside MAZA")
				}
				if c.Enable != expected.Enable {
					if _, _, err := clientSvc.SetClientEnableByEmail(inboundSvc, c.Email, expected.Enable); err != nil {
						return err
					}
				}
				delete(wanted, c.Email)
			} else if revoked[c.Email] {
				if _, err := clientSvc.DelInboundClientByEmail(inboundSvc, inbound.Id, c.Email, false, false); err != nil {
					return err
				}
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
			if _, err := clientSvc.AddInboundClient(inboundSvc, &model.Inbound{Id: inbound.Id, Protocol: model.AmneziaWG, Settings: string(data)}); err != nil {
				return err
			}
		}
		// The low-level inbound API does not mint a subscription ID for the
		// first peer. Repair only missing IDs through the normal client API;
		// existing subscription tokens and peer keys remain unchanged.
		for _, c := range clients {
			record, err := clientSvc.GetRecordByEmail(nil, c.Email)
			if err != nil {
				return err
			}
			if record.SubID == "" {
				if _, err := clientSvc.Update(inboundSvc, record.Id, *record.ToClient(), record.LimitHwid); err != nil {
					return err
				}
			}
		}
		if err := s.cleanupRevoked(); err != nil {
			return err
		}
		if s.activate != nil {
			if err := s.activate(); err != nil {
				return err
			}
		}
	}
	if len(s.state.Revoked) > 0 {
		old := s.state.Revoked
		s.state.Revoked = nil
		if err := s.save(); err != nil {
			s.state.Revoked = old
			return err
		}
	}
	s.pending = false
	return nil
}

func (s *MazaService) allowed(user int) bool { return s.state.Owner == 0 || s.state.Owner == user }

// Initialize creates the singleton managed inbound without provisioning a client.
func (s *MazaService) Initialize(user int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if user <= 0 || !s.allowed(user) {
		return errors.New("access denied")
	}
	if s.state.Owner != 0 {
		return errors.New("MAZA is already configured; manage it on the MAZA page")
	}
	s.state.Owner = user
	if err := s.save(); err != nil {
		s.state.Owner = 0
		return err
	}
	s.pending = true
	if err := s.apply(); err != nil {
		return errors.New("MAZA saved; backend update is pending")
	}
	return nil
}

func (s *MazaService) List(user int) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.allowed(user) {
		return nil, errors.New("MAZA belongs to another administrator")
	}
	clients := make([]map[string]any, 0, len(s.state.Clients))
	for _, c := range s.state.Clients {
		clients = append(clients, map[string]any{"id": c.ID, "name": c.Name, "email": mazaClientEmail(c), "address": c.Address, "created": c.Created, "enabled": !c.Disabled})
	}
	return map[string]any{"clients": clients, "origin": s.origin, "pending": s.pending, "limit": 64, "remark": s.state.Remark, "enabled": !s.state.Disabled}, nil
}

// Configure persists the desired state before changing the runtime.
func (s *MazaService) Configure(user int, remark *string, enabled *bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if user <= 0 || s.state.Owner != user || s.state.Deleting {
		return errors.New("access denied")
	}
	if s.pending {
		return errors.New("previous change is still being applied")
	}
	old := s.state
	if remark != nil {
		name, err := mazaName(*remark)
		if err != nil {
			return err
		}
		s.state.Remark = name
	}
	if enabled != nil {
		s.state.Disabled = !*enabled
	}
	if err := s.save(); err != nil {
		s.state = old
		return err
	}
	s.pending = true
	if err := s.apply(); err != nil {
		return errors.New("settings saved; backend update is pending")
	}
	return nil
}

// Remove revokes all clients before deleting the managed inbound. The tombstone is
// persisted so the reconciler completes the operation after interruption.
func (s *MazaService) Remove(user int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if user <= 0 || s.state.Owner != user {
		return errors.New("access denied")
	}
	if s.pending {
		return errors.New("previous change is still being applied")
	}
	old := s.state
	s.state.Revoked = append([]string{}, s.state.Revoked...)
	for _, c := range s.state.Clients {
		s.state.Revoked = append(s.state.Revoked, mazaClientEmail(c))
	}
	s.state.Deleting, s.state.Clients = true, []MazaClient{}
	if err := s.save(); err != nil {
		s.state = old
		return err
	}
	s.pending = true
	if err := s.apply(); err != nil {
		return errors.New("deletion saved; revocation is being retried")
	}
	return nil
}

func mazaName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 || !utf8.ValidString(name) || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", errors.New("name must contain 1–64 UTF-8 bytes without control characters")
	}
	return name, nil
}

func (s *MazaService) Create(user int, name string) error {
	return s.CreateWithEmail(user, name, "")
}

func (s *MazaService) CreateWithEmail(user int, name, email string) error {
	return s.createWithEmail(user, name, email, false)
}

// QueueClient persists the client before replying to an administrator who may
// be using this VPN. The existing reconciler applies it outside the HTTP request;
// changing Xray's SOCKS account list can restart the core and break that request.
func (s *MazaService) QueueClient(user int, name, email string) error {
	return s.createWithEmail(user, name, email, true)
}

func (s *MazaService) createWithEmail(user int, name, email string, queued bool) error {
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
	email = strings.TrimSpace(email)
	if email != "" {
		if err := validateClientEmail(email); err != nil {
			return err
		}
		var count int64
		if err := database.GetDB().Model(&model.ClientRecord{}).Where("LOWER(email) = LOWER(?)", email).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return errors.New("client name already exists")
		}
	}
	if len(s.state.Clients) >= 64 {
		return errors.New("64-client limit reached")
	}
	used := map[string]bool{}
	var reserved []netip.Prefix
	for _, c := range s.state.Clients {
		if c.Name == name {
			return errors.New("client name already exists")
		}
		used[c.Address] = true
	}
	// Reserve addresses of peers added through ordinary 3x-ui as well; never
	// silently detach an unrelated client while reconciling MAZA's own peers.
	var inbound model.Inbound
	if err := database.GetDB().Where("tag = ?", mazaTag).First(&inbound).Error; err == nil {
		peers, err := (&ClientService{}).ListForInbound(nil, inbound.Id)
		if err != nil {
			return err
		}
		for _, peer := range peers {
			for _, addr := range peer.AllowedIPs {
				used[addr] = true
				if prefix, err := netip.ParsePrefix(addr); err == nil {
					reserved = append(reserved, prefix)
				}
			}
		}
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	address := ""
	for i := 2; i < 255; i++ {
		v := fmt.Sprintf("10.78.0.%d/32", i)
		addr := netip.MustParseAddr(fmt.Sprintf("10.78.0.%d", i))
		taken := used[v]
		for _, prefix := range reserved {
			if prefix.Contains(addr) {
				taken = true
				break
			}
		}
		if !taken {
			address = v
			break
		}
	}
	if address == "" {
		return errors.New("no free MAZA client addresses")
	}
	priv, pub, err := wg.GenerateWireguardKeypair()
	if err != nil {
		return err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	c := MazaClient{ID: hex.EncodeToString(id), Name: name, Email: email, Address: address, Created: time.Now().Unix(), PrivateKey: priv, PublicKey: pub}
	old := s.state
	s.state.Clients = append(append([]MazaClient{}, s.state.Clients...), c)
	s.state.Owner = user
	if err := s.save(); err != nil {
		s.state = old
		return err
	}
	s.pending = true
	if queued {
		return nil
	}
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
	s.state.Revoked = append(append([]string{}, s.state.Revoked...), mazaClientEmail(old.Clients[index]))
	if err := s.save(); err != nil {
		s.state = old
		return err
	}
	s.pending = true
	if err := s.apply(); err != nil {
		return errors.New("revocation saved; native core update pending")
	}
	return nil
}

func (s *MazaService) SetClientEnabled(user int, id string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if user <= 0 || s.state.Owner != user || s.state.Deleting {
		return errors.New("access denied")
	}
	if s.pending {
		return errors.New("previous change is still being applied")
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
	s.state.Clients = append([]MazaClient{}, s.state.Clients...)
	s.state.Clients[index].Disabled = !enabled
	if err := s.save(); err != nil {
		s.state = old
		return err
	}
	s.pending = true
	if err := s.apply(); err != nil {
		return errors.New("change saved; backend update is pending")
	}
	return nil
}

func (s *MazaService) ExportByEmail(user int, email string) (string, string, error) {
	s.mu.Lock()
	if !s.allowed(user) || user <= 0 {
		s.mu.Unlock()
		return "", "", errors.New("access denied")
	}
	id := ""
	for _, c := range s.state.Clients {
		if mazaClientEmail(c) == email {
			id = c.ID
			break
		}
	}
	s.mu.Unlock()
	if id == "" {
		return "", "", errors.New("MAZA profile not found")
	}
	link, _, err := s.Export(user, id)
	return id, link, err
}

// SubscriptionURL exposes the existing client's subscription, without issuing
// new credentials or changing the peer when the URL is refreshed.
func (s *MazaService) SubscriptionURL(user int, id, host string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if user <= 0 || !s.allowed(user) || s.pending {
		return "", errors.New("subscription unavailable")
	}
	for _, c := range s.state.Clients {
		if c.ID != id {
			continue
		}
		settings := &SettingService{}
		enabled, err := settings.GetSubEnable()
		if err != nil || !enabled {
			return "", errors.New("subscriptions are disabled")
		}
		record, err := (&ClientService{}).GetRecordByEmail(nil, mazaClientEmail(c))
		if err != nil || record.SubID == "" {
			return "", errors.New("subscription not found")
		}
		uri, err := settings.GetSubURI()
		if err != nil {
			return "", err
		}
		if uri == "" {
			path, err := settings.GetSubPath()
			if err != nil {
				return "", err
			}
			uri = settings.BuildSubURIBase(host) + path
		}
		return strings.TrimRight(uri, "/") + "/" + url.PathEscape(record.SubID), nil
	}
	return "", errors.New("client not found")
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
	endpoint, _ := url.Parse(s.origin)
	port, _ := strconv.Atoi(endpoint.Port())
	profile := map[string]any{"version": 2, "name": c.Name, "server": endpoint.Hostname(), "port": port, "maza": s.state.Parameters,
		"wireguard": map[string]any{"private_key": c.PrivateKey, "public_key": s.state.ServerPublic, "address": c.Address,
			"dns": []string{"1.1.1.1", "1.0.0.1"}, "allowed_ips": []string{"0.0.0.0/0", "::/0"}, "mtu": 1280, "keepalive": 20}}
	payload, err := json.Marshal(profile)
	if err != nil {
		return "", nil, err
	}
	link := "maza://" + base64.RawURLEncoding.EncodeToString(payload)
	readme := "MAZA native profile v2\n\nImport profile.maza, profile.json or the QR code into AIRClient 0.3.2 or newer.\nThe client uses the native MAZA WireGuard-derived UDP core. No local bridge or TLS relay is required.\nKeep this profile private. Ordinary WireGuard clients cannot use it.\n"
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for _, f := range []struct {
		name string
		data []byte
	}{{"profile.maza", []byte(link)}, {"profile.json", payload}, {"README.txt", []byte(readme)}} {
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

// IsManagedClient protects the durable desired state from generic client edits.
// Managed clients must use the MAZA API so changes and revocations survive restart.
func (s *MazaService) IsManagedClient(email string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.state.Clients {
		if mazaClientEmail(c) == email {
			return true
		}
	}
	return false
}

// Remove only orphan records owned by an explicit MAZA revocation. Preserve any
// unrelated attachments or external links the administrator added separately.
func (s *MazaService) cleanupRevoked() error {
	clients := &ClientService{}
	for _, email := range s.state.Revoked {
		rec, err := clients.GetRecordByEmail(nil, email)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		ids, err := clients.GetInboundIdsForRecord(rec.Id)
		if err != nil {
			return err
		}
		links, err := clients.GetExternalLinksForRecord(rec.Id)
		if err != nil {
			return err
		}
		if len(ids) == 0 && len(links) == 0 {
			if _, err := clients.DeleteByEmail(&InboundService{}, email, false); err != nil {
				return err
			}
		}
	}
	return nil
}
