package service

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mazacore "github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	wg "github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
)

func nativeMaza(t *testing.T) *MazaService {
	t.Helper()
	setupBulkDB(t)
	priv, pub, err := wg.GenerateWireguardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := mazacore.GenerateMazaParameters()
	if err != nil {
		t.Fatal(err)
	}
	return &MazaService{dir: t.TempDir(), origin: "udp://vpn.example.com:9443", state: mazaState{
		Version: 2, Parameters: parameters, ServerPrivate: priv, ServerPublic: pub, Clients: []MazaClient{},
	}}
}
func mazaInbound(t *testing.T) model.Inbound {
	t.Helper()
	var ib model.Inbound
	if err := database.GetDB().Where("tag = ?", mazaTag).First(&ib).Error; err != nil {
		t.Fatal(err)
	}
	return ib
}
func mazaPeerCount(t *testing.T) int {
	t.Helper()
	instances, err := (&InboundService{}).DesiredAmneziaWGInstances()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, i := range instances {
		if i.Tag == mazaTag {
			count += len(i.Peers)
		}
	}
	return count
}
func TestMazaNativeProvisionExportRevoke(t *testing.T) {
	s := nativeMaza(t)
	if err := s.Initialize(0); err == nil {
		t.Fatal("anonymous initialization")
	}
	if err := s.Initialize(1); err != nil {
		t.Fatal(err)
	}
	if err := s.Initialize(2); err == nil {
		t.Fatal("foreign owner")
	}
	ib := mazaInbound(t)
	if ib.Protocol != model.AmneziaWG || ib.Listen != "0.0.0.0" || ib.Port != mazaPort || !ib.ExcludeFromSub {
		t.Fatal("not a native managed inbound")
	}
	if err := s.CreateWithEmail(1, "Рабочий Mac", "mac"); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(1, "Laptop"); err != nil {
		t.Fatal(err)
	}
	a, b := s.state.Clients[0], s.state.Clients[1]
	if a.PrivateKey == b.PrivateKey || a.Address == b.Address {
		t.Fatal("peer isolation")
	}
	if mazaPeerCount(t) != 2 {
		t.Fatal("native peers not installed")
	}
	listing, err := s.List(1)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(listing)
	for _, secret := range []string{a.PrivateKey, s.state.ServerPrivate, s.state.Parameters["headerprotectionkey"]} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatal("credential leaked through listing")
		}
	}
	id, link, err := s.ExportByEmail(1, "mac")
	if err != nil || id != a.ID {
		t.Fatal("direct share unavailable", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, "maza://"))
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		Version   int
		Server    string
		Port      int
		Maza      mazacore.MazaParameters
		Wireguard map[string]any
	}
	if err := json.Unmarshal(payload, &profile); err != nil {
		t.Fatal(err)
	}
	if profile.Version != 2 || profile.Server != "vpn.example.com" || profile.Port != 9443 || profile.Wireguard["private_key"] != a.PrivateKey {
		t.Fatal("native export incorrect")
	}
	if err := mazacore.ValidateMazaParameters(profile.Maza); err != nil {
		t.Fatal(err)
	}
	for _, old := range []string{"auth_private_key", "wireguard_endpoint", "origin"} {
		if bytes.Contains(payload, []byte(old)) {
			t.Fatal("obsolete transport in native profile")
		}
	}
	_, bundle, err := s.Export(1, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	if err != nil || len(z.File) != 3 {
		t.Fatal("bundle format", err)
	}
	for _, f := range z.File {
		if f.Mode().Perm() != 0600 {
			t.Fatal("bundle mode")
		}
	}
	info, err := os.Stat(filepath.Join(s.dir, "state.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private state mode")
	}
	if _, err := os.Stat(filepath.Join(s.dir, "relay")); !os.IsNotExist(err) {
		t.Fatal("obsolete relay directory created")
	}
	if err := s.Delete(1, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Export(1, a.ID); err == nil {
		t.Fatal("revoked profile exported")
	}
	if mazaPeerCount(t) != 1 {
		t.Fatal("native peer not revoked")
	}
	if err := s.Delete(1, b.ID); err != nil {
		t.Fatal(err)
	}
	if mazaPeerCount(t) != 0 {
		t.Fatal("empty peer set not applied")
	}
}
func TestMazaNativeEnableRemoveAndRetry(t *testing.T) {
	s := nativeMaza(t)
	if err := s.CreateWithEmail(1, "phone", "phone"); err != nil {
		t.Fatal(err)
	}
	c := s.state.Clients[0]
	if err := s.SetClientEnabled(1, c.ID, false); err != nil {
		t.Fatal(err)
	}
	if mazaPeerCount(t) != 0 {
		t.Fatal("disabled peer remains")
	}
	if err := s.SetClientEnabled(1, c.ID, true); err != nil {
		t.Fatal(err)
	}
	if mazaPeerCount(t) != 1 {
		t.Fatal("enabled peer missing")
	}
	name, off, on := "Office MAZA", false, true
	if err := s.Configure(1, &name, &off); err != nil {
		t.Fatal(err)
	}
	if mazaPeerCount(t) != 0 || mazaInbound(t).Remark != name {
		t.Fatal("inbound settings")
	}
	if err := s.Configure(1, nil, &on); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(2); err == nil {
		t.Fatal("foreign delete")
	}
	s.activate = func() error { return errors.New("core unavailable") }
	if err := s.Remove(1); err == nil || !s.pending || !s.state.Deleting {
		t.Fatal("lost pending deletion")
	}
	var persisted mazaState
	data, err := os.ReadFile(filepath.Join(s.dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(data, &persisted) != nil || !persisted.Deleting || len(persisted.Clients) != 0 {
		t.Fatal("deletion not durable")
	}
	s.activate = func() error { return nil }
	if err := s.apply(); err != nil {
		t.Fatal(err)
	}
	if s.pending || s.state.Owner != 0 {
		t.Fatal("retry incomplete")
	}
	if err := s.Initialize(1); err != nil {
		t.Fatal(err)
	}
}
func TestMazaPendingActivationDoesNotExportCredentials(t *testing.T) {
	s := nativeMaza(t)
	s.activate = func() error { return errors.New("core unavailable") }
	if err := s.Create(1, "pending"); err == nil || !s.pending {
		t.Fatal("activation failure hidden")
	}
	if _, _, err := s.Export(1, s.state.Clients[0].ID); err == nil {
		t.Fatal("pending profile exported")
	}
	s.activate = func() error { return nil }
	if err := s.apply(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Export(1, s.state.Clients[0].ID); err != nil {
		t.Fatal(err)
	}
}
func TestMazaPreservesOrdinaryPeer(t *testing.T) {
	s := nativeMaza(t)
	if err := s.Initialize(1); err != nil {
		t.Fatal(err)
	}
	ib := mazaInbound(t)
	_, pub, err := wg.GenerateWireguardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	add := &model.Inbound{Id: ib.Id, Protocol: model.AmneziaWG, Settings: clientsSettings(t, []model.Client{{Email: "ordinary", Enable: true, PublicKey: pub, AllowedIPs: []string{"10.78.0.2/32"}}})}
	if _, err := (&ClientService{}).AddInboundClient(&InboundService{}, add); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(1, "managed"); err != nil {
		t.Fatal(err)
	}
	if s.state.Clients[0].Address != "10.78.0.3/32" {
		t.Fatal("address collision")
	}
	if err := s.Delete(1, s.state.Clients[0].ID); err != nil {
		t.Fatal(err)
	}
	peers, err := (&ClientService{}).ListForInbound(nil, ib.Id)
	if err != nil || len(peers) != 1 || peers[0].Email != "ordinary" {
		t.Fatal("unrelated peer changed")
	}
}
func TestMazaRejectsInvalidNames(t *testing.T) {
	for _, s := range []string{"", "   ", "name\nline", "\x00", strings.Repeat("a", 65), string([]byte{0xff})} {
		if _, err := mazaName(s); err == nil {
			t.Fatal("invalid name accepted")
		}
	}
}

func TestMazaRevocationRemovesOrphansAndAllowsNameReuse(t *testing.T) {
	s := nativeMaza(t)
	for i := 0; i < 2; i++ {
		if err := s.CreateWithEmail(1, "Reusable", "reuse"); err != nil {
			t.Fatal(err)
		}
		id := s.state.Clients[0].ID
		if err := s.Delete(1, id); err != nil {
			t.Fatal(err)
		}
		var count int64
		if err := database.GetDB().Model(&model.ClientRecord{}).Where("email = ?", "reuse").Count(&count).Error; err != nil || count != 0 {
			t.Fatal("revocation left an orphan", err)
		}
	}
	if err := s.CreateWithEmail(1, "Reusable", "reuse"); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(1); err != nil {
		t.Fatal(err)
	}
	var count int64
	database.GetDB().Model(&model.ClientRecord{}).Where("email = ?", "reuse").Count(&count)
	if count != 0 {
		t.Fatal("inbound removal left an orphan")
	}
}
