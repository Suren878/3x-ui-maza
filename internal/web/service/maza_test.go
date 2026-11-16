package service

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	wg "github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
)

func TestMazaProvisionExportRevoke(t *testing.T) {
	setupBulkDB(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "relay"), 0700); err != nil {
		t.Fatal(err)
	}
	priv, pub, err := wg.GenerateWireguardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	s := &MazaService{dir: dir, origin: "https://vpn.example.com:9443", address: "192.0.2.1:9443", state: mazaState{Version: 1, ServerPrivate: priv, ServerPublic: pub, Clients: []MazaClient{}}}
	if err := s.Create(1, "Рабочий Mac"); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(1, "Рабочий Mac"); err == nil {
		t.Fatal("duplicate name accepted")
	}
	if err := s.Create(2, "other admin"); err == nil {
		t.Fatal("owner check bypassed")
	}
	if err := s.Create(1, "Laptop"); err != nil {
		t.Fatal(err)
	}
	a, b := s.state.Clients[0], s.state.Clients[1]
	if a.Address == b.Address || a.PrivateKey == b.PrivateKey || a.AuthPrivate == b.AuthPrivate {
		t.Fatal("client credentials are not isolated")
	}
	listing, err := s.List(1)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(listing)
	if bytes.Contains(encoded, []byte(a.PrivateKey)) || bytes.Contains(encoded, []byte(a.AuthPrivate)) {
		t.Fatal("list leaked credentials")
	}
	link, bundle, err := s.Export(1, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, "maza://"))
	if err != nil {
		t.Fatal(err)
	}
	var profile map[string]any
	if err = json.Unmarshal(payload, &profile); err != nil {
		t.Fatal(err)
	}
	der, err := base64.RawURLEncoding.DecodeString(profile["auth_private_key"].(string))
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	derived := base64.RawURLEncoding.EncodeToString(key.(ed25519.PrivateKey).Public().(ed25519.PublicKey))
	if derived != a.AuthPublic {
		t.Fatal("exported auth key mismatch")
	}
	r, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.File) != 6 {
		t.Fatal("incomplete bundle")
	}
	for _, f := range r.File {
		if f.Mode().Perm() != 0600 {
			t.Fatal("bundle files must be private")
		}
	}
	stat, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("state file permissions")
	}
	var ib model.Inbound
	if err := database.GetDB().Where("tag = ?", mazaTag).First(&ib).Error; err != nil {
		t.Fatal(err)
	}
	if ib.Listen != "127.0.0.1" || ib.Port != mazaPort || ib.Protocol != model.WireGuard {
		t.Fatal("backend is not isolated")
	}
	if err := s.Delete(1, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Export(1, a.ID); err == nil {
		t.Fatal("revoked client exported")
	}
	config, err := os.ReadFile(filepath.Join(dir, "relay", "server.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(config, []byte(a.AuthPublic)) || !bytes.Contains(config, []byte(b.AuthPublic)) {
		t.Fatal("relay revocation incorrect")
	}
	clients, err := (&ClientService{}).ListForInbound(nil, ib.Id)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].PublicKey != b.PublicKey {
		t.Fatalf("WireGuard peer was not revoked; remaining peers: %d", len(clients))
	}
	if err := s.Delete(1, b.ID); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(s.relayConfig(), []byte("clients = []")) {
		t.Fatal("empty authorization must remain valid TOML")
	}
}

func TestMazaPendingActivationDoesNotExportCredentials(t *testing.T) {
	setupBulkDB(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "relay"), 0700); err != nil {
		t.Fatal(err)
	}
	priv, pub, err := wg.GenerateWireguardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	s := &MazaService{dir: dir, origin: "https://vpn.example.com", state: mazaState{Version: 1, ServerPrivate: priv, ServerPublic: pub, Clients: []MazaClient{}}, activate: func() error { return errors.New("core unavailable") }}
	if err := s.apply(); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(1, "pending"); err == nil {
		t.Fatal("activation failure must be visible")
	}
	if !s.pending {
		t.Fatal("failed activation lost retry state")
	}
	if _, _, err := s.Export(1, s.state.Clients[0].ID); err == nil {
		t.Fatal("unapplied profile exported")
	}
	data, err := os.ReadFile(filepath.Join(dir, "relay", "server.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(s.state.Clients[0].AuthPublic)) {
		t.Fatal("unapplied key authorized")
	}
	s.activate = func() error { return nil }
	if err := s.apply(); err != nil {
		t.Fatal(err)
	}
	if s.pending {
		t.Fatal("retry did not complete")
	}
	_, bundle, err := s.Export(1, s.state.Clients[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range z.File {
		if f.Name == "client.toml" {
			r, e := f.Open()
			if e != nil {
				t.Fatal(e)
			}
			var b bytes.Buffer
			_, e = b.ReadFrom(r)
			r.Close()
			if e != nil {
				t.Fatal(e)
			}
			if bytes.Contains(b.Bytes(), []byte("server_address")) {
				t.Fatal("domain-only config should use DNS")
			}
		}
	}
}

func TestMazaRejectsInvalidNames(t *testing.T) {
	for _, s := range []string{"", "   ", "name\nline", "\x00", strings.Repeat("a", 65), string([]byte{0xff})} {
		if _, err := mazaName(s); err == nil {
			t.Fatal("invalid name accepted")
		}
	}
}
