package sub

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

func TestMazaNoWireguardLink(t *testing.T) {
	inbound := &model.Inbound{Tag: service.MazaInboundTag, Protocol: model.AmneziaWG, Port: 9443}
	if link := (&SubService{}).GetLink(inbound, "client"); link != "" {
		t.Fatal("MAZA must not export its internal WireGuard endpoint")
	}
}

func TestMazaNeverDowngradesInJSONOrClash(t *testing.T) {
	seedSubDB(t)
	serverPrivate, serverPublic := mustWireguardKeypair(t)
	clientPrivate, _ := mustWireguardKeypair(t)
	settings := fmt.Sprintf(`{"server":{"privateKey":%q,"publicKey":%q,"mtu":1280},"clients":[{"email":"native","privateKey":%q,"allowedIPs":["10.78.0.2/32"],"enable":true}]}`, serverPrivate, serverPublic, clientPrivate)
	seedTunnelSubInbound(t, model.AmneziaWG, service.MazaInboundTag, "native-sub", "native", settings, 9443)
	// Even though the raw subscription is enabled, standard formats must not
	// silently omit MAZA's header protection or padding and emit a broken peer.
	js, _, err := NewSubJsonService("", "", "", "", NewSubService("")).GetJson("native-sub", "sub.example.com", false)
	if err != nil || js != "" {
		t.Fatal("MAZA was downgraded in JSON", err)
	}
	clash, _, err := NewSubClashService(false, "", false, NewSubService("")).GetClash("native-sub", "sub.example.com")
	if err != nil || clash != "" {
		t.Fatal("MAZA was downgraded in Clash", err)
	}
}

func TestAirClientSubscriptionAlwaysUsesShareLinks(t *testing.T) {
	seedSubDB(t)
	seedSubInbound(t, "air-sub", "air", 4480, 1, `{"network":"tcp","security":"none"}`)
	router := newSubscriptionTestRouter(subscriptionTestRouterConfig{
		jsonAutoDetect: true, jsonUserAgentRegex: ".*",
		clashAutoDetect: true, clashUserAgentRegex: ".*",
	})
	for _, ua := range []string{"AIRClient/0.3.3", "sing-box/1.12 AIR Client"} {
		req := httptest.NewRequest(http.MethodGet, "http://sub.example.com/sub/air-sub", nil)
		req.Header.Set("User-Agent", ua)
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		body, err := base64.StdEncoding.DecodeString(resp.Body.String())
		if resp.Code != http.StatusOK || err != nil || !strings.HasPrefix(string(body), "vless://") {
			t.Fatalf("%s did not receive share links", ua)
		}
	}
}
