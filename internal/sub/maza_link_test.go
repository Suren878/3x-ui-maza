package sub

import (
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
