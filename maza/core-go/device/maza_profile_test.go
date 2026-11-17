package device

import (
	"encoding/base64"
	"strconv"
	"testing"
)

func TestMazaPathMTUBoundsPaddingAndTrailers(t *testing.T) {
	p, err := GenerateMazaParameters()
	if err != nil {
		t.Fatal(err)
	}
	for s4 := 12; s4 <= 192; s4++ {
		p["s4"] = strconv.Itoa(s4)
		mtu, err := MazaInnerMTU(p)
		if err != nil || mtu+s4+MinMessageSize+48 != 1280 {
			t.Fatalf("bad inner MTU for S4=%d: %d, %v", s4, mtu, err)
		}
		d := new(Device)
		d.tun.mtu.Store(int32(mtu))
		d.paddings.transport.Store(uint32(s4))
		d.randomTrailers.Store(true)
		var addition UintRange
		addition.FromUint32(32, 192)
		d.contentPaddingAddition.Store(addition)
		peer := &Peer{device: d}
		peer.udpWindow.Store(65535) // Older client or a previous, larger path.
		for _, size := range []int{0, 148, 1200, 1231, 1232, 1400} {
			for i := 0; i < 100; i++ {
				for _, pad := range []int{peer.randomPaddingAddition(size), peer.randomTrailer(size), d.randomTrailer(size)} {
					if pad < 0 || pad > max(1232-size, 0) {
						t.Fatalf("S4=%d size=%d padding=%d exceeds path", s4, size, pad)
					}
				}
			}
		}
	}
}

func TestMazaGeneratedProfiles(t *testing.T) {
	var previous string
	for i := 0; i < 100; i++ {
		p, err := GenerateMazaParameters()
		if err != nil {
			t.Fatal(err)
		}
		if p["headerprotectionkey"] == previous {
			t.Fatal("repeated protection key")
		}
		previous = p["headerprotectionkey"]
		if p["s1"] != p["s2"] || p["s1"] != p["s3"] || p["s1"] != p["s4"] {
			t.Fatal("new profiles need a shared packet-type offset with random trailers")
		}
		for k, v := range p {
			delete(p, k)
			if ValidateMazaParameters(p) == nil {
				t.Fatalf("missing %s accepted", k)
			}
			p[k] = v
		}
		for k, v := range map[string]string{"headerprotectionkey": base64.StdEncoding.EncodeToString(make([]byte, 32)), "h2": p["h1"], "randomtrailers": "false", "disablecookies": "true", "s1": "0", "jc": "10", "rekeyaftertime": "120", "persistentkeepaliveinterval": "20"} {
			old := p[k]
			p[k] = v
			if ValidateMazaParameters(p) == nil {
				t.Fatalf("invalid %s accepted", k)
			}
			p[k] = old
		}
	}
}
