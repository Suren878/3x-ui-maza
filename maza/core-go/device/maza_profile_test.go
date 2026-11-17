package device

import (
	"encoding/base64"
	"testing"
)

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
