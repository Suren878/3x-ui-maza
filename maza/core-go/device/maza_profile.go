// SPDX-License-Identifier: MIT
// MAZA uses this local WireGuard/AWG core directly; no extra transport is used.
package device

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// MazaParameters are exportable interface settings, including a confidential
// header-protection key. Never log this map or include it in public client lists.
type MazaParameters map[string]string

var mazaTiming = map[string]string{
	"rekeyaftertime": "90-120", "rejectaftertime": "180-210",
	"rekeytimeout": "3-6", "keepalivetimeout": "8-16", "maxhandshakeattempts": "18-24",
}

func GenerateMazaParameters() (MazaParameters, error) {
	entropy := make([]byte, 64)
	if _, err := rand.Read(entropy); err != nil {
		return nil, err
	}
	p := MazaParameters{
		"headerprotectionkey":    base64.StdEncoding.EncodeToString(entropy[:32]),
		"s1":                     strconv.Itoa(96 + int(entropy[32]&31)),
		"s2":                     strconv.Itoa(96 + int(entropy[33]&31)),
		"s3":                     strconv.Itoa(64 + int(entropy[34]&31)),
		"s4":                     strconv.Itoa(16 + int(entropy[35]%16)),
		"contentpaddingaddition": "32-192", "randomtrailers": "true",
		"disablecookies": "false", "jc": "0", "jmin": "0", "jmax": "0",
		"persistentkeepaliveinterval": "15-25",
	}
	for i := 0; i < 4; i++ {
		// Four separated regions, each containing a random 65536-value window.
		start := uint64(0x10000000) + uint64(i)*0x30000000 + uint64(binary.LittleEndian.Uint32(entropy[36+i*4:])&0x0fff0000)
		p[fmt.Sprintf("h%d", i+1)] = fmt.Sprintf("%d-%d", start, start+65535)
	}
	for k, v := range mazaTiming {
		p[k] = v
	}
	return p, ValidateMazaParameters(p)
}

func ValidateMazaParameters(p MazaParameters) error {
	invalid := errors.New("invalid MAZA native profile")
	if len(p) != 21 || p["jc"] != "0" || p["jmin"] != "0" || p["jmax"] != "0" {
		return invalid
	}
	key, err := base64.StdEncoding.DecodeString(p["headerprotectionkey"])
	if err != nil || len(key) != 32 {
		return invalid
	}
	nonzero := byte(0)
	for _, b := range key {
		nonzero |= b
	}
	if nonzero == 0 {
		return invalid
	}
	for _, k := range []string{"s1", "s2", "s3", "s4"} {
		n, e := strconv.Atoi(p[k])
		if e != nil || n < 12 || n > 192 {
			return invalid
		}
	}
	var ranges [4][2]uint64
	for i := 0; i < 4; i++ {
		parts := strings.Split(p[fmt.Sprintf("h%d", i+1)], "-")
		if len(parts) != 2 {
			return invalid
		}
		lo, e1 := strconv.ParseUint(parts[0], 10, 32)
		hi, e2 := strconv.ParseUint(parts[1], 10, 32)
		if e1 != nil || e2 != nil || lo <= 4 || hi < lo || hi-lo < 128 {
			return invalid
		}
		ranges[i] = [2]uint64{lo, hi}
		for j := 0; j < i; j++ {
			if lo <= ranges[j][1] && ranges[j][0] <= hi {
				return invalid
			}
		}
	}
	if p["contentpaddingaddition"] != "32-192" || p["randomtrailers"] != "true" || p["disablecookies"] != "false" || p["persistentkeepaliveinterval"] != "15-25" {
		return invalid
	}
	for k, v := range mazaTiming {
		if p[k] != v {
			return invalid
		}
	}
	return nil
}
