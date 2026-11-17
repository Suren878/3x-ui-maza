package device

import (
	"encoding/binary"
	"testing"
)

func mazaClassifierFixture(trailers bool) *Device {
	d := new(Device)
	d.randomTrailers.Store(trailers)
	d.paddings.init.Store(108)
	d.paddings.response.Store(113)
	d.paddings.cookie.Store(75)
	d.paddings.transport.Store(23)
	for i, target := range []*AtomicUintRange{&d.headers.init, &d.headers.response, &d.headers.cookie, &d.headers.transport} {
		var r UintRange
		lo := uint32(0x10000000 + i*0x30000000)
		r.FromUint32(lo, lo+65535)
		target.Store(r)
	}
	return d
}

func TestMazaTransportNotMistakenForHandshake(t *testing.T) {
	// Ciphertext at another S-offset can fall in a handshake's H-range.
	// With trailers enabled, a large data packet also passes its length test.
	// Match the Rust receiver: transport must take precedence in this case.
	for _, mask := range [][]byte{{0, 0, 0, 0}, {0x81, 0x17, 0x32, 0xf4}} {
		for _, collision := range []struct{ offset, value uint32 }{
			{108, 0x10000042}, {113, 0x40000042}, {75, 0x70000042},
		} {
			d := mazaClassifierFixture(true)
			packet := make([]byte, 1200)
			for _, field := range []struct{ offset, value uint32 }{{23, 0xa0000042}, collision} {
				binary.LittleEndian.PutUint32(packet[field.offset:], field.value)
				applyHash(packet[field.offset:field.offset+4], packet[field.offset:field.offset+4], mask)
			}
			_, kind, padding := d.DeterminePacketTypeAndPadding(packet, mask)
			if kind != MessageTransportType || padding != 23 {
				t.Fatalf("data classified as type %d with padding %d (collision offset %d)", kind, padding, collision.offset)
			}
		}
	}
}

func TestMazaHandshakeClassificationStillWorks(t *testing.T) {
	for _, trailers := range []bool{false, true} {
		d := mazaClassifierFixture(trailers)
		for _, tc := range []struct{ padding, size, header, kind uint32 }{
			{108, MessageInitiationSize, 0x10000042, MessageInitiationType},
			{113, MessageResponseSize, 0x40000042, MessageResponseType},
			{75, MessageCookieReplySize, 0x70000042, MessageCookieReplyType},
		} {
			length := tc.padding + tc.size
			if trailers {
				length += 137
			}
			packet := make([]byte, length)
			binary.LittleEndian.PutUint32(packet[tc.padding:], tc.header)
			size, kind, padding := d.DeterminePacketTypeAndPadding(packet, []byte{0, 0, 0, 0})
			if size != int(tc.size) || kind != tc.kind || padding != tc.padding {
				t.Fatalf("handshake classified incorrectly: size=%d type=%d padding=%d", size, kind, padding)
			}
		}
	}
}
