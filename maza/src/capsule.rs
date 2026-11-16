//! RFC 9297 capsules and RFC 9298 context-zero UDP datagrams over HTTP/2 DATA.
use anyhow::{Result, bail, ensure};
use bytes::{Buf, Bytes, BytesMut};
use std::future::poll_fn;

pub const MAX_UDP: usize = 65_527;
const MAX_CAPSULE: usize = MAX_UDP + 8;
const MAX_FRAME: usize = 16_384;

pub fn put_varint(value: u64, out: &mut Vec<u8>) {
    assert!(value < (1 << 62));
    if value < 64 {
        out.push(value as u8);
    } else if value < 16_384 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < (1 << 30) {
        out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

fn varint(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let length = 1 << (first >> 6);
    if input.len() < length {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, length))
}

pub fn encode(payload: &[u8]) -> Result<Bytes> {
    ensure!(
        payload.len() <= MAX_UDP,
        "UDP payload exceeds RFC 9298 limit"
    );
    let mut data = Vec::with_capacity(payload.len() + 6);
    put_varint(0, &mut data);
    put_varint((payload.len() + 1) as u64, &mut data);
    put_varint(0, &mut data);
    data.extend_from_slice(payload);
    Ok(data.into())
}

#[derive(Default)]
pub struct Decoder {
    buffer: BytesMut,
    skip: u64,
}

impl Decoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            self.buffer.len() + bytes.len() <= MAX_CAPSULE + 16 + MAX_FRAME,
            "capsule buffer limit exceeded"
        );
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    pub fn datagram(&mut self) -> Result<Option<Bytes>> {
        loop {
            if self.skip != 0 {
                let count = self.skip.min(self.buffer.len() as u64) as usize;
                self.buffer.advance(count);
                self.skip -= count as u64;
                if self.skip != 0 {
                    return Ok(None);
                }
            }
            let Some((kind, a)) = varint(&self.buffer) else {
                return Ok(None);
            };
            let Some((length, b)) = varint(&self.buffer[a..]) else {
                return Ok(None);
            };
            if kind != 0 {
                // Unknown capsules must be ignored, even when their declared size is huge.
                self.buffer.advance(a + b);
                self.skip = length;
                continue;
            }
            ensure!(
                length > 0 && length <= MAX_CAPSULE as u64,
                "invalid DATAGRAM capsule length"
            );
            let total = a + b + length as usize;
            if self.buffer.len() < total {
                return Ok(None);
            }
            self.buffer.advance(a + b);
            let mut body = self.buffer.split_to(length as usize).freeze();
            let (context, used) =
                varint(&body).ok_or_else(|| anyhow::anyhow!("truncated context ID"))?;
            body.advance(used);
            if context != 0 {
                continue;
            }
            ensure!(body.len() <= MAX_UDP, "UDP payload exceeds RFC 9298 limit");
            return Ok(Some(body));
        }
    }

    pub fn finish(&self) -> Result<()> {
        ensure!(
            self.buffer.is_empty() && self.skip == 0,
            "truncated capsule stream"
        );
        Ok(())
    }
}

pub struct DatagramReceiver {
    stream: h2::RecvStream,
    decoder: Decoder,
}

impl DatagramReceiver {
    pub fn new(stream: h2::RecvStream) -> Self {
        Self {
            stream,
            decoder: Decoder::default(),
        }
    }

    /// Cancellation-safe: partially decoded capsules stay in self.
    pub async fn recv(&mut self) -> Result<Option<Bytes>> {
        loop {
            if let Some(packet) = self.decoder.datagram()? {
                return Ok(Some(packet));
            }
            match self.stream.data().await {
                Some(chunk) => {
                    let chunk = chunk?;
                    self.decoder.push(&chunk)?;
                    self.stream.flow_control().release_capacity(chunk.len())?;
                }
                None => {
                    self.decoder.finish()?;
                    return Ok(None);
                }
            }
        }
    }
}

pub struct DatagramSender(pub(crate) h2::SendStream<Bytes>);

impl DatagramSender {
    /// Once started, finish this send or close the connection; a partial capsule cannot be reused.
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        send_bytes(&mut self.0, encode(payload)?).await
    }
}

pub(crate) async fn send_bytes(stream: &mut h2::SendStream<Bytes>, mut bytes: Bytes) -> Result<()> {
    while !bytes.is_empty() {
        stream.reserve_capacity(bytes.len());
        let capacity = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .ok_or_else(|| anyhow::anyhow!("HTTP/2 send stream closed"))??;
        if capacity == 0 {
            bail!("HTTP/2 send capacity exhausted");
        }
        let count = bytes.len().min(capacity);
        stream.send_data(bytes.split_to(count), false)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_coalesced_and_empty_datagrams() {
        let mut data = encode(b"first").unwrap().to_vec();
        data.extend_from_slice(&encode(b"").unwrap());
        data.extend_from_slice(&encode(&vec![7; MAX_UDP]).unwrap());
        let mut decoder = Decoder::default();
        let mut packets = Vec::new();
        for byte in data {
            decoder.push(&[byte]).unwrap();
            while let Some(packet) = decoder.datagram().unwrap() {
                packets.push(packet);
            }
        }
        assert_eq!(
            packets,
            vec![
                Bytes::from_static(b"first"),
                Bytes::new(),
                Bytes::from(vec![7; MAX_UDP])
            ]
        );
        decoder.finish().unwrap();
    }

    #[test]
    fn skips_unknown_capsules_and_contexts_without_allocating_declared_length() {
        let mut decoder = Decoder::default();
        decoder.push(&[37, 3, 1, 2, 3, 0, 2, 1, 9]).unwrap();
        decoder.push(&encode(b"ok").unwrap()).unwrap();
        assert_eq!(decoder.datagram().unwrap().unwrap(), b"ok"[..]);
        decoder.finish().unwrap();
        let mut huge = vec![37];
        put_varint(1 << 40, &mut huge);
        decoder.push(&huge).unwrap();
        assert!(decoder.datagram().unwrap().is_none());
        assert!(decoder.buffer.capacity() < 100_000);
        assert!(decoder.finish().is_err());
    }

    #[test]
    fn rejects_oversize_and_truncated_capsules() {
        let mut decoder = Decoder::default();
        let mut bytes = vec![0];
        put_varint(1 << 40, &mut bytes);
        decoder.push(&bytes).unwrap();
        assert!(decoder.datagram().is_err());
        let mut decoder = Decoder::default();
        decoder.push(&[0, 4, 0, 7]).unwrap();
        assert!(decoder.datagram().unwrap().is_none());
        assert!(decoder.finish().is_err());
        assert!(encode(&vec![0; MAX_UDP + 1]).is_err());
    }
}
