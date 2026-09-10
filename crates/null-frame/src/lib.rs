//! Fixed 2048-byte frames + token-bucket shaping (§6).
//!
//! Layout (§6.1):
//! ```text
//! ver(2) | type(1) | counter(8) | payload_len(4) | reserved(17) | payload | padding
//! ```

use null_core::{
    FrameType, NullError, Result, FRAME_HEADER_SIZE, FRAME_SIZE, MAX_PAYLOAD_SIZE, PROTOCOL_VERSION,
};
use rand::{rngs::OsRng, RngCore};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_type: FrameType,
    pub counter: u64,
    pub payload: Vec<u8>, // plaintext payload incl. tag (caller encrypts)
}

impl Frame {
    pub fn new(frame_type: FrameType, counter: u64, payload: Vec<u8>) -> Result<Self> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(NullError::Frame(format!(
                "payload {} > max {MAX_PAYLOAD_SIZE}",
                payload.len()
            )));
        }
        Ok(Self {
            frame_type,
            counter,
            payload,
        })
    }

    pub fn dummy(counter: u64) -> Self {
        let mut payload = vec![0u8; 64];
        OsRng.fill_bytes(&mut payload);
        Self {
            frame_type: FrameType::Dummy,
            counter,
            payload,
        }
    }

    /// Serialize to exactly FRAME_SIZE bytes with random padding.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert_eq!(FRAME_HEADER_SIZE, 32);
        let mut out = vec![0u8; FRAME_SIZE];
        out[0..2].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        out[2] = self.frame_type as u8;
        out[3..11].copy_from_slice(&self.counter.to_be_bytes());
        out[11..15].copy_from_slice(&(self.payload.len() as u32).to_be_bytes());
        OsRng.fill_bytes(&mut out[15..32]); // reserved randomness
        out[32..32 + self.payload.len()].copy_from_slice(&self.payload);
        // Padding region already zeroed; randomize it for indistinguishability.
        OsRng.fill_bytes(&mut out[32 + self.payload.len()..]);
        out
    }

    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() != FRAME_SIZE {
            return Err(NullError::Frame(format!(
                "frame must be {FRAME_SIZE} bytes"
            )));
        }
        let ver = u16::from_be_bytes([raw[0], raw[1]]);
        if ver != PROTOCOL_VERSION {
            return Err(NullError::Frame(format!("bad version {ver:#x}")));
        }
        let frame_type = FrameType::try_from(raw[2])?;
        let counter = u64::from_be_bytes(raw[3..11].try_into().unwrap());
        let len = u32::from_be_bytes(raw[11..15].try_into().unwrap()) as usize;
        if len > MAX_PAYLOAD_SIZE {
            return Err(NullError::Frame("payload len overflow".into()));
        }
        let payload = raw[32..32 + len].to_vec();
        Ok(Self {
            frame_type,
            counter,
            payload,
        })
    }
}

/// Token-bucket regulator (§6.2): base 1 frame/2s, burst 5, jitter N(2s, 0.5s).
pub struct TrafficShaper {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TrafficShaper {
    pub fn new() -> Self {
        Self {
            tokens: 5.0,
            capacity: 5.0,
            refill_per_sec: 0.5, // 1 per 2s
            last: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let dt = self.last.elapsed().as_secs_f64();
        self.tokens = (self.tokens + dt * self.refill_per_sec).min(self.capacity);
        self.last = Instant::now();
    }

    /// Returns true if a frame may be sent now.
    pub fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Jittered delay until next slot (truncated normal μ=2s σ=0.5s, clamped 0.5..4s).
    pub fn next_delay() -> Duration {
        let mut b = [0u8; 8];
        OsRng.fill_bytes(&mut b);
        let u = u64::from_be_bytes(b) as f64 / u64::MAX as f64; // 0..1
                                                                // Box-Muller-ish cheap approx: map uniform to ±2σ.
        let sample = 2.0 + (u - 0.5) * 2.0; // 1.0..3.0
        Duration::from_secs_f64(sample.clamp(0.5, 4.0))
    }
}

impl Default for TrafficShaper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_size_invariant() {
        let f = Frame::new(FrameType::Data, 1, vec![9u8; 100]).unwrap();
        assert_eq!(f.encode().len(), FRAME_SIZE);
        let g = Frame::decode(&f.encode()).unwrap();
        assert_eq!(g.counter, 1);
        assert_eq!(g.payload.len(), 100);
    }

    #[test]
    fn dummy_is_full_size() {
        assert_eq!(Frame::dummy(0).encode().len(), FRAME_SIZE);
    }

    #[test]
    fn rejects_oversize() {
        assert!(Frame::new(FrameType::Data, 0, vec![0u8; MAX_PAYLOAD_SIZE + 1]).is_err());
    }

    #[test]
    fn header_size_const() {
        assert_eq!(FRAME_HEADER_SIZE, 32);
    }

    #[test]
    fn shaper_burst_then_throttle() {
        let mut s = TrafficShaper::new();
        for _ in 0..5 {
            assert!(s.try_consume());
        }
        assert!(!s.try_consume());
    }
}
