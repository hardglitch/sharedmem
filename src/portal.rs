use std::sync::Arc;
use crate::core::SharedMem;

const PORTAL_NAME: &str = "portal_shm";
const PORTAL_SIZE: usize = 4096;

#[derive(Clone)]
pub struct Portal {
    ring: Arc<SharedMem>,
}
impl Portal {
    pub fn create() -> std::io::Result<Self> {
        let ring = SharedMem::create(PORTAL_NAME, PORTAL_SIZE)?;
        Ok(Self { ring: Arc::new(ring) })
    }
    pub fn open() -> std::io::Result<Self> {
        let ring = SharedMem::open(PORTAL_NAME, PORTAL_SIZE)?;
        Ok(Self { ring: Arc::new(ring) })
    }
    pub fn announce(&self, id: u64) -> std::io::Result<()> {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&id.to_le_bytes());
        self.ring.try_push(&buf)
    }
    pub fn listen(&self) -> u64 {
        loop {
            if let Some(v) = self.ring.try_pop() && v.len() == 8 {
                return Self::value(&v)
            }
            else {
                #[cfg(unix)] let dummy = self.ring.wait_pop_blocking();
                #[cfg(windows)] let dummy = self.ring.pop_blocking();

                if dummy.len() == 8 {
                    return Self::value(&dummy)
                }
            }
        }
    }
    fn value(v: &[u8]) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&v[..8]);
        u64::from_le_bytes(b)
    }
}
