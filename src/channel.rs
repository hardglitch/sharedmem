use crate::core::SharedMem;
use crate::portal::Portal;

pub struct SharedChannel {
    id: u64,
    req: SharedMem,
    resp: SharedMem,
    is_creator: bool,
}
impl SharedChannel {
    pub fn create(id: u64) -> std::io::Result<Self> {
        let req_name = format!("req_{}", id);
        let resp_name = format!("resp_{}", id);
        let req = SharedMem::create(&req_name, 1 << 16)?;   // 64KiB
        let resp = SharedMem::create(&resp_name, 1 << 16)?; // 64KiB
        Ok(Self { id, req, resp, is_creator: true })
    }
    pub fn open(id: u64) -> std::io::Result<Self> {
        let req_name = format!("req_{}", id);
        let resp_name = format!("resp_{}", id);
        let req = SharedMem::open(&req_name, 1 << 16)?;   // 64KiB
        let resp = SharedMem::open(&resp_name, 1 << 16)?; // 64KiB
        Ok(Self { id, req, resp, is_creator: false })
    }

    pub fn send(&self, msg: &[u8], portal: Portal) -> std::io::Result<()> {
        if self.is_creator {
            self.req.try_push(msg)?;
        } else {
            self.resp.try_push(msg)?;
        }
        portal.announce(self.id)?;
        Ok(())
    }

    pub fn recv(&self) -> std::io::Result<Vec<u8>> {
        let r =
            if self.is_creator {
                #[cfg(unix)] { self.resp.wait_pop_blocking() }
                #[cfg(windows)] { self.resp.pop_blocking() }
            } else {
                #[cfg(unix)] { self.req.wait_pop_blocking() }
                #[cfg(windows)] { self.req.pop_blocking() }
            };
        Ok(r)
    }
}
