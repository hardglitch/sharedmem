use std::cell::UnsafeCell;
use std::io::{Error, ErrorKind};
use std::slice;
use std::sync::atomic::{AtomicU32, Ordering};
use crate::os;

#[repr(C)]
struct Header {
    write_pos: AtomicU32,
    read_pos: AtomicU32,
    cap: u32,
    _pad: [u8; 64 - 4*4], // pad to 64 bytes

    #[cfg(unix)]
    notify: AtomicU32, // futex word (0=idle, 1=signaled)
}
const HEADER_SIZE: usize = size_of::<Header>();

#[allow(dead_code)]
pub struct SharedMem {
    mm: UnsafeCell<os::os::MmapMutWrapper>,
    header_ptr: *mut Header,
    data_ptr: *mut u8,
    cap: usize,
}

impl SharedMem {
    pub fn create(name: &str, size: usize) -> std::io::Result<Self> {
        let mm = os::os::map_shared(name, size, true)?;
        Self::from_mmap(mm)
    }

    pub fn open(name: &str, size: usize) -> std::io::Result<Self> {
        let mm = os::os::map_shared(name, size, false)?;
        Self::from_mmap(mm)
    }

    pub fn open_with_retry(name: &str, size: usize) -> std::io::Result<Self> {
        loop {
            match Self::open(name, size) {
                Ok(r) => return Ok(r),
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    }

    fn from_mmap(mm: os::os::MmapMutWrapper) -> std::io::Result<Self> {
        if mm.inner.size <= HEADER_SIZE + 8 {
            return Err(Error::new(ErrorKind::InvalidInput, "Too small"));
        }

        let ptr = mm.inner.ptr;
        let header_ptr = ptr as *mut Header;
        unsafe {
            let header = &mut *header_ptr;
            let cap = mm.inner.size - HEADER_SIZE;

            if header.cap == 0 {
                header.write_pos.store(0, Ordering::Release);
                header.read_pos.store(0, Ordering::Release);
                header.cap = cap as u32;
                #[cfg(unix)] header.notify.store(0, Ordering::Release);
            }

            Ok(Self {
                mm: UnsafeCell::new(mm),
                header_ptr,
                data_ptr: ptr.add(HEADER_SIZE),
                cap,
            })
        }
    }

    #[allow(clippy::mut_from_ref)]
    fn data_slice_mut(&self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.data_ptr, self.cap) }
    }

    pub fn try_push(&self, payload: &[u8]) -> std::io::Result<()> {
        let header = unsafe { &*self.header_ptr };
        let w = header.write_pos.load(Ordering::Acquire);
        let r = header.read_pos.load(Ordering::Acquire);

        let cap = self.cap as u32;
        let need = 4u32 + payload.len() as u32;
        let used = w.wrapping_sub(r);
        let free = cap.wrapping_sub(used);
        if need > free-1 { // keep one slot free
            return Err(Error::new(ErrorKind::WouldBlock, "Ring buffer full"));
        }
        let start = (w % cap) as usize;
        let data = self.data_slice_mut();

        // write len (4 bytes) then payload using two-slice copy
        let mut write_bytes = Vec::with_capacity(need as usize);
        write_bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        write_bytes.extend_from_slice(payload);

        let first = std::cmp::min(cap as usize - start, write_bytes.len());
        data[start..start + first].copy_from_slice(&write_bytes[..first]);
        if first < write_bytes.len() {
            let rest = write_bytes.len() - first;
            data[..rest].copy_from_slice(&write_bytes[first..]);
        }

        header.write_pos.store(w + need, Ordering::Release);

        #[cfg(unix)]
        {
            // signal reader via futex stored at header.notify
            header.notify.store(1, Ordering::Release);

            let futex_addr = &header.notify as *const AtomicU32 as *mut i32;
            let _ = os::os::futex::futex_wake(futex_addr, 1);

            // flush to backing store so other processes mapped to same file see it
            unsafe {
                (&(*self.mm.get()).inner).mmap.flush()?
            }
        }

        Ok(())
    }

    pub fn try_pop(&self) -> Option<Vec<u8>> {
        let header = unsafe { &*self.header_ptr };
        let w = header.write_pos.load(Ordering::Acquire);
        let mut r = header.read_pos.load(Ordering::Acquire);
        if r == w { return None; }

        let cap = self.cap;
        let data = self.data_slice_mut();
        let start = r as usize % cap;

        // read 4-byte len safely (may wrap)
        let mut len_bytes = [0u8; 4];
        for i in 0..4 {
            len_bytes[i] = data[(start + i) % cap];
        }
        let len = u32::from_le_bytes(len_bytes) as usize;

        // ensure message fully available
        let available = w.wrapping_sub(r);
        if available < 4 + len as u32 { return None; }

        // read payload with two-slice copy
        let payload_start = (start + 4) % cap;
        let mut buf = vec![0u8; len];
        let first = std::cmp::min(cap - payload_start, len);
        buf[..first].copy_from_slice(&data[payload_start..payload_start + first]);
        if first < len {
            buf[first..].copy_from_slice(&data[..(len - first)]);
        }

        r = r + 4 + len as u32;
        header.read_pos.store(r, Ordering::Release);

        // clear data
        data.iter_mut().for_each(|b| { *b = 0; });

        Some(buf)
    }

    #[cfg(unix)]
    pub fn wait_pop_blocking(&self) -> Vec<u8> {
        loop {
            if let Some(m) = self.try_pop() { return m; }

            // futex wait on notify word = 0
            let header = unsafe { &*self.header_ptr };
            let futex_addr = &header.notify as *const AtomicU32 as *mut i32;
            // set notify to 0 then wait if still 0
            header.notify.store(0, Ordering::Release);
            let _ = os::os::futex::futex_wait(futex_addr, 0);
        }
    }

    pub fn push_blocking(&self, payload: &[u8]) {
        loop {
            if self.try_push(payload).is_ok() { return; }
            std::hint::spin_loop();
            std::thread::yield_now();
        }
    }

    pub fn pop_blocking(&self) -> Vec<u8> {
        loop {
            if let Some(m) = self.try_pop() { return m; }
            std::hint::spin_loop();
            std::thread::yield_now();
        }
    }
}
unsafe impl Send for SharedMem {}
unsafe impl Sync for SharedMem {}
#[cfg(windows)]
impl Drop for SharedMem {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Memory::UnmapViewOfFile;

        unsafe {
            let mm = (*self.mm.get()).inner.clone();

            if !mm.ptr.is_null() {
                let addr = MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: mm.ptr as *mut std::ffi::c_void
                };
                UnmapViewOfFile(addr);
            }
            if !mm.hmap.is_null() {
                CloseHandle(mm.hmap);
            }

            std::ptr::drop_in_place(self.mm.get())
        };
    }
}
#[cfg(unix)]
impl Drop for SharedMem {
    fn drop(&mut self) {
        unsafe {
            let mm = (*self.mm.get()).inner.clone();

            if !mm.ptr.is_null() {
                let _ = mm.mmap.flush();
                libc::munmap(mm.ptr as *mut libc::c_void, mm.size);
            }
        }
    }
}

