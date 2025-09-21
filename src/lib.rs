use std::cell::UnsafeCell;
use std::io::{Error, ErrorKind, Result};
use std::slice;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

#[cfg(unix)]
mod os {
	use memmap2::{MmapMut, MmapOptions};
	use std::fs::OpenOptions;
	use std::io::{Error, ErrorKind, Result};
	use std::os::unix::fs::OpenOptionsExt;
	use std::path::PathBuf;
	use std::sync::Arc;

	const ALIGNED_HEADER_SIZE: usize = 64;


	pub(crate) struct MmapMutInner {
		pub(crate) ptr: *mut u8,
		pub(crate) size: usize,
		pub(crate) mmap: MmapMut,
	}
	unsafe impl Send for MmapMutInner {}
	unsafe impl Sync for MmapMutInner {}

	pub(crate) struct MmapMutWrapper {
		pub(crate) inner: Arc<MmapMutInner>
	}


	pub(crate) fn map_shared(name: &str, size: usize, create: bool) -> Result<MmapMutWrapper> {
		let mut path = PathBuf::from("/dev/shm");
		path.push(name);

		let mmap =
			if create {
				let _ = std::fs::remove_file(&path); // fresh start

				let f = OpenOptions::new()
					.read(true)
					.write(true)
					.create(true)
					.truncate(true)
					.mode(0o600) // rw for owner only
					.open(&path)?;

				f.set_len(size as u64)?;

				let mut mm = unsafe { MmapOptions::new().map_mut(&f)? };
				// zero header area so header.cap==0 is deterministic
				mm[..ALIGNED_HEADER_SIZE].iter_mut().for_each(|b| { *b = 0; });
				mm
			}
			else {
				let f = OpenOptions::new()
					.read(true)
					.write(true)
					.open(&path)?;

				let meta = f.metadata()?;
				if meta.len() < size as u64 {
					return Err(Error::new(
						ErrorKind::Other,
						format!("Shared file too small: {} bytes", meta.len()),
					));
				}
				unsafe { MmapOptions::new().map_mut(&f)? }
			};

		let ptr = mmap.as_ptr() as *mut u8;
		let size = mmap.len();

		let inner = MmapMutInner {
			ptr,
			size,
			mmap,
		};
		let wrapper = MmapMutWrapper {
			inner: Arc::new(inner)
		};

		Ok(wrapper)
	}


	// ---------- Futex helpers ----------
	pub(crate) mod futex {
		use libc::{syscall, SYS_futex, FUTEX_WAIT, FUTEX_WAKE};
		use std::io::{Error, Result};
		use std::ptr;

		pub(crate) fn futex_wait(addr: *mut i32, val: i32) -> Result<()> {
			unsafe {
				let r = syscall(SYS_futex, addr, FUTEX_WAIT, val, ptr::null::<libc::timespec>());
				if r == -1 {
					let err = Error::last_os_error();
					// EINTR or EAGAIN are possible; treat as okay to return Err
					return Err(err);
				}
				Ok(())
			}
		}
		pub(crate) fn futex_wake(addr: *mut i32, n: i32) -> Result<i32> {
			unsafe {
				let r = syscall(SYS_futex, addr, FUTEX_WAKE, n);
				if r == -1 { return Err(Error::last_os_error()); }
				Ok(r as i32)
			}
		}
	}
}

#[cfg(windows)]
mod os {
	use std::ffi::OsStr;
	use std::io::{Error, Result};
	use std::os::windows::prelude::*;
	use std::ptr;
	use std::sync::Arc;
	use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
	use windows_sys::Win32::System::Memory::{CreateFileMappingW, MapViewOfFile, OpenFileMappingW, FILE_MAP_ALL_ACCESS, PAGE_READWRITE};


	pub(crate) struct MmapMutInner {
		pub(crate) ptr: *mut u8,
		pub(crate) size: usize,
		pub(crate) hmap: HANDLE,
	}
	unsafe impl Send for MmapMutInner {}
	unsafe impl Sync for MmapMutInner {}

	pub(crate) struct MmapMutWrapper {
		pub(crate) inner: Arc<MmapMutInner>
	}
	// impl MmapMutWrapper {
	// 	pub fn flush(&self) -> Result<()> {
	// 		// optionally use FlushViewOfFile
	// 		Ok(())
	// 	}
	// }

	pub(crate) fn map_shared(name: &str, size: usize, create: bool) -> Result<MmapMutWrapper> {
		let wide: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();
		unsafe {
			let hmap = if create {
				CreateFileMappingW(
					INVALID_HANDLE_VALUE,
					ptr::null(),
					PAGE_READWRITE,
					(size >> 32) as u32,
					size as u32,
					wide.as_ptr(),
				)
			} else {
				OpenFileMappingW(FILE_MAP_ALL_ACCESS, 0, wide.as_ptr())
			};
			if hmap.is_null() { return Err(Error::last_os_error()); }

			let addr = MapViewOfFile(hmap, FILE_MAP_ALL_ACCESS, 0, 0, size);
			if addr.Value.is_null() {
				CloseHandle(hmap);
				return Err(Error::last_os_error());
			}

			let inner = MmapMutInner {
				ptr: addr.Value as *mut u8,
				size,
				hmap,
			};
			let wrapper = MmapMutWrapper {
				inner: Arc::new(inner)
			};

			Ok(wrapper)
		}
	}
}

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
	mm: UnsafeCell<os::MmapMutWrapper>,
	header_ptr: *mut Header,
	data_ptr: *mut u8,
	cap: usize,
}

impl SharedMem {
	pub fn create(name: &str, size: usize) -> Result<Self> {
		let mm = os::map_shared(name, size, true)?;
		Self::from_mmap(mm)
	}

	pub fn open(name: &str, size: usize) -> Result<Self> {
		let mm = os::map_shared(name, size, false)?;
		Self::from_mmap(mm)
	}

	pub fn open_with_retry(name: &str, size: usize) -> Result<Self> {
		loop {
			match Self::open(name, size) {
				Ok(r) => return Ok(r),
				Err(_) => {
					std::thread::sleep(std::time::Duration::from_millis(10));
				}
			}
		}
	}

	fn from_mmap(mm: os::MmapMutWrapper) -> Result<Self> {
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

	pub fn try_push(&self, payload: &[u8]) -> Result<()> {
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
			let _ = os::futex::futex_wake(futex_addr, 1);

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
			let _ = os::futex::futex_wait(futex_addr, 0);
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


const PORTAL_NAME: &str = "portal_shm";
const PORTAL_SIZE: usize = 4096;

#[derive(Clone)]
pub struct Portal {
	ring: Arc<SharedMem>,
}
impl Portal {
	pub fn create() -> Result<Self> {
		let ring = SharedMem::create(PORTAL_NAME, PORTAL_SIZE)?;
		Ok(Self { ring: Arc::new(ring) })
	}
	pub fn open() -> Result<Self> {
		let ring = SharedMem::open(PORTAL_NAME, PORTAL_SIZE)?;
		Ok(Self { ring: Arc::new(ring) })
	}
	pub fn announce(&self, id: u64) -> Result<()> {
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



pub struct SharedChannel {
	id: u64,
	req: SharedMem,
	resp: SharedMem,
	is_creator: bool,
}
impl SharedChannel {
	pub fn create(id: u64) -> Result<Self> {
		let req_name = format!("req_{}", id);
		let resp_name = format!("resp_{}", id);
		let req = SharedMem::create(&req_name, 1 << 16)?;   // 64KiB
		let resp = SharedMem::create(&resp_name, 1 << 16)?; // 64KiB
		Ok(Self { id, req, resp, is_creator: true })
	}
	pub fn open(id: u64) -> Result<Self> {
		let req_name = format!("req_{}", id);
		let resp_name = format!("resp_{}", id);
		let req = SharedMem::open(&req_name, 1 << 16)?;   // 64KiB
		let resp = SharedMem::open(&resp_name, 1 << 16)?; // 64KiB
		Ok(Self { id, req, resp, is_creator: false })
	}

	pub fn send(&self, msg: &[u8], portal: Portal) -> Result<()> {
		if self.is_creator {
			self.req.try_push(msg)?;
		} else {
			self.resp.try_push(msg)?;
		}
		portal.announce(self.id)?;
		Ok(())
	}

	pub fn recv(&self) -> Result<Vec<u8>> {
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
