use std::io::{Error, ErrorKind, Result};
use std::slice;
use std::sync::atomic::{AtomicU32, Ordering};

#[cfg(unix)]
mod os {
	use memmap2::MmapOptions;
	use std::fs::OpenOptions;
	use std::io::Result;
	use std::path::PathBuf;

	pub struct MmapMutWrapper {
		pub ptr: *mut u8,
		pub size: usize,
	}

	impl MmapMutWrapper {
		pub fn flush(&self) -> Result<()> { Ok(()) }
	}

	pub fn map_shared(name: &str, size: usize, create: bool) -> Result<MmapMutWrapper> {
		use std::os::unix::fs::OpenOptionsExt;
		let mut path = PathBuf::from("/dev/shm");
		path.push(name);

		if create {
			let f = OpenOptions::new()
				.read(true)
				.write(true)
				.create(true)
				.mode(0o600) // rw for owner only
				.open(&path)?;
			f.set_len(size as u64)?;
			// optional: remove the file, mapping stays valid
			// std::fs::remove_file(&path)?;
			let mm = unsafe { MmapOptions::new().len(size).map_mut(&f)? };
			Ok(mm.into())
		} else {
			let f = OpenOptions::new().read(true).write(true).open(&path)?;
			let mm = unsafe { MmapOptions::new().map_mut(&f)? };
			Ok(mm.into())
		}
	}
}

#[cfg(windows)]
mod os {
	use std::ffi::OsStr;
	use std::io::{Error, Result};
	use std::os::windows::prelude::*;
	use std::ptr;
	use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
	use windows_sys::Win32::System::Memory::{
		CreateFileMappingW, MapViewOfFile, OpenFileMappingW, FILE_MAP_ALL_ACCESS, PAGE_READWRITE,
	};

	pub struct MmapMutWrapper {
		pub ptr: *mut u8,
		pub size: usize,
	}

	impl MmapMutWrapper {
		pub fn flush(&self) -> Result<()> { Ok(()) } // Windows: optionally use FlushViewOfFile
	}

	pub fn map_shared(name: &str, size: usize, create: bool) -> Result<MmapMutWrapper> {
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
			Ok(MmapMutWrapper { ptr: addr.Value as usize as *mut u8, size })
		}
	}
}

#[repr(C)]
struct Header {
	write_pos: AtomicU32,
	read_pos: AtomicU32,
	cap: u32,
	_reserved: u32,
}
const HEADER_SIZE: usize = size_of::<Header>();

pub struct SharedMem {
	mm: os::MmapMutWrapper,
	header_ptr: *mut Header,
	data_ptr: *mut u8,
	cap: usize,
}

impl SharedMem {
	pub fn create_or_open(name: &str, size: usize) -> Result<Self> {
		match Self::create(name, size) {
			Ok(r) => Ok(r),
			Err(_) => Self::open(name, size),
		}
	}

	pub fn open_with_retry(name: &str, size: usize) -> Result<Self> {
		loop {
			match Self::open(name, size) {
				Ok(r) => return Ok(r),
				Err(_) => {
					std::thread::sleep(std::time::Duration::from_millis(50));
				}
			}
		}
	}


	fn create(name: &str, size: usize) -> Result<Self> {
		let mm = os::map_shared(name, size, true)?;
		Self::from_mmap(mm)
	}

	fn open(name: &str, size: usize) -> Result<Self> {
		let mm = os::map_shared(name, size, false)?;
		Self::from_mmap(mm)
	}

	fn from_mmap(mm: os::MmapMutWrapper) -> Result<Self> {
		let ptr = mm.ptr;
		let header_ptr = ptr as *mut Header;
		unsafe {
			let header = &mut *header_ptr;
			let cap = (mm.size - HEADER_SIZE) as u32;
			if header.cap == 0 {
				header.write_pos = AtomicU32::new(0);
				header.read_pos = AtomicU32::new(0);
				header.cap = cap;
				header._reserved = 0;
			}
			let mm_size = mm.size;
			Ok(Self { mm, header_ptr, data_ptr: ptr.add(HEADER_SIZE), cap: mm_size - HEADER_SIZE })
		}
	}

	fn data_slice_mut(&mut self) -> &mut [u8] {
		unsafe { slice::from_raw_parts_mut(self.data_ptr, self.cap) }
	}

	pub fn try_push(&mut self, payload: &[u8]) -> Result<()> {
		let hdr = unsafe { &*self.header_ptr };
		let w = hdr.write_pos.load(Ordering::Acquire);
		let r = hdr.read_pos.load(Ordering::Acquire);

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
		let mut write_bytes = Vec::with_capacity(4 + payload.len());
		write_bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
		write_bytes.extend_from_slice(payload);

		let first = std::cmp::min(cap as usize - start, write_bytes.len()) as usize;
		data[start..start + first].copy_from_slice(&write_bytes[..first]);
		if first < write_bytes.len() {
			let rest = write_bytes.len() - first;
			data[..rest].copy_from_slice(&write_bytes[first..]);
		}

		hdr.write_pos.store(w + need, Ordering::Release);

		self.mm.flush()?;
		Ok(())
	}

	pub fn try_pop(&mut self) -> Option<Vec<u8>> {
		let hdr = unsafe { &*self.header_ptr };
		let w = hdr.write_pos.load(Ordering::Acquire);
		let mut r = hdr.read_pos.load(Ordering::Acquire);
		if r == w { return None; }

		let cap = self.cap as u32;
		let cap_usize = self.cap;
		let data = self.data_slice_mut();
		let start = (r % cap) as usize;

		// read 4-byte len safely (may wrap)
		let mut len_bytes = [0u8;4];
		for i in 0..4 {
			len_bytes[i] = data[(start + i) % cap_usize];
		}
		let len = u32::from_le_bytes(len_bytes) as usize;

		// ensure message fully available
		let available = w.wrapping_sub(r);
		if available < 4 + len as u32 { return None; }

		// read payload with two-slice copy
		let payload_start = (start + 4) % cap_usize;
		let mut buf = vec![0u8; len];
		let first = std::cmp::min(cap_usize - payload_start, len);
		buf[..first].copy_from_slice(&data[payload_start..payload_start + first]);
		if first < len {
			buf[first..].copy_from_slice(&data[..(len - first)]);
		}

		r = r + 4 + len as u32;
		hdr.read_pos.store(r, Ordering::Release);

		Some(buf)
	}

	pub fn push_blocking(&mut self, payload: &[u8]) {
		loop {
			if self.try_push(payload).is_ok() { return; }
			std::hint::spin_loop();
			std::thread::yield_now();
		}
	}

	pub fn pop_blocking(&mut self) -> Vec<u8> {
		loop {
			if let Some(m) = self.try_pop() { return m; }
			std::hint::spin_loop();
			std::thread::yield_now();
		}
	}
}
