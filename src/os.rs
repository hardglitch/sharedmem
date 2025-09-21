#[cfg(unix)]
#[allow(clippy::module_inception)]
pub(crate) mod os {
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
#[allow(clippy::module_inception)]
pub(crate) mod os {
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
