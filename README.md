A cross-platform **lock-free shared memory ring buffer** for inter-process communication (IPC).

- **Only DRAM**: no sockets, no disk files. On Windows it uses `CreateFileMappingW(INVALID_HANDLE_VALUE, ...)`.  
  On Linux/Unix it uses `/dev/shm` (tmpfs).  
- **Request/Response model**: designed for one writer - one reader with length-prefixed messages.  
- **Lock-free**: atomic read/write pointers, no mutexes.  
- **Zero-copy slices**: payloads are written/read directly into memory with wraparound handling.  

### Features
- Cross-platform (Windows, Linux, other Unix).  
- Monotonic counters for safe wraparound.  
- Length-prefixed variable-size messages.  
- Error signaling (`WouldBlock`) when buffer is full.  

### Example
#### The first process
```rust
use sharedmem::SharedMem;

fn main() -> std::io::Result<()> {
    let mut request = SharedMem::create("request", 1 << 20)?; // 1MB
    let mut response = SharedMem::create("response", 1 << 20)?; // 1MB

    request.try_push(b"Hello from Writer!")?;

    loop {
        if let Some(data) = response.try_pop() {
            println!("Response: {}", String::from_utf8_lossy(&data));
            break
        }
    }

    Ok(())
}
```
```
cargo run --example writer
```

#### The second process
```rust
use sharedmem::SharedMem;

fn main() -> std::io::Result<()> {
    let mut request = SharedMem::open_with_retry("request", 1 << 20)?; // 1MB
    let mut response = SharedMem::open_with_retry("response", 1 << 20)?; // 1MB

    if let Some(data) = request.try_pop() {
        println!("Request: {}", String::from_utf8_lossy(&data));
        response.try_push(b"Hello from Reader!")?;
    }
    else { println!("Nothing"); }

    Ok(())
}
```
```
cargo run --example reader
```
