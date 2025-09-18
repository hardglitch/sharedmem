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

    // Create shared memory 1 MB
    let mut request = SharedMem::create_or_open("request", 1 << 20)?;
    let mut response = SharedMem::create_or_open("response", 1 << 20)?;

    request.try_push(b"Hello from writer!")?;
    loop {
        if let Some(data) = response.try_pop() {
            println!("Response: {}", String::from_utf8_lossy(&data));
            break
        }
    }

    Ok(())
}
```

#### The second process
```rust
use sharedmem::SharedMem;

fn main() -> std::io::Result<()> {
    let mut request = SharedMem::create_or_open("request", 1 << 20)?;
    let mut response = SharedMem::create_or_open("response", 1 << 20)?;

    if let Some(data) = request.try_pop() {
        println!("Request: {}", String::from_utf8_lossy(&data));
        response.try_push(&data)?;
    }
    else { println!("Nothing"); }

    Ok(())
}
```
