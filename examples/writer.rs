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
