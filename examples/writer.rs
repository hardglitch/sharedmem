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
