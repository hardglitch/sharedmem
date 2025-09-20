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
