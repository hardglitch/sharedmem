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
