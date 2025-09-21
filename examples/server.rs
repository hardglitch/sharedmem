use sharedmem::Portal;
use sharedmem::SharedChannel;
use std::io::Result;

fn main() -> Result<()> {
    let portal = Portal::create()?;
    println!("Server started");

    loop {
        let id = portal.listen();
        dbg!(&id);
        let channel = SharedChannel::open(id)?;

        let req = channel.recv()?;
        eprintln!("Server: got from {}: {}", id, String::from_utf8_lossy(&req));

        // Do something

        let resp = b"Hello, client";
        channel.send(resp, portal.clone())?;
    }
}
