use sharedmem::{SharedChannel, Portal};
use std::io::Result;

fn main() -> Result<()> {
    // open portal and announce
    let portal = Portal::open()?;

    std::thread::scope(|s| {
        for _ in 0..2 {
            let portal = portal.clone();

            s.spawn(|| {
                let _ = one_thread(portal);
            });
        }
    });

    Ok(())
}

fn one_thread(portal: Portal) -> Result<()> {
    let id = rand::random::<u64>(); // unique id
    let channel = SharedChannel::create(id)?;

    channel.send(b"hello server", portal)?;

    // Server do something

    let resp = channel.recv()?;
    println!("client got: {}", String::from_utf8_lossy(&resp));

    Ok(())
}
