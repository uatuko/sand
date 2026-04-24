use std::{
    net::UdpSocket,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use sand::{dns, ThreadPool};

fn main() {
    let zone_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("zone.db"));

    let zone = match dns::zone::Zone::load(&zone_path) {
        Ok(z) => Arc::new(z),
        Err(e) => {
            eprintln!("error loading zone file: {e}");
            return;
        }
    };

    let socket = Arc::new(UdpSocket::bind("127.0.0.1:1053").unwrap());
    socket.set_nonblocking(true).unwrap();
    let pool = ThreadPool::new(thread::available_parallelism().map_or(1, |n| n.get()));

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || r.store(false, Ordering::SeqCst))
        .expect("Error setting termination signal handler");

    println!(
        "Listening on {} (zone: {})",
        socket.local_addr().unwrap(),
        zone_path.display()
    );

    let mut buf = [0u8; 65535];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                let data = buf[..n].to_vec();
                let socket = Arc::clone(&socket);
                let zone = Arc::clone(&zone);
                pool.execute(move || {
                    let response = dns::resolve(&data, &zone);
                    if response.is_empty() {
                        return;
                    }
                    if let Err(e) = socket.send_to(&response, src) {
                        eprintln!("send error to {src}: {e}");
                    }
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => eprintln!("receive error: {e}"),
        }
    }

    println!("Shutting down.");
}
