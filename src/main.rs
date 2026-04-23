use std::{
    net::UdpSocket,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use sand::ThreadPool;

fn main() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:1053").unwrap());
    socket.set_nonblocking(true).unwrap();
    let pool = ThreadPool::new(4);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || r.store(false, Ordering::SeqCst)).unwrap();

    let mut buf = [0u8; 65535];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                let data = buf[..n].to_vec();
                let socket = Arc::clone(&socket);
                pool.execute(move || {
                    if let Err(e) = socket.send_to(&data, src) {
                        eprintln!("Send error: {e}");
                    }
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => eprintln!("Receive error: {e}"),
        }
    }

    println!("Shutting down.");
}
