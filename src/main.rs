use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::{Duration, Instant},
};

use quic_probe::ProbeBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let probe = ProbeBuilder::default()
        .max_idle_timeout(Duration::from_secs_f32(0.001))?
        .initial_rtt(Duration::from_secs_f32(0.001))
        .build()?;

    loop {
        let start = Instant::now();
        let result = probe
            .probe(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9000)),
                "localhost",
            )
            .await;
        eprintln!("{:?} {:?}", start.elapsed(), result);
        if result? {
            break;
        }
    }

    Ok(())
}
