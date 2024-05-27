use clap::Parser;

use cloudflare_ddns::update_ip;
use tokio::time::{sleep, Duration};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
    /// Name of the person to greet
    #[clap(long)]
    token: String,

    /// Number of times to greet
    #[clap(long)]
    zone: String,

    #[clap(long)]
    domain: String,

    #[clap(long)]
    ipserver: String,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();

    loop {
        log::info!("Start Try update ip");
        if let Err(err) = update_ip(&args.token, &args.zone, &args.domain, &args.ipserver).await {
            log::error!("{:?}", err);
        }
        sleep(Duration::from_secs(60)).await;
    }
}
