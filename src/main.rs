use clap::Parser;

use cloudflare_ddns::update_ip;
use tokio::time::{sleep, Duration};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
    #[clap(long)]
    token: String,

    #[clap(long)]
    zone: String,

    #[clap(long)]
    domain: String,

    #[clap(long)]
    ipv6_domain: String,

    #[clap(long)]
    ipserver: Option<String>,

    #[clap(long)]
    ipv6_device: Option<String>,
}

#[tokio::main]
async fn main() {
    // env_logger::init();
    let args = Args::parse();
    env_logger::init();

    loop {
        log::info!("Start Try update ip");
        if let Err(err) = update_ip(
            &args.token,
            &args.zone,
            &args.domain,
            &args.ipv6_domain,
            &args.ipserver,
            &args.ipv6_device,
        )
        .await
        {
            log::error!("{:?}", err);
        }
        sleep(Duration::from_secs(60)).await;
    }
}
