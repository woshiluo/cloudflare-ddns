//
// lib.rs
// Copyright (C) 2022 Woshiluo Luo <woshiluo.luo@outlook.com>
// Distributed under terms of the GNU AGPLv3+ license.
//
use cloudflare::endpoints::{dns::dns, zones::zone};
use cloudflare::framework::client::async_api::Client;
use cloudflare::framework::{client::ClientConfig, Environment};
use serde::Deserialize;
use std::str::FromStr;
use tokio::time::sleep;

#[derive(Deserialize)]
struct GetIP {
    pub ip: String,
}

#[derive(Debug)]
struct DNSRecord {
    pub ip: String,
    pub valid: std::time::Instant,
}

impl DNSRecord {
    fn empty() -> Self {
        DNSRecord {
            ip: "".to_string(),
            valid: std::time::Instant::now(),
        }
    }
}

#[derive(Debug)]
pub enum DdnsError {
    Message(String),
    FailedGetIp(String),
    FailedGetIpv6(String),
    FailedLookUp(String),
    FailedApiRequest(String),
}

fn get_ipv6(device_name: &str) -> Result<String, DdnsError> {
    use local_ip_address::list_afinet_netifas;
    use std::net::IpAddr;
    let ifas = list_afinet_netifas().unwrap();

    if let Some((_, ipaddr)) = ifas
        .iter()
        .find(|(name, ipaddr)| *name == device_name && matches!(ipaddr, IpAddr::V6(_)))
    {
        return Ok(ipaddr.to_string());
    };

    Err(DdnsError::FailedGetIpv6("Not Found".to_string()))
}

async fn get_ip(ipserver: &str) -> Result<String, DdnsError> {
    let body = reqwest::get(ipserver)
        .await
        .map_err(|err| DdnsError::FailedGetIp(err.to_string()))?
        .text()
        .await
        .map_err(|err| DdnsError::FailedGetIp(err.to_string()))?;
    let ip: GetIP = serde_json::from_str(&body)
        .map_err(|err| DdnsError::FailedGetIp(format!("Failed to deserialize {}", err)))?;
    Ok(ip.ip)
}

async fn look_up(domain: &str) -> Result<DNSRecord, DdnsError> {
    use trust_dns_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .map_err(|err| DdnsError::FailedLookUp(err.to_string()))?;
    let response = resolver
        .ipv4_lookup(domain)
        .await
        .map_err(|err| DdnsError::FailedLookUp(err.to_string()))?;
    let address = response
        .iter()
        .next()
        .ok_or(DdnsError::FailedLookUp("No domain".to_string()))?;

    Ok(DNSRecord {
        ip: address.to_string(),
        valid: response.valid_until(),
    })
}

async fn look_upv6(domain: &str) -> Result<DNSRecord, DdnsError> {
    use trust_dns_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .map_err(|err| DdnsError::FailedLookUp(err.to_string()))?;
    let response = resolver
        .ipv6_lookup(domain)
        .await
        .map_err(|err| DdnsError::FailedLookUp(err.to_string()))?;
    let address = response
        .iter()
        .next()
        .ok_or(DdnsError::FailedLookUp("No domain".to_string()))?;

    Ok(DNSRecord {
        ip: address.to_string(),
        valid: response.valid_until(),
    })
}

fn get_client(token: String) -> Result<Client, DdnsError> {
    let credentials = cloudflare::framework::auth::Credentials::UserAuthToken { token };
    let api_client = Client::new(
        credentials,
        ClientConfig::default(),
        Environment::Production,
    )
    .map_err(|err| DdnsError::FailedApiRequest(err.to_string()))?;
    Ok(api_client)
}

async fn get_zone_id(client: &Client, zone: &str) -> Result<String, DdnsError> {
    let zones = client
        .request(&zone::ListZones {
            params: zone::ListZonesParams {
                name: Some(zone.to_string()),
                status: None,
                page: None,
                per_page: None,
                order: None,
                direction: None,
                search_match: None,
            },
        })
        .await
        .map_err(|err| DdnsError::FailedApiRequest(err.to_string()))?
        .result;
    let zone_id = &zones
        .first()
        .ok_or(DdnsError::FailedApiRequest("Zone not foound".to_string()))?
        .id;
    Ok(zone_id.clone())
}

async fn get_dns_id_a(client: &Client, zone_id: &str, domain: &str) -> Result<String, DdnsError> {
    let dns = client
        .request(&dns::ListDnsRecords {
            zone_identifier: zone_id,
            params: dns::ListDnsRecordsParams {
                record_type: None,
                name: Some(domain.to_string()),
                page: None,
                per_page: None,
                order: None,
                direction: None,
                search_match: None,
            },
        })
        .await
        .map_err(|err| DdnsError::FailedApiRequest(err.to_string()))?
        .result;
    let dns_id = &dns
        .iter()
        .find(|item| matches!(item.content, dns::DnsContent::A { content: _ }))
        .ok_or(DdnsError::FailedApiRequest(
            "DnsRecord not found".to_string(),
        ))?
        .id;
    Ok(dns_id.clone())
}

async fn get_dns_id_aaaa(
    client: &Client,
    zone_id: &str,
    domain: &str,
) -> Result<String, DdnsError> {
    let dns = client
        .request(&dns::ListDnsRecords {
            zone_identifier: zone_id,
            params: dns::ListDnsRecordsParams {
                record_type: None,
                name: Some(domain.to_string()),
                page: None,
                per_page: None,
                order: None,
                direction: None,
                search_match: None,
            },
        })
        .await
        .map_err(|err| DdnsError::FailedApiRequest(err.to_string()))?
        .result;
    let dns_id = &dns
        .iter()
        .find(|item| matches!(item.content, dns::DnsContent::AAAA { content: _ }))
        .ok_or(DdnsError::FailedApiRequest(
            "DnsRecord not found".to_string(),
        ))?
        .id;
    Ok(dns_id.clone())
}

pub async fn update_ip(
    token: &str,
    zone: &str,
    ipv4_domain: &str,
    ipv6_domain: &str,
    ipserver: &Option<String>,
    ipv6_device: &Option<String>,
) -> Result<(), DdnsError> {
    let enable_ipv6 = ipv6_device.is_some();
    let enable_ipv4 = ipserver.is_some();

    let ipv4_valid = if enable_ipv4 {
        let domain = ipv4_domain;
        let public_ip = get_ip(ipserver.clone().unwrap().as_str()).await?;
        let current_ip = look_up(domain).await?;

        log::info!(
            "{}'s ip is {}, currently public ip is {}",
            domain,
            current_ip.ip,
            public_ip,
        );
        if public_ip != current_ip.ip {
            log::info!("Update {}'s ip to {}", domain, public_ip);

            let client = get_client(token.to_string().to_string())?;
            log::info!("Client get");
            let zone_id = get_zone_id(&client, zone).await?;
            log::info!("Zone get");
            let dns_id = get_dns_id_a(&client, &zone_id, domain).await?;
            log::info!("Dns get");

            log::debug!("zone identifier: {}, dns identifier: {}", zone_id, dns_id);

            // TODO: create record
            client
                .request(&dns::UpdateDnsRecord {
                    zone_identifier: &zone_id,
                    identifier: &dns_id,
                    params: dns::UpdateDnsRecordParams {
                        ttl: Some(60),
                        proxied: None,
                        name: domain,
                        content: dns::DnsContent::A {
                            content: std::net::Ipv4Addr::from_str(&public_ip)
                                .map_err(|err| DdnsError::Message(err.to_string()))?,
                        },
                    },
                })
                .await
                .map_err(|err| DdnsError::FailedApiRequest(err.to_string()))?;
        }
        current_ip.valid
    } else {
        std::time::Instant::now() + std::time::Duration::from_secs(180)
    };

    if enable_ipv6 {
        let domain = ipv6_domain;
        let public_ipv6 = match ipv6_device {
            Some(name) => get_ipv6(name.as_str())?,
            None => "".to_string(),
        };

        let current_ipv6 = match look_upv6(domain).await {
            Ok(ip) => ip,
            Err(err) => {
                log::warn!("Failed get current ipv6 {:?}", err);
                DNSRecord::empty()
            }
        };

        log::info!(
            "{}'s ipv6 is {}, currently public ip is {}",
            domain,
            &current_ipv6.ip,
            public_ipv6,
        );
        if public_ipv6 != current_ipv6.ip {
            log::info!("Update {}'s ipv6 to {}", domain, public_ipv6);

            let client = get_client(token.to_string().to_string())?;
            log::info!("Client get");
            let zone_id = get_zone_id(&client, zone).await?;
            log::info!("Zone get");
            let dns_id = get_dns_id_aaaa(&client, &zone_id, domain).await?;
            log::info!("Dns get");

            log::debug!("zone identifier: {}, dns identifier: {}", zone_id, dns_id);

            // TODO: create record
            client
                .request(&dns::UpdateDnsRecord {
                    zone_identifier: &zone_id,
                    identifier: &dns_id,
                    params: dns::UpdateDnsRecordParams {
                        ttl: Some(60),
                        proxied: None,
                        name: domain,
                        content: dns::DnsContent::AAAA {
                            content: std::net::Ipv6Addr::from_str(&public_ipv6)
                                .map_err(|err| DdnsError::Message(err.to_string()))?,
                        },
                    },
                })
                .await
                .map_err(|err| DdnsError::FailedApiRequest(err.to_string()))?;
        }
    }

    // TODO: check_max ipv6_valid
    log::info!("Waiting for {:?}", ipv4_valid - std::time::Instant::now());
    while ipv4_valid > std::time::Instant::now() {
        sleep(ipv4_valid - std::time::Instant::now()).await;
    }

    Ok(())
}
