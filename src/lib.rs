//
// lib.rs
// Copyright (C) 2022 Woshiluo Luo <woshiluo.luo@outlook.com>
// Distributed under terms of the GNU AGPLv3+ license.
//
use cloudflare::endpoints::{dns, zone};
use cloudflare::framework::apiclient::ApiClient;
use cloudflare::framework::{Environment, HttpApiClient, HttpApiClientConfig};
use serde::Deserialize;
use std::str::FromStr;

#[derive(Deserialize)]
struct GetIP {
    pub ip: String,
}

#[derive(Debug)]
struct DNSRecord {
    pub ip: String,
    pub valid: std::time::Instant,
}

#[derive(Debug)]
pub enum DdnsError {
    Message(String),
    FailedGetIp(String),
    FailedLookUp(String),
    FailedApiRequest(String),
}

fn get_ip(ipserver: &str) -> Result<String, DdnsError> {
    let body = reqwest::blocking::get(ipserver)
        .map_err(|err| DdnsError::FailedGetIp(err.to_string()))?
        .text()
        .map_err(|err| DdnsError::FailedGetIp(err.to_string()))?;
    let ip: GetIP = serde_json::from_str(&body)
        .map_err(|err| DdnsError::FailedGetIp(format!("Failed to deserialize {}", err)))?;
    Ok(ip.ip)
}

fn look_up(domain: &str) -> Result<DNSRecord, DdnsError> {
    use trust_dns_resolver::Resolver;

    let resolver =
        Resolver::from_system_conf().map_err(|err| DdnsError::FailedLookUp(err.to_string()))?;
    let response = resolver
        .lookup_ip(domain)
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

fn get_client(token: String) -> Result<HttpApiClient, DdnsError> {
    let credentials = cloudflare::framework::auth::Credentials::UserAuthToken { token };
    let api_client = HttpApiClient::new(
        credentials,
        HttpApiClientConfig::default(),
        Environment::Production,
    )
    .map_err(|err| DdnsError::FailedApiRequest(err.to_string()))?;
    Ok(api_client)
}

fn get_zone_id(client: &HttpApiClient, zone: &str) -> Result<String, DdnsError> {
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
        .map_err(|err| DdnsError::FailedApiRequest(err.to_string()))?
        .result;
    let zone_id = &zones
        .first()
        .ok_or(DdnsError::FailedApiRequest("Zone not foound".to_string()))?
        .id;
    Ok(zone_id.clone())
}

fn get_dns_id(client: &HttpApiClient, zone_id: &str, domain: &str) -> Result<String, DdnsError> {
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
        .map_err(|err| DdnsError::FailedApiRequest(err.to_string()))?
        .result;
    let dns_id = &dns
        .first()
        .ok_or(DdnsError::FailedApiRequest(
            "DnsRecord not foound".to_string(),
        ))?
        .id;
    Ok(dns_id.clone())
}

pub fn update_ip(token: &str, zone: &str, domain: &str, ipserver: &str) -> Result<(), DdnsError> {
    let public_ip = get_ip(ipserver)?;
    let current_ip = look_up(domain)?;
    log::info!(
        "{}'s ip is {}, currently public ip is {}",
        domain,
        current_ip.ip,
        public_ip
    );

    if public_ip != current_ip.ip {
        log::info!("Update {}'s ip to {}", domain, public_ip);

        let client = get_client(token.to_string().to_string())?;
        let zone_id = get_zone_id(&client, zone)?;
        let dns_id = get_dns_id(&client, &zone_id, domain)?;

        log::debug!("zone identifier: {}, dns identifier: {}", zone_id, dns_id);

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
            .map_err(|err| DdnsError::FailedApiRequest(err.to_string()))?;
    }

    log::info!(
        "Waiting for {:?}",
        current_ip.valid - std::time::Instant::now()
    );
    while current_ip.valid > std::time::Instant::now() {
        std::thread::sleep(current_ip.valid - std::time::Instant::now());
    }

    Ok(())
}
