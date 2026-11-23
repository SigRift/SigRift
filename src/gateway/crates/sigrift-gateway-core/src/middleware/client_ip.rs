//! Client IP extraction with trusted-proxy support.
//!
//! `X-Forwarded-For` is a list that every proxy *appends* to, so only the
//! entries added by proxies we trust say anything reliable; everything to
//! their left was written by the client and can be forged. The client IP
//! is therefore resolved like this:
//!
//! - no peer address known (no `ConnectInfo`) → [`UNKNOWN_CLIENT`]; the
//!   header is never consulted, so a missing peer cannot be spoofed;
//! - the direct peer is not a trusted proxy → the peer address; the
//!   header is ignored;
//! - the direct peer is a trusted proxy → walk `X-Forwarded-For` from the
//!   right, skipping addresses of trusted proxies, and take the first one
//!   that is not trusted. If every entry is trusted the leftmost one is the
//!   client. An entry that is not an IP address ends the walk at the last
//!   trusted hop, which is then used.
//!
//! The trusted set ([`TrustedProxies`]) holds IPs and CIDR networks, IPv4
//! and IPv6 (`UC_TRUSTED_PROXIES`). IPv4-mapped IPv6 addresses are treated
//! as the IPv4 address they carry, and the result is always the canonical
//! text form of an address, so one client cannot spread itself over many
//! rate-limit buckets by varying how its address is spelled.

use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request};
use std::net::{IpAddr, SocketAddr};

/// The client "address" used when the peer address is unknown. All such
/// requests share it (one rate-limit bucket), which fails closed.
pub const UNKNOWN_CLIENT: &str = "unknown";

/// The resolved client IP, inserted into request extensions by the auth
/// middleware so handlers (and the proxy, for `X-Forwarded-For`) use the
/// same value the session-binding check used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIp(pub String);

/// One trusted IP network (a single address is a /32 or /128).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// Parse `addr` or `addr/prefix`. Host bits below the prefix are
    /// ignored (like Python's `ip_network(..., strict=False)`).
    fn parse(entry: &str) -> Option<Self> {
        let (addr, prefix) = match entry.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim())),
            None => (entry, None),
        };
        let addr: IpAddr = addr.parse().ok()?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = match prefix {
            Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
                p.parse::<u8>().ok().filter(|&n| n <= max)?
            }
            Some(_) => return None,
            None => max,
        };
        // An IPv4-mapped IPv6 network (::ffff:a.b.c.d/n, n >= 96) is the
        // IPv4 network it maps, since addresses are compared canonically.
        if let IpAddr::V6(v6) = addr {
            if let Some(v4) = v6.to_ipv4_mapped() {
                if prefix >= 96 {
                    return Some(Self {
                        addr: IpAddr::V4(v4),
                        prefix: prefix - 96,
                    });
                }
            }
        }
        Some(Self { addr, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// Trusted proxy addresses and networks (`UC_TRUSTED_PROXIES`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies {
    nets: Vec<IpNet>,
}

impl TrustedProxies {
    /// Parse a comma-separated list of IPs and CIDRs. Returns the parsed
    /// set and the entries that could not be parsed.
    pub fn parse(list: &str) -> (Self, Vec<String>) {
        let mut nets = Vec::new();
        let mut invalid = Vec::new();
        for entry in list.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            match IpNet::parse(entry) {
                Some(net) => nets.push(net),
                None => invalid.push(entry.to_string()),
            }
        }
        (Self { nets }, invalid)
    }

    /// True if *ip* is a trusted proxy address.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.nets.iter().any(|net| net.contains(ip))
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    /// Number of configured entries (addresses and networks).
    pub fn len(&self) -> usize {
        self.nets.len()
    }
}

/// Parse a comma-separated list of trusted proxy IPs/CIDRs, logging any
/// entry that is not an IP address or CIDR network (it is ignored).
pub fn parse_trusted_proxies(list: &str) -> TrustedProxies {
    let (trusted, invalid) = TrustedProxies::parse(list);
    for entry in &invalid {
        tracing::warn!(
            entry = %entry,
            "UC_TRUSTED_PROXIES: ignoring an entry that is not an IP address or CIDR network"
        );
    }
    trusted
}

/// One `X-Forwarded-For` element as an address: a bare IP, `ip:port`,
/// `[v6]` or `[v6]:port`. `None` for anything else (including the RFC 7239
/// `unknown` / obfuscated identifiers).
fn parse_forwarded_ip(entry: &str) -> Option<IpAddr> {
    let entry = entry.trim().trim_matches('"');
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(ip.to_canonical());
    }
    if let Ok(sock) = entry.parse::<SocketAddr>() {
        return Some(sock.ip().to_canonical());
    }
    entry
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|inner| inner.parse::<IpAddr>().ok())
        .map(|ip| ip.to_canonical())
}

/// Resolve the client IP of a request whose direct peer is `peer`.
///
/// See the module documentation for the rules.
pub fn resolve_client_ip(
    peer: Option<IpAddr>,
    headers: &HeaderMap,
    trusted: &TrustedProxies,
) -> String {
    let Some(peer) = peer.map(|ip| ip.to_canonical()) else {
        return UNKNOWN_CLIENT.to_string();
    };
    if !trusted.contains(peer) {
        return peer.to_string();
    }
    // Every X-Forwarded-For line, in order, as one list. A line that is not
    // visible ASCII counts as one unparseable element.
    let mut entries: Vec<Option<IpAddr>> = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        match value.to_str() {
            Ok(line) => entries.extend(line.split(',').map(parse_forwarded_ip)),
            Err(_) => entries.push(None),
        }
    }
    let mut client = peer;
    for entry in entries.into_iter().rev() {
        let Some(ip) = entry else {
            // Not an address: nothing to its left can be trusted. Use the
            // last hop that was vouched for.
            break;
        };
        client = ip;
        if !trusted.contains(ip) {
            break;
        }
    }
    client.to_string()
}

/// Extract the real client IP from a request (see [`resolve_client_ip`]).
pub fn extract_client_ip<B>(req: &Request<B>, trusted: &TrustedProxies) -> String {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    resolve_client_ip(peer, req.headers(), trusted)
}

/// The client IP the auth middleware resolved for this request, or — when
/// the middleware did not run (handlers called directly) — resolve it now.
pub fn client_ip_of<B>(req: &Request<B>, trusted: &TrustedProxies) -> String {
    match req.extensions().get::<ClientIp>() {
        Some(ClientIp(ip)) => ip.clone(),
        None => extract_client_ip(req, trusted),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn trusted(list: &str) -> TrustedProxies {
        let (t, invalid) = TrustedProxies::parse(list);
        assert!(invalid.is_empty(), "{invalid:?}");
        t
    }

    fn req_with_connect_info(ip: &str, xff: &[&str]) -> Request<()> {
        let addr: SocketAddr = match ip.parse::<IpAddr>().unwrap() {
            IpAddr::V4(v4) => SocketAddr::from((v4, 12345)),
            IpAddr::V6(v6) => SocketAddr::from((v6, 12345)),
        };
        let mut builder = Request::builder().uri("/test");
        for value in xff {
            builder = builder.header("x-forwarded-for", *value);
        }
        let mut req = builder.body(()).unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        req
    }

    #[test]
    fn test_direct_ip_when_not_trusted() {
        let req = req_with_connect_info("10.0.0.5", &["1.2.3.4"]);
        assert_eq!(
            extract_client_ip(&req, &TrustedProxies::default()),
            "10.0.0.5"
        );
    }

    #[test]
    fn test_xff_used_when_trusted() {
        let req = req_with_connect_info("127.0.0.1", &["203.0.113.50"]);
        assert_eq!(
            extract_client_ip(&req, &trusted("127.0.0.1")),
            "203.0.113.50"
        );
    }

    /// Regression (G3): a trusted proxy *appends* the address it saw, so
    /// the leftmost entries are whatever the client sent. The client must
    /// not be able to pick its own address by sending X-Forwarded-For.
    #[test]
    fn spoofed_leftmost_entry_is_ignored_behind_an_appending_proxy() {
        // Client 198.51.100.7 sends "X-Forwarded-For: 6.6.6.6"; the proxy
        // (127.0.0.1) appends the real address.
        let req = req_with_connect_info("127.0.0.1", &["6.6.6.6, 198.51.100.7"]);
        assert_eq!(
            extract_client_ip(&req, &trusted("127.0.0.1")),
            "198.51.100.7"
        );
        // Rotating the forged value does not change the bucket.
        let req = req_with_connect_info("127.0.0.1", &["7.7.7.7, 198.51.100.7"]);
        assert_eq!(
            extract_client_ip(&req, &trusted("127.0.0.1")),
            "198.51.100.7"
        );
    }

    #[test]
    fn trusted_hops_are_skipped_from_the_right() {
        // client → proxy A (10.0.0.2) → proxy B (127.0.0.1) → gateway
        let req = req_with_connect_info("127.0.0.1", &["9.9.9.9, 203.0.113.9, 10.0.0.2"]);
        assert_eq!(
            extract_client_ip(&req, &trusted("127.0.0.1, 10.0.0.0/8")),
            "203.0.113.9"
        );
    }

    #[test]
    fn several_header_lines_form_one_list() {
        let req = req_with_connect_info("127.0.0.1", &["6.6.6.6", "198.51.100.7"]);
        assert_eq!(
            extract_client_ip(&req, &trusted("127.0.0.1")),
            "198.51.100.7"
        );
    }

    #[test]
    fn all_trusted_chain_yields_leftmost() {
        let req = req_with_connect_info("127.0.0.1", &["10.1.1.1, 10.2.2.2"]);
        assert_eq!(
            extract_client_ip(&req, &trusted("127.0.0.1, 10.0.0.0/8")),
            "10.1.1.1"
        );
    }

    #[test]
    fn garbage_entry_stops_at_last_trusted_hop() {
        let req = req_with_connect_info("127.0.0.1", &["1.2.3.4, nonsense, 10.2.2.2"]);
        assert_eq!(
            extract_client_ip(&req, &trusted("127.0.0.1, 10.0.0.0/8")),
            "10.2.2.2"
        );
        let req = req_with_connect_info("127.0.0.1", &["1.2.3.4, unknown"]);
        assert_eq!(extract_client_ip(&req, &trusted("127.0.0.1")), "127.0.0.1");
        let req = req_with_connect_info("127.0.0.1", &[""]);
        assert_eq!(extract_client_ip(&req, &trusted("127.0.0.1")), "127.0.0.1");
    }

    #[test]
    fn forwarded_entries_with_ports_and_brackets() {
        let t = trusted("127.0.0.1");
        let req = req_with_connect_info("127.0.0.1", &["203.0.113.5:4711"]);
        assert_eq!(extract_client_ip(&req, &t), "203.0.113.5");
        let req = req_with_connect_info("127.0.0.1", &["[2001:db8::5]:443"]);
        assert_eq!(extract_client_ip(&req, &t), "2001:db8::5");
        let req = req_with_connect_info("127.0.0.1", &["[2001:DB8:0::5]"]);
        assert_eq!(extract_client_ip(&req, &t), "2001:db8::5", "canonical form");
    }

    #[test]
    fn test_trusted_but_no_xff_returns_peer() {
        let req = req_with_connect_info("127.0.0.1", &[]);
        assert_eq!(extract_client_ip(&req, &trusted("127.0.0.1")), "127.0.0.1");
    }

    /// Regression (G3): without a peer address the header must not be
    /// believed — there is nothing to say who wrote it.
    #[test]
    fn no_connect_info_ignores_xff() {
        let req = Request::builder()
            .uri("/test")
            .header("x-forwarded-for", "1.2.3.4")
            .body(())
            .unwrap();
        assert_eq!(
            extract_client_ip(&req, &trusted("127.0.0.1, 0.0.0.0/0")),
            UNKNOWN_CLIENT
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        assert_eq!(
            resolve_client_ip(None, &headers, &trusted("0.0.0.0/0")),
            UNKNOWN_CLIENT
        );
    }

    /// Regression (G3): CIDR entries were silently dropped.
    #[test]
    fn cidr_entries_are_honoured() {
        let t = trusted("172.16.0.0/12, fd00::/8");
        assert!(t.contains("172.20.1.2".parse().unwrap()));
        assert!(t.contains("172.31.255.255".parse().unwrap()));
        assert!(!t.contains("172.32.0.1".parse().unwrap()));
        assert!(t.contains("fd12:3456::1".parse().unwrap()));
        assert!(!t.contains("fe80::1".parse().unwrap()));
        let req = req_with_connect_info("172.18.0.3", &["203.0.113.50"]);
        assert_eq!(extract_client_ip(&req, &t), "203.0.113.50");
    }

    #[test]
    fn ipv4_mapped_addresses_match_ipv4_entries() {
        let t = trusted("127.0.0.1, 10.0.0.0/8");
        assert!(t.contains("::ffff:127.0.0.1".parse().unwrap()));
        assert!(t.contains("::ffff:10.9.8.7".parse().unwrap()));
        let req = req_with_connect_info("::ffff:127.0.0.1", &["::ffff:203.0.113.1"]);
        assert_eq!(extract_client_ip(&req, &t), "203.0.113.1");
        let mapped = trusted("::ffff:192.168.0.0/112");
        assert!(mapped.contains("192.168.4.4".parse().unwrap()));
        assert!(!mapped.contains("192.169.0.1".parse().unwrap()));
    }

    #[test]
    fn zero_prefix_and_host_bits() {
        let t = trusted("0.0.0.0/0");
        assert!(t.contains("8.8.8.8".parse().unwrap()));
        assert!(!t.contains("::1".parse().unwrap()), "v4 net never holds v6");
        let t = trusted("10.0.0.5/8");
        assert!(t.contains("10.200.0.1".parse().unwrap()));
        let t = trusted("::/0");
        assert!(t.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_parse_trusted_proxies() {
        let result = parse_trusted_proxies("127.0.0.1, ::1, 10.0.0.1");
        assert_eq!(result.len(), 3);
        assert!(result.contains("127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(result.contains("::1".parse::<IpAddr>().unwrap()));
        assert!(!result.contains("10.0.0.2".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn invalid_entries_are_reported() {
        let (t, invalid) =
            TrustedProxies::parse("10.0.0.0/8, bogus, 10.0.0.0/33, 1.2.3.4/x, ::1/129, 1.2.3.4/");
        assert_eq!(t.len(), 1);
        assert_eq!(
            invalid,
            vec!["bogus", "10.0.0.0/33", "1.2.3.4/x", "::1/129", "1.2.3.4/"]
        );
    }

    #[test]
    fn test_parse_trusted_proxies_empty() {
        assert!(parse_trusted_proxies("").is_empty());
        assert!(parse_trusted_proxies(" , ").is_empty());
    }

    #[test]
    fn client_ip_extension_is_preferred() {
        let mut req = req_with_connect_info("10.0.0.5", &[]);
        assert_eq!(client_ip_of(&req, &TrustedProxies::default()), "10.0.0.5");
        req.extensions_mut().insert(ClientIp("203.0.113.1".into()));
        assert_eq!(
            client_ip_of(&req, &TrustedProxies::default()),
            "203.0.113.1"
        );
    }

    fn xff_lines(lines: &[&[u8]]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append(
                "x-forwarded-for",
                axum::http::HeaderValue::from_bytes(line).unwrap(),
            );
        }
        headers
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    /// G3: a client that claims an address inside the trusted range does
    /// not become a "proxy" whose left neighbour it can pick: the walk
    /// stops at the real client the trusted proxy appended.
    #[test]
    fn a_client_claiming_a_trusted_address_is_not_skipped_past() {
        let t = trusted("127.0.0.1, 10.0.0.0/8");
        let req = req_with_connect_info("127.0.0.1", &["6.6.6.6, 10.9.9.9, 198.51.100.20"]);
        assert_eq!(extract_client_ip(&req, &t), "198.51.100.20");
        // The same forged entries sent straight to the gateway are ignored.
        let req = req_with_connect_info("198.51.100.20", &["6.6.6.6, 10.9.9.9"]);
        assert_eq!(extract_client_ip(&req, &t), "198.51.100.20");
        // A peer inside a trusted network but not listed is not trusted.
        let req = req_with_connect_info("127.0.0.2", &["6.6.6.6"]);
        assert_eq!(extract_client_ip(&req, &t), "127.0.0.2");
    }

    /// Only X-Forwarded-For is read: `Forwarded` and `X-Real-IP` are
    /// client-controlled too and name nobody, from a trusted proxy or not.
    #[test]
    fn other_forwarding_headers_are_ignored() {
        let t = trusted("127.0.0.1");
        for peer in ["127.0.0.1", "198.51.100.30"] {
            for (name, value) in [
                ("forwarded", "for=6.6.6.6"),
                ("forwarded", "for=\"[2001:db8::6]\";proto=https"),
                ("x-real-ip", "6.6.6.6"),
                ("x-client-ip", "6.6.6.6"),
                ("true-client-ip", "6.6.6.6"),
            ] {
                let mut req = req_with_connect_info(peer, &[]);
                req.headers_mut().insert(name, value.parse().unwrap());
                assert_eq!(
                    extract_client_ip(&req, &t),
                    peer,
                    "{name}: {value} via {peer}"
                );
            }
        }
    }

    /// A header line that is not visible ASCII is one unparseable entry:
    /// nothing to its left is believed.
    #[test]
    fn an_unreadable_forwarded_line_ends_the_walk() {
        let t = trusted("127.0.0.1, 10.0.0.0/8");
        let peer = ip("127.0.0.1");
        let headers = xff_lines(&[b"6.6.6.6", b"caf\xc3\xa9", b"10.0.0.2"]);
        assert_eq!(resolve_client_ip(peer, &headers, &t), "10.0.0.2");
        let headers = xff_lines(&[b"6.6.6.6", b"\xff"]);
        assert_eq!(resolve_client_ip(peer, &headers, &t), "127.0.0.1");
        let headers = xff_lines(&[b"6.6.6.6, \xff 1.2.3.4"]);
        assert_eq!(resolve_client_ip(peer, &headers, &t), "127.0.0.1");
    }

    #[test]
    fn quoted_and_bracketed_forwarded_entries_are_parsed() {
        let t = trusted("127.0.0.1");
        let peer = ip("127.0.0.1");
        for (line, client) in [
            ("\"203.0.113.5\"", "203.0.113.5"),
            ("\"[2001:db8::7]:80\"", "2001:db8::7"),
            ("[::ffff:203.0.113.1]:443", "203.0.113.1"),
            (" 203.0.113.6 ", "203.0.113.6"),
        ] {
            let headers = xff_lines(&[line.as_bytes()]);
            assert_eq!(resolve_client_ip(peer, &headers, &t), client, "{line}");
        }
        // Malformed brackets are not addresses: the proxy itself is used.
        for line in [
            "[203.0.113.5",
            "203.0.113.5]",
            "[]",
            "[2001:db8::7",
            "_hidden",
        ] {
            let headers = xff_lines(&[line.as_bytes()]);
            assert_eq!(resolve_client_ip(peer, &headers, &t), "127.0.0.1", "{line}");
        }
    }

    /// One client gets one canonical spelling, so it cannot spread itself
    /// over many rate-limit buckets.
    #[test]
    fn the_peer_address_is_canonical_when_not_trusted() {
        let none = TrustedProxies::default();
        let empty = HeaderMap::new();
        assert_eq!(
            resolve_client_ip(ip("::ffff:203.0.113.9"), &empty, &none),
            "203.0.113.9"
        );
        assert_eq!(
            resolve_client_ip(ip("2001:0DB8:0000:0000::0001"), &empty, &none),
            "2001:db8::1"
        );
        let headers = xff_lines(&[b"198.51.100.1"]);
        assert_eq!(
            resolve_client_ip(ip("::ffff:203.0.113.9"), &headers, &none),
            "203.0.113.9",
            "the header is ignored for an untrusted peer"
        );
    }

    #[test]
    fn ipv6_proxy_chains_are_walked_like_ipv4_ones() {
        let t = trusted("::1, fd00::/8");
        let req = req_with_connect_info("::1", &["2001:db8::66, 2001:db8::9, fd00::2"]);
        assert_eq!(extract_client_ip(&req, &t), "2001:db8::9");
        let req = req_with_connect_info("::1", &["fd00::3, fd00::2"]);
        assert_eq!(extract_client_ip(&req, &t), "fd00::3");
        let req = req_with_connect_info("2001:db8::9", &["::1"]);
        assert_eq!(extract_client_ip(&req, &t), "2001:db8::9");
    }

    /// A typo in `UC_TRUSTED_PROXIES` must not quietly widen (or reshape)
    /// the trusted set: such an entry is rejected, not reinterpreted.
    #[test]
    fn trusted_proxy_entries_are_parsed_strictly() {
        let (t, invalid) = TrustedProxies::parse(
            "10.0.0.0/+8, 10.0.0.0/-8, 10.0.0.0/8.0, 10.0.0.0/8/8, /8, 10.0.0.0/256, \
             [::1], 10.0.0, 10.0.0.0.0/8",
        );
        assert!(t.is_empty(), "{t:?}");
        assert_eq!(invalid.len(), 9, "{invalid:?}");
        // The same parse, logged by the startup helper, keeps the valid ones.
        let t = parse_trusted_proxies("bogus, 192.0.2.1/32, 2001:db8::1/128, 10.0.0.0 / 8");
        assert_eq!(t.len(), 3);
        assert!(t.contains("192.0.2.1".parse().unwrap()));
        assert!(!t.contains("192.0.2.2".parse().unwrap()));
        assert!(t.contains("2001:db8::1".parse().unwrap()));
        assert!(!t.contains("2001:db8::2".parse().unwrap()));
        assert!(t.contains("10.255.0.1".parse().unwrap()));
    }

    /// An IPv4-mapped network shorter than /96 is not an IPv4 network, so
    /// it never trusts an IPv4 (or mapped) address.
    #[test]
    fn short_mapped_networks_do_not_trust_ipv4_addresses() {
        let t = trusted("::ffff:0.0.0.0/95");
        assert!(!t.contains("10.0.0.1".parse().unwrap()));
        assert!(!t.contains("::ffff:10.0.0.1".parse().unwrap()));
        let req = req_with_connect_info("::ffff:127.0.0.1", &["6.6.6.6"]);
        assert_eq!(extract_client_ip(&req, &t), "127.0.0.1");
    }
}
