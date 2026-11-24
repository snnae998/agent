//! 送中 self-check: whether this host's egress is geo-located to China.
//!
//! The criterion is the one xykt's IPQuality uses: fetch the YouTube Premium
//! page from the host's own egress and look at what it says. A body carrying
//! `www.google.cn` means YouTube treats this egress as mainland China (送中);
//! otherwise the page's `contentRegion` names the country it does see. The
//! check has to run on the node itself -- the hub's view of the node's
//! address says where the connection arrived from, not where the node's own
//! outbound traffic lands, and behind NAT or a tunnel the two differ.
//!
//! Each stack is forced separately: a dual-stack host can be clean on IPv4
//! and 送中 on IPv6, and only a lookup restricted to one family proves
//! anything about that family. The egress probe doubles as the gate: no
//! address on a stack means that stack does not exist here (`none`), while
//! an address but an unreadable Premium page is a failed check (`fail`),
//! which the hub must not render as either clean or 送中.

use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// The page whose body carries the verdict. The cookie set is IPQuality's:
/// it pins a consent state under which the page reliably embeds
/// `contentRegion` and, for a Chinese egress, the `www.google.cn` marker.
const PREMIUM_URL: &str = "https://www.youtube.com/premium";
const PREMIUM_COOKIE: &str = "YSC=BiCUU3-5Gdk; CONSENT=YES+cb.20220301-11-p0.en+FX+700; GPS=1; VISITOR_INFO1_LIVE=4VwPMkB7W5A; PREF=tz=Asia.Shanghai; _gcl_au=1.1.1809531354.1646633279";
const USER_AGENT: &str =
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36";

/// Per-stack egress probes. Both names must be asked through a resolver
/// restricted to the stack under test: a name with only an A record can
/// never prove an IPv6 egress exists, and vice versa.
const PROBE_V4: &str = "https://api4.ipify.org";
const PROBE_V6: &str = "https://api64.ipify.org";

/// The Premium page runs to a few hundred kilobytes; the markers sit near
/// the top. The cap exists so a pathological response cannot spend the
/// agent's memory budget on a check that runs a handful of times a day.
const BODY_CAP: u64 = 4 << 20;

/// One check's outcome, in the shape the hub reads by name. Statuses are
/// `ok`, `cn`, `fail`, `none` per stack; a region is set only for `ok`
/// (the country YouTube sees, `??` when the page does not say) and `cn`
/// (always `CN`).
#[derive(Serialize)]
pub struct SongzhongResult {
    pub v4: String,
    pub v4_region: String,
    pub v6: String,
    pub v6_region: String,
    pub ip4: String,
    pub ip6: String,
    pub checked: i64,
}

/// Runs both stacks' checks back to back. Blocking throughout (ureq), so
/// the caller runs it on a blocking thread, never on the session loop.
pub fn run_check() -> SongzhongResult {
    let (v4, v4_region, ip4) = check_stack(false);
    let (v6, v6_region, ip6) = check_stack(true);
    SongzhongResult {
        v4,
        v4_region,
        v6,
        v6_region,
        ip4,
        ip6,
        checked: SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64),
    }
}

fn check_stack(v6: bool) -> (String, String, String) {
    let none = || ("none".to_owned(), String::new(), String::new());
    let agent = stack_agent(v6);
    let probe = if v6 { PROBE_V6 } else { PROBE_V4 };
    let Some(ip) = fetch(&agent, probe, false) else {
        return none();
    };
    let ip = ip.trim().to_owned();
    match ip.parse::<IpAddr>() {
        Ok(addr) if addr.is_ipv6() == v6 => {}
        _ => return none(),
    }
    let Some(body) = fetch(&agent, PREMIUM_URL, true) else {
        return ("fail".to_owned(), String::new(), ip);
    };
    if body.contains("www.google.cn") {
        return ("cn".to_owned(), "CN".to_owned(), ip);
    }
    ("ok".to_owned(), extract_region(&body).unwrap_or_else(|| "??".to_owned()), ip)
}

/// An HTTP client whose resolver keeps only one address family, so every
/// request it makes provably leaves over that stack. ureq follows redirects
/// by default, which the Premium URL needs.
///
/// A proxy named by the environment (the usual `HTTPS_PROXY`/`ALL_PROXY`)
/// is honoured, as curl honours it: a host that can only reach the internet
/// through a gateway proxy has that proxy as its effective egress, which is
/// exactly what the check is asked to judge. With a proxy in play the
/// family filter applies to the proxy connection and the far stack is the
/// proxy's choice.
fn stack_agent(v6: bool) -> ureq::Agent {
    let mut builder =
        ureq::AgentBuilder::new().timeout(Duration::from_secs(15)).resolver(move |hostport: &str| {
            let addrs: Vec<SocketAddr> = hostport.to_socket_addrs()?.filter(|a| a.is_ipv6() == v6).collect();
            Ok(addrs)
        });
    for var in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        if let Ok(raw) = std::env::var(var) {
            if let Ok(proxy) = ureq::Proxy::new(raw.trim()) {
                builder = builder.proxy(proxy);
                break;
            }
        }
    }
    builder.build()
}

fn fetch(agent: &ureq::Agent, url: &str, premium: bool) -> Option<String> {
    let mut req = agent.get(url);
    if premium {
        req = req.set("Accept-Language", "en").set("Cookie", PREMIUM_COOKIE).set("User-Agent", USER_AGENT);
    }
    let resp = req.call().ok()?;
    let mut body = Vec::new();
    resp.into_reader().take(BODY_CAP).read_to_end(&mut body).ok()?;
    Some(String::from_utf8_lossy(&body).into_owned())
}

/// The country code in `"contentRegion":"XX"`, when the page carries one.
fn extract_region(body: &str) -> Option<String> {
    let start = body.find("\"contentRegion\":\"")? + "\"contentRegion\":\"".len();
    let region: String = body[start..].chars().take_while(|c| c.is_ascii_uppercase()).collect();
    if region.is_empty() {
        None
    } else {
        Some(region)
    }
}

#[cfg(test)]
mod tests {
    use super::extract_region;

    #[test]
    fn region_reads_the_country_code() {
        assert_eq!(extract_region(r#"{"contentRegion":"US","x":1}"#).as_deref(), Some("US"));
        assert_eq!(extract_region(r#"{"contentRegion":""}"#), None);
        assert_eq!(extract_region("no marker at all"), None);
    }
}
