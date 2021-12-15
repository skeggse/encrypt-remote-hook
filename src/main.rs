use anyhow::{anyhow, Context, Result};
use dnsclient::UpstreamServer;
use serde::Deserialize;
use std::{
    env, fs,
    fs::File,
    io,
    io::Read,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::Path,
    process::{Command, ExitStatus, Output, Stdio},
    str::FromStr,
};
use ureq::Resolver;

#[derive(Deserialize)]
struct Device {
    block: String,
    name: String,
    // TODO: add options support
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum Key {
    #[serde(rename = "rootfs")]
    RootFS { path: String },
    #[serde(rename = "https")]
    HTTPS { url: String },
}

#[derive(Deserialize)]
struct Config {
    device: Device,
    #[serde(rename = "key")]
    keys: Vec<Key>,
}

const CONFIG_PATH: &'static str = "/etc/crypttab.remote.toml";
const KEYFILE_PATH: &'static str = "/crypto_keyfile_combined.bin";
const SCHEMES: &'static [&'static str] = &["LABEL=", "UUID=", "PARTLABEL=", "PARTUUID="];
const DNS_FIELDS: &'static [&'static str] = &["IPV4DNS0", "IPV4DNS1"];

fn read_to_end(filename: &str) -> Result<Vec<u8>> {
    let mut file = File::open(filename).context(format!("failed to open {}", filename))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .context(format!("failed to read {}", filename))?;
    Ok(data)
}

fn read_config() -> Result<Box<Config>> {
    let config_data = read_to_end(CONFIG_PATH)?;
    toml::de::from_slice(&config_data).context(format!("failed to parse {}", CONFIG_PATH))
}

// Not optimized, unlikely fs::read_to_string :(
fn read_to_string_lossy(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut buf = vec![];
    file.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into())
}

fn get_dns_servers() -> io::Result<Vec<UpstreamServer>> {
    let mut servers = vec![];
    for entry in fs::read_dir("/tmp")? {
        let path = entry?.path();
        let path = path.as_path();
        let path_str = path.to_string_lossy();

        if path.is_file() && path_str.starts_with("/tmp/net-") && path_str.ends_with(".conf") {
            // For whatever reason, the DEVICE line can include a 0xf8 and make
            // the entire file invalid UTF-8.
            let conf =
                dotenv_parser::parse_dotenv(&read_to_string_lossy(&path)?).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("failed to parse {}", path_str),
                    )
                })?;
            for field in DNS_FIELDS.iter() {
                if let Some(addr) = conf.get(field as &str) {
                    let addr = Ipv4Addr::from_str(addr).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "failed to parse ip address")
                    })?;
                    if addr == Ipv4Addr::new(0, 0, 0, 0) {
                        // It seems that this address sometimes shows up as a
                        // sentinel value, meaning nil.
                        continue;
                    }
                    servers.push(UpstreamServer::new(
                        // No clear reason to use SocketAddr instead of IpAddr,
                        // because dnsclient doesn't use the port.
                        SocketAddrV4::new(addr, 53),
                    ));
                }
            }
        }
    }
    if servers.len() == 0 {
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no servers provided by dhcp",
        ))
    } else {
        Ok(servers)
    }
}

struct InitResolver;

// We can't rely on libnss existing or being able to getaddrinfo, so we make the
// dns request manually based on what's available in /tmp/net-*.conf.
impl Resolver for InitResolver {
    fn resolve(&self, netloc: &str) -> io::Result<Vec<SocketAddr>> {
        // rust implements this with LookupHost, but doesn't seem to expose that
        // functionality.
        let (host, port_str) = netloc
            .rsplit_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket address"))?;
        let port: u16 = port_str
            .parse()
            .ok()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid port value"))?;

        let client = dnsclient::sync::DNSClient::new_with_system_resolvers()
            .or_else::<io::Error, _>(|_| Ok(dnsclient::sync::DNSClient::new(get_dns_servers()?)))?;
        let mut a: Vec<SocketAddr> = client
            .query_a(host)?
            .into_iter()
            .map(|a| SocketAddr::new(a.into(), port))
            .collect();
        a.extend(
            client
                .query_aaaa(host)?
                .into_iter()
                .map(|a| SocketAddr::new(a.into(), port)),
        );
        Ok(a)
    }
}

// Adapted from https://salsa.debian.org/kernel-team/initramfs-tools/-/blob/master/scripts/functions.
fn resolve_device(device: &str) -> Result<String> {
    if !SCHEMES.iter().any(|scheme| device.starts_with(scheme)) {
        return Err(anyhow!(
            "device block does not match expected persistent block naming schemes"
        ));
    }

    let mut result = Command::new("blkid")
        .args(["-l", "-t", device, "-o", "device"])
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()?;
    result.check_okay("blkid")?;

    String::from_utf8(result.stdout)
        .map(|v| v.trim_end().into())
        .context("failed to decode blkid output")
}

trait ResolveKey {
    fn resolve_key(&self) -> Result<Vec<u8>>;
}

impl ResolveKey for Key {
    fn resolve_key(&self) -> Result<Vec<u8>> {
        match self {
            Key::RootFS { path } => read_to_end(path),
            Key::HTTPS { url } => {
                // TODO: re-use agent?
                let agent = ureq::builder().resolver(InitResolver).build();
                let mut data = Vec::new();
                let req = agent.get(url);
                let url = req.request_url()?;
                let protocol = url.scheme();
                if protocol != "https" {
                    return Err(anyhow!("unsupported protocol {}", protocol));
                }
                req.call()?.into_reader().read_to_end(&mut data)?;
                Ok(data)
            }
        }
    }
}

impl ResolveKey for Config {
    fn resolve_key(&self) -> Result<Vec<u8>> {
        let mut keys_iter = self.keys.iter();
        let first_key = keys_iter.next().ok_or_else(|| anyhow!("no keys defined"))?;
        let mut combined_key: Vec<u8> = first_key.resolve_key()?;
        for key in keys_iter {
            let next_key = key.resolve_key()?;
            if combined_key.len() != next_key.len() {
                return Err(anyhow!("key sizes differed"));
            }
            combined_key
                .iter_mut()
                .zip(next_key.iter())
                .for_each(|(b1, b2)| *b1 ^= b2);
        }
        Ok(combined_key)
    }
}

fn is_luks(device: &str) -> Result<bool> {
    Ok(Command::new("cryptsetup")
        .args(["isLuks", device])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success())
}

trait CommandOkay {
    fn check_okay(&mut self, component: &str) -> Result<&Self>;
}

impl CommandOkay for ExitStatus {
    fn check_okay(&mut self, component: &str) -> Result<&Self> {
        if self.success() {
            Ok(self)
        } else {
            Err(match self.code() {
                Some(code) => anyhow!("{} failed: {}", component, code),
                None => anyhow!("{} abnormal termination", component),
            })
        }
    }
}

impl CommandOkay for Output {
    fn check_okay(&mut self, component: &str) -> Result<&Self> {
        self.status.check_okay(component)?;
        Ok(self)
    }
}

impl CommandOkay for Command {
    fn check_okay(&mut self, component: &str) -> Result<&Self> {
        self.status()?.check_okay(component)?;
        Ok(self)
    }
}

trait StdioNull {
    fn stdio_null(&mut self) -> &mut Self;
}

impl StdioNull for Command {
    fn stdio_null(&mut self) -> &mut Self {
        self.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
    }
}

fn main() -> Result<()> {
    let quiet_mode = env::var("quiet").map(|q| q == "y").unwrap_or(false);

    Command::new("modprobe")
        .args(["-a", "-q", "dm-crypt"])
        .stdio_null()
        .check_okay("modprobe dm-crypt")?;

    let config = read_config()?;

    let mapper_dest = format!("/dev/mapper/{}", &config.device.name);
    if let Ok(_) = fs::metadata(&mapper_dest) {
        println!("device {} already exists, skipping", mapper_dest);
        return Ok(());
    }

    let block_device: &str = &resolve_device(&config.device.block)?;

    if !is_luks(block_device)? {
        return Err(anyhow!("non-luks devices are not yet supported"));
    }

    let key = config.resolve_key()?;
    fs::write(KEYFILE_PATH, key)?;

    Command::new("cryptsetup")
        .args([
            "--key-file",
            KEYFILE_PATH,
            "open",
            "--type",
            "luks",
            block_device,
            &config.device.name,
        ])
        .stdin(Stdio::null())
        .stdout(if quiet_mode {
            Stdio::null()
        } else {
            Stdio::inherit()
        })
        .stderr(Stdio::null())
        .check_okay("cryptsetup open")?;

    // finally, rm keyfile
    if let Err(err) = fs::remove_file(KEYFILE_PATH) {
        println!("warning: failed to clean up keyfile ({})", err);
    }

    Ok(())
}
