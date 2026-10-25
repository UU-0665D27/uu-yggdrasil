//! Multicast-обнаружение пиров по локальной сети.
//!
//! Формат beacon-пакетов и TLS-соединений совместим с yggdrasil-go и
//! Yggdrasil-ng: группа `ff02::114`, UDP-порт `9001`, версия протокола
//! `0.5`, BLAKE2b-512 хэш пароля и обычный `meta`-handshake поверх TLS.
//! После TLS-соединения подлинность пира проверяется тем же ed25519
//! handshake'ом, что и для явно заданных `tcp://` пиров.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
    time::{Duration, Instant},
};

use blake2::{
    Blake2b512, Blake2bMac512,
    digest::{Digest, KeyInit, Mac},
};
use ed25519_dalek::SigningKey;
use getifaddrs::{self, InterfaceFlags};
use glob_match::glob_match;
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ED25519};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Mutex,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use crate::{
    config::MulticastInterfaceConfig,
    ironwood::network::{
        PublicKey, handshake_async,
        link::{LINK_VERSION_MAJOR, LINK_VERSION_MINOR},
        public_key_from_bytes, spawn_conn,
    },
    yggdrasil::Inner,
};

const MULTICAST_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0114);
const MULTICAST_PORT: u16 = 9001;
const BEACON_MAX_INTERVAL: Duration = Duration::from_secs(15);
const RECV_BUF_SIZE: usize = 2048;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// `major:u16 | minor:u16 | key:[32] | port:u16 | hash_len:u16`.
const ADVERTISEMENT_HEADER: usize = 40;

/// Запущенный движок multicast-обнаружения.
pub struct Multicast {
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

impl Multicast {
    pub(crate) fn close(&self) {
        self.cancel.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Drop for Multicast {
    fn drop(&mut self) {
        self.close();
    }
}

/// Запустить multicast-обнаружение. Ошибка не должна ронять узел: вызывающий
/// код логирует её и продолжает работу без multicast.
pub(crate) fn start(
    inner: &Arc<Inner>,
    config: Vec<MulticastInterfaceConfig>,
) -> io::Result<Multicast> {
    let patterns: Vec<MulticastInterfaceConfig> = config
        .into_iter()
        .filter(|config| config.beacon || config.listen)
        .collect();
    if patterns.is_empty() {
        debug!("multicast: all interfaces disabled");
        return Ok(Multicast {
            cancel: CancellationToken::new(),
            tasks: Vec::new(),
        });
    }

    let socket = create_multicast_socket()?;
    let udp = Arc::new(UdpSocket::from_std(socket)?);
    let tls = Arc::new(TlsConfigs::new(inner.secret())?);
    let cancel = CancellationToken::new();
    let interfaces = Arc::new(Mutex::new(HashMap::new()));
    let listeners = Arc::new(Mutex::new(HashMap::new()));
    let in_progress = Arc::new(Mutex::new(HashSet::new()));

    let monitor = tokio::spawn(monitor_loop(
        Arc::clone(inner),
        Arc::clone(&tls),
        cancel.clone(),
        Arc::clone(&interfaces),
        Arc::clone(&listeners),
        Arc::clone(&udp),
        patterns,
    ));
    let receiver = tokio::spawn(receiver_loop(
        Arc::clone(inner),
        tls,
        cancel.clone(),
        interfaces,
        in_progress,
        udp,
    ));

    Ok(Multicast {
        cancel,
        tasks: vec![monitor, receiver],
    })
}

// ── Beacon ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
struct Advertisement {
    major_version: u16,
    minor_version: u16,
    public_key: [u8; 32],
    port: u16,
    hash: Vec<u8>,
}

impl Advertisement {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ADVERTISEMENT_HEADER + self.hash.len());
        buf.extend_from_slice(&self.major_version.to_be_bytes());
        buf.extend_from_slice(&self.minor_version.to_be_bytes());
        buf.extend_from_slice(&self.public_key);
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf.extend_from_slice(
            &u16::try_from(self.hash.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        buf.extend_from_slice(&self.hash);
        buf
    }

    fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < ADVERTISEMENT_HEADER {
            return None;
        }
        let major_version = u16::from_be_bytes([data[0], data[1]]);
        let minor_version = u16::from_be_bytes([data[2], data[3]]);
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[4..36]);
        let port = u16::from_be_bytes([data[36], data[37]]);
        let hash_len = usize::from(u16::from_be_bytes([data[38], data[39]]));
        let end = ADVERTISEMENT_HEADER.checked_add(hash_len)?;
        if data.len() < end {
            return None;
        }
        Some(Self {
            major_version,
            minor_version,
            public_key,
            port,
            hash: data[ADVERTISEMENT_HEADER..end].to_vec(),
        })
    }
}

fn auth_hash(public_key: &[u8; 32], password: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        let mut hasher = Blake2b512::new();
        hasher.update(public_key);
        hasher.finalize().to_vec()
    } else {
        let mut mac =
            Blake2bMac512::new_from_slice(password).expect("BLAKE2b key must be at most 64 bytes");
        mac.update(public_key);
        mac.finalize().into_bytes().to_vec()
    }
}

// ── Interfaces ───────────────────────────────────────────────────────────

struct InterfaceState {
    index: u32,
    addrs: Vec<Ipv6Addr>,
    beacon: bool,
    listen: bool,
    joined: bool,
    port: u16,
    priority: u8,
    password: Vec<u8>,
    hash: Vec<u8>,
    beacon_interval: Duration,
    last_beacon: Instant,
}

struct ListenerInfo {
    port: u16,
    bind: Ipv6Addr,
    cancel: CancellationToken,
    _handle: JoinHandle<()>,
}

fn interface_display_name(entry: &getifaddrs::Interface) -> String {
    #[cfg(windows)]
    {
        if !entry.description.is_empty() {
            return entry.description.clone();
        }
    }
    entry.name.clone()
}

fn create_multicast_socket() -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_only_v6(true)?;
    let bind = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MULTICAST_PORT, 0, 0);
    socket.bind(&SocketAddr::V6(bind).into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

fn discover_interfaces(
    public_key: PublicKey,
    patterns: &[MulticastInterfaceConfig],
) -> HashMap<String, InterfaceState> {
    let Ok(entries) = getifaddrs::getifaddrs() else {
        debug!("multicast: failed to enumerate interfaces");
        return HashMap::new();
    };

    let mut by_name: HashMap<String, (u32, Vec<Ipv6Addr>)> = HashMap::new();
    for entry in entries {
        let flags = entry.flags;
        if !flags.contains(InterfaceFlags::UP)
            || !flags.contains(InterfaceFlags::RUNNING)
            || !flags.contains(InterfaceFlags::MULTICAST)
            || flags.contains(InterfaceFlags::POINTTOPOINT)
            || flags.contains(InterfaceFlags::LOOPBACK)
        {
            continue;
        }
        let Some(index) = entry.index else {
            continue;
        };
        let getifaddrs::Address::V6(address) = &entry.address else {
            continue;
        };
        let ip = address.address;
        if ip.segments()[0] & 0xffc0 != 0xfe80 {
            continue;
        }
        by_name
            .entry(interface_display_name(&entry))
            .or_insert_with(|| (index, Vec::new()))
            .1
            .push(ip);
    }

    let now = Instant::now();
    let mut result = HashMap::new();
    for (name, (index, addrs)) in by_name {
        for config in patterns {
            if !config.beacon && !config.listen {
                continue;
            }
            if !glob_match(&config.filter, &name) {
                continue;
            }
            let password = config.password.as_bytes().to_vec();
            let hash = auth_hash(public_key.as_bytes(), &password);
            result.insert(
                name,
                InterfaceState {
                    index,
                    addrs,
                    beacon: config.beacon,
                    listen: config.listen,
                    joined: false,
                    port: config.port,
                    priority: config.priority,
                    password,
                    hash,
                    beacon_interval: Duration::from_secs(1),
                    last_beacon: now.checked_sub(Duration::from_secs(60)).unwrap_or(now),
                },
            );
            break;
        }
    }
    result
}

fn join_multicast(udp: &UdpSocket, index: u32) -> io::Result<()> {
    SockRef::from(udp).join_multicast_v6(&MULTICAST_GROUP, index)
}

// ── Monitor / beacon loop ────────────────────────────────────────────────

async fn monitor_loop(
    inner: Arc<Inner>,
    tls: Arc<TlsConfigs>,
    cancel: CancellationToken,
    interfaces: Arc<Mutex<HashMap<String, InterfaceState>>>,
    listeners: Arc<Mutex<HashMap<String, ListenerInfo>>>,
    udp: Arc<UdpSocket>,
    patterns: Vec<MulticastInterfaceConfig>,
) {
    loop {
        let discovered = discover_interfaces(inner.key(), &patterns);
        refresh_interfaces(&interfaces, &listeners, discovered).await;
        manage_interfaces(&inner, &tls, &cancel, &interfaces, &listeners, &udp).await;

        tokio::select! {
            () = cancel.cancelled() => break,
            () = sleep(Duration::from_secs(1)) => {}
        }
    }
}

async fn refresh_interfaces(
    interfaces: &Mutex<HashMap<String, InterfaceState>>,
    listeners: &Mutex<HashMap<String, ListenerInfo>>,
    discovered: HashMap<String, InterfaceState>,
) {
    let mut current = interfaces.lock().await;
    let old_names: Vec<String> = current.keys().cloned().collect();
    for name in old_names {
        if discovered.contains_key(&name) {
            continue;
        }
        current.remove(&name);
        let removed = listeners.lock().await.remove(&name);
        if let Some(listener) = removed {
            listener.cancel.cancel();
        }
        debug!(interface = %name, "multicast: interface removed");
    }
    for (name, state) in discovered {
        if let Some(existing) = current.get_mut(&name) {
            if existing.index != state.index {
                // Membership is tied to the interface index. If an interface
                // disappears and comes back with a new index, join again.
                existing.index = state.index;
                existing.joined = false;
            }
            if existing.addrs != state.addrs {
                debug!(
                    interface = %name,
                    addrs = ?state.addrs,
                    "multicast: interface addresses changed"
                );
            }
            existing.addrs = state.addrs;
        } else {
            debug!(
                interface = %name,
                index = state.index,
                addrs = ?state.addrs,
                "multicast: interface discovered"
            );
            current.insert(name, state);
        }
    }
}

async fn manage_interfaces(
    inner: &Arc<Inner>,
    tls: &Arc<TlsConfigs>,
    cancel: &CancellationToken,
    interfaces: &Mutex<HashMap<String, InterfaceState>>,
    listeners: &Mutex<HashMap<String, ListenerInfo>>,
    udp: &UdpSocket,
) {
    let mut current = interfaces.lock().await;
    let mut active = listeners.lock().await;
    for (name, state) in &mut *current {
        if state.listen && !state.joined {
            match join_multicast(udp, state.index) {
                Ok(()) => state.joined = true,
                // Linux keeps the socket in the multicast group when the
                // interface flaps and rejoins with the same index. A second
                // IPV6_ADD_MEMBERSHIP then fails with EADDRINUSE, which is
                // not an error for us.
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    state.joined = true;
                    trace!(
                        interface = %name,
                        "multicast: group membership survived interface flap"
                    );
                }
                Err(error) => {
                    debug!(
                        interface = %name,
                        %error,
                        "multicast: failed to join group"
                    );
                }
            }
        }

        // A link-local address can change while the interface keeps its name
        // (e.g. Wi-Fi reconnect). Stop the listener and let the code below
        // start a fresh one on the new address.
        if let Some(listener) = active.get(name)
            && !state.addrs.contains(&listener.bind)
        {
            let listener = active.remove(name);
            if let Some(listener) = listener {
                listener.cancel.cancel();
                debug!(interface = %name, "multicast: listener address changed");
            }
        }

        if state.beacon && !active.contains_key(name) {
            let mut started = None;
            let mut last_error = None;
            for bind in state.addrs.iter().copied() {
                let config = BeaconListenerConfig {
                    bind,
                    port: state.port,
                    scope_id: state.index,
                    priority: state.priority,
                    password: state.password.clone(),
                };
                match start_tls_listener(Arc::clone(inner), Arc::clone(tls), cancel.clone(), config)
                    .await
                {
                    Ok((port, listener_cancel, handle)) => {
                        started = Some((bind, port, listener_cancel, handle));
                        break;
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            match started {
                Some((bind, port, listener_cancel, handle)) => {
                    info!(
                        interface = %name,
                        port,
                        "multicast: beacon listener started"
                    );
                    active.insert(
                        name.clone(),
                        ListenerInfo {
                            port,
                            bind,
                            cancel: listener_cancel,
                            _handle: handle,
                        },
                    );
                }
                None => {
                    if let Some(error) = last_error {
                        // EADDRNOTAVAIL is normal right after an interface
                        // appears: the link-local address may still be in
                        // DAD. We retry every monitor tick.
                        if error.kind() == io::ErrorKind::AddrNotAvailable {
                            debug!(
                                interface = %name,
                                %error,
                                "multicast: beacon listener address not ready"
                            );
                        } else {
                            warn!(
                                interface = %name,
                                %error,
                                "multicast: failed to start beacon listener"
                            );
                        }
                    }
                }
            }
        }
        if state.beacon
            && state.last_beacon.elapsed() >= state.beacon_interval
            && let Some(listener) = active.get(name)
        {
            send_beacon(udp, name, state, listener.port, inner.key()).await;
        }
    }
}

async fn send_beacon(
    udp: &UdpSocket,
    name: &str,
    state: &mut InterfaceState,
    port: u16,
    public_key: PublicKey,
) {
    let advertisement = Advertisement {
        major_version: LINK_VERSION_MAJOR,
        minor_version: LINK_VERSION_MINOR,
        public_key: *public_key.as_bytes(),
        port,
        hash: state.hash.clone(),
    };
    let destination = SocketAddrV6::new(MULTICAST_GROUP, MULTICAST_PORT, 0, state.index);
    match udp.send_to(&advertisement.encode(), destination).await {
        Ok(_) => {
            trace!(
                interface = %name,
                port,
                interval = ?state.beacon_interval,
                "multicast: beacon sent"
            );
        }
        Err(error) => {
            debug!(
                interface = %name,
                %error,
                "multicast: failed to send beacon"
            );
        }
    }
    state.beacon_interval =
        (state.beacon_interval + Duration::from_secs(1)).min(BEACON_MAX_INTERVAL);
    state.last_beacon = Instant::now();
}

// ── Receiver / discovery loop ────────────────────────────────────────────

async fn receiver_loop(
    inner: Arc<Inner>,
    tls: Arc<TlsConfigs>,
    cancel: CancellationToken,
    interfaces: Arc<Mutex<HashMap<String, InterfaceState>>>,
    in_progress: Arc<Mutex<HashSet<PublicKey>>>,
    udp: Arc<UdpSocket>,
) {
    let mut buf = vec![0u8; RECV_BUF_SIZE];
    loop {
        let received = tokio::select! {
            () = cancel.cancelled() => break,
            result = udp.recv_from(&mut buf) => result,
        };
        let (len, from) = match received {
            Ok(value) => value,
            Err(error) => {
                if cancel.is_cancelled() {
                    break;
                }
                debug!(%error, "multicast: receive error");
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let SocketAddr::V6(from) = from else {
            continue;
        };
        let Some(advertisement) = Advertisement::decode(&buf[..len]) else {
            continue;
        };
        if advertisement.major_version != LINK_VERSION_MAJOR
            || advertisement.minor_version != LINK_VERSION_MINOR
        {
            trace!(
                major = advertisement.major_version,
                minor = advertisement.minor_version,
                "multicast: incompatible beacon version"
            );
            continue;
        }
        if advertisement.public_key == *inner.key().as_bytes() {
            continue;
        }
        let Some(peer_key) = public_key_from_bytes(&advertisement.public_key) else {
            debug!(
                key = %crate::config::hex(&advertisement.public_key),
                "multicast: ignoring invalid or weak peer key"
            );
            continue;
        };
        if inner.node().peer_keys().contains(&peer_key) {
            continue;
        }
        let Some(interface) = find_listening_interface(interfaces.as_ref(), from.scope_id()).await
        else {
            continue;
        };
        if auth_hash(&advertisement.public_key, &interface.password) != advertisement.hash {
            debug!(
                from = %from,
                interface = %interface.name,
                "multicast: auth hash mismatch"
            );
            continue;
        }

        {
            let mut pending = in_progress.lock().await;
            if !pending.insert(peer_key) {
                continue;
            }
        }

        let address = SocketAddrV6::new(*from.ip(), advertisement.port, 0, from.scope_id());
        info!(
            peer = %crate::config::hex(&advertisement.public_key),
            interface = %interface.name,
            %address,
            "multicast: discovered peer"
        );
        let inner = Arc::clone(&inner);
        let tls = Arc::clone(&tls);
        let pending = Arc::clone(&in_progress);
        let password = interface.password.clone();
        let priority = interface.priority;
        tokio::spawn(async move {
            if let Err(error) =
                connect_tls(&inner, &tls, address, peer_key, priority, &password).await
            {
                debug!(
                    peer = %crate::config::hex(peer_key.as_bytes()),
                    %address,
                    %error,
                    "multicast: connect failed"
                );
            }
            pending.lock().await.remove(&peer_key);
        });
    }
}

struct ListeningInterface {
    name: String,
    password: Vec<u8>,
    priority: u8,
}

async fn find_listening_interface(
    interfaces: &Mutex<HashMap<String, InterfaceState>>,
    scope_id: u32,
) -> Option<ListeningInterface> {
    interfaces
        .lock()
        .await
        .iter()
        .find(|(_, state)| state.index == scope_id && state.listen)
        .map(|(name, state)| ListeningInterface {
            name: name.clone(),
            password: state.password.clone(),
            priority: state.priority,
        })
}

// ── TLS link ─────────────────────────────────────────────────────────────

struct TlsConfigs {
    server: Arc<rustls::ServerConfig>,
    client: Arc<rustls::ClientConfig>,
}

impl TlsConfigs {
    fn new(secret: &SigningKey) -> io::Result<Self> {
        let (certificate, private_key) = self_signed(secret)?;
        let certificates = vec![certificate];
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
            .map_err(io::Error::other)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
            .with_client_auth_cert(certificates.clone(), private_key.clone_key())
            .map_err(io::Error::other)?;
        let server = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_client_cert_verifier(Arc::new(AcceptAnyClient))
            .with_single_cert(certificates, private_key)
            .map_err(io::Error::other)?;
        Ok(Self {
            server: Arc::new(server),
            client: Arc::new(client),
        })
    }
}

/// TLS здесь только шифрует канал. Подлинность пира проверяет
/// `meta`-handshake yggdrasil по ed25519-ключу.
#[derive(Debug)]
struct AcceptAnyServer;

impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        supported_schemes()
    }
}

#[derive(Debug)]
struct AcceptAnyClient;

impl ClientCertVerifier for AcceptAnyClient {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        supported_schemes()
    }
}

pub(crate) fn supported_schemes() -> Vec<SignatureScheme> {
    vec![
        SignatureScheme::ED25519,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP521_SHA512,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
    ]
}

fn self_signed(
    secret: &SigningKey,
) -> io::Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let pkcs8 = ed25519_pkcs8(&secret.to_bytes());
    let key_pair =
        KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(pkcs8), &PKCS_ED25519)
            .map_err(|error| io::Error::other(format!("rcgen key: {error}")))?;
    let mut params = CertificateParams::default();
    params.distinguished_name.push(
        DnType::CommonName,
        crate::config::hex(secret.verifying_key().as_bytes()),
    );
    let certificate = params
        .self_signed(&key_pair)
        .map_err(|error| io::Error::other(format!("rcgen certificate: {error}")))?;
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    Ok((certificate.der().clone(), private_key))
}

/// PKCS#8 v1 для Ed25519 из 32-байтового seed.
fn ed25519_pkcs8(seed: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&[
        0x30, 0x2e, // SEQUENCE
        0x02, 0x01, 0x00, // version
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // Ed25519 OID
        0x04, 0x22, 0x04, 0x20, // OCTET STRING -> OCTET STRING
    ]);
    out.extend_from_slice(seed);
    out
}

struct BeaconListenerConfig {
    bind: Ipv6Addr,
    port: u16,
    scope_id: u32,
    priority: u8,
    password: Vec<u8>,
}

async fn start_tls_listener(
    inner: Arc<Inner>,
    tls: Arc<TlsConfigs>,
    cancel: CancellationToken,
    config: BeaconListenerConfig,
) -> io::Result<(u16, CancellationToken, JoinHandle<()>)> {
    let listener = TcpListener::bind(SocketAddrV6::new(
        config.bind,
        config.port,
        0,
        config.scope_id,
    ))
    .await?;
    let actual_port = listener.local_addr()?.port();
    let acceptor = TlsAcceptor::from(Arc::clone(&tls.server));
    let listener_cancel = cancel.child_token();
    let task_cancel = listener_cancel.clone();
    let password = config.password;
    let priority = config.priority;
    let handle = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                () = task_cancel.cancelled() => break,
                result = listener.accept() => result,
            };
            let (stream, peer) = match accepted {
                Ok(value) => value,
                Err(error) => {
                    if task_cancel.is_cancelled() {
                        break;
                    }
                    debug!(%error, "multicast: listener accept error");
                    sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let password = password.clone();
            let cancel = task_cancel.clone();
            let inner = Arc::clone(&inner);
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let tls_stream = tokio::select! {
                    () = cancel.cancelled() => return,
                    result = acceptor.accept(stream) => result,
                };
                let Ok(mut tls_stream) = tls_stream else {
                    debug!(%peer, "multicast: TLS accept failed");
                    return;
                };
                let result = timeout(
                    CONNECT_TIMEOUT,
                    handshake_async(&mut tls_stream, inner.secret(), &password, priority),
                )
                .await;
                let Ok(Ok(meta)) = result else {
                    debug!(%peer, "multicast: handshake failed");
                    return;
                };
                if meta.public_key == inner.key() {
                    debug!(%peer, "multicast: rejected self-connection");
                    return;
                }
                debug!(
                    peer = %crate::config::hex(meta.public_key.as_bytes()),
                    %peer,
                    "multicast: inbound TLS peer connected"
                );
                let _ = spawn_conn(
                    Arc::clone(inner.node()),
                    meta.public_key,
                    Box::new(tls_stream),
                    priority,
                )
                .await;
            });
        }
    });
    Ok((actual_port, listener_cancel, handle))
}

async fn connect_tls(
    inner: &Arc<Inner>,
    tls: &TlsConfigs,
    address: SocketAddrV6,
    expected: PublicKey,
    priority: u8,
    password: &[u8],
) -> io::Result<()> {
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "multicast TCP connect timed out")
        })??;
    stream.set_nodelay(true)?;
    let server_name = rustls::pki_types::ServerName::IpAddress(IpAddr::V6(*address.ip()).into());
    let connector = TlsConnector::from(Arc::clone(&tls.client));
    let mut stream = timeout(CONNECT_TIMEOUT, connector.connect(server_name, stream))
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "multicast TLS connect timed out")
        })??;
    let meta = timeout(
        CONNECT_TIMEOUT,
        handshake_async(&mut stream, inner.secret(), password, priority),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "multicast handshake timed out"))??;
    if meta.public_key != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "multicast peer key does not match beacon",
        ));
    }
    let node = Arc::clone(inner.node());
    tokio::spawn(async move {
        let _ = spawn_conn(node, expected, Box::new(stream), priority).await;
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertisement_roundtrip() {
        let advertisement = Advertisement {
            major_version: LINK_VERSION_MAJOR,
            minor_version: LINK_VERSION_MINOR,
            public_key: [7u8; 32],
            port: 4242,
            hash: vec![9u8; 64],
        };
        let encoded = advertisement.encode();
        assert_eq!(encoded.len(), ADVERTISEMENT_HEADER + 64);
        assert_eq!(Advertisement::decode(&encoded), Some(advertisement));
    }

    #[test]
    fn advertisement_rejects_truncated_hash() {
        let advertisement = Advertisement {
            major_version: LINK_VERSION_MAJOR,
            minor_version: LINK_VERSION_MINOR,
            public_key: [7u8; 32],
            port: 4242,
            hash: vec![9u8; 64],
        };
        let mut encoded = advertisement.encode();
        encoded.pop();
        assert_eq!(Advertisement::decode(&encoded), None);
    }

    #[test]
    fn advertisement_rejects_short_packet() {
        assert_eq!(Advertisement::decode(&[0u8; 39]), None);
    }

    #[test]
    fn auth_hash_depends_on_password() {
        let key = [3u8; 32];
        let open = auth_hash(&key, &[]);
        let secret = auth_hash(&key, b"secret");
        assert_eq!(open.len(), 64);
        assert_eq!(secret.len(), 64);
        assert_ne!(open, secret);
        assert_eq!(open, auth_hash(&key, &[]));
    }

    #[test]
    fn tls_configs_build() {
        let secret = SigningKey::from_bytes(&[5u8; 32]);
        TlsConfigs::new(&secret).expect("TLS configs");
    }
}
