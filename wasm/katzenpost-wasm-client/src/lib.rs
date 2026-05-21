use aes::Aes256;
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use ctr::cipher::{KeyIvInit, StreamCipher};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Deserializer, Serialize};
use serde_bytes::ByteBuf;
use sha2::Sha256;
use std::collections::BTreeMap;
use thiserror::Error;
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};

const CERT_VERSION: u32 = 0;
const ED25519_PUBLIC_KEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;
const WEBTRANSPORT_TRANSPORT: &str = "webtransport";

const NODE_ID_LEN: usize = 32;
const X25519_PUBLIC_KEY_LEN: usize = 32;
const RECIPIENT_ID_LEN: usize = 32;
const SURB_ID_LEN: usize = 16;
const MAC_LEN: usize = 32;
const SURB_REPLY_LEN: usize = 1 + SURB_ID_LEN;
const PACKET_LEN: usize = 3082;
const NR_HOPS: usize = 5;
const HEADER_LEN: usize = 476;
const ROUTING_INFO_LEN: usize = 410;
const PER_HOP_ROUTING_INFO_LEN: usize = 82;
const SURB_LEN: usize = 572;
const KEM_X25519_NAME: &str = "x25519";
const KEM_X25519_CIPHERTEXT_LEN: usize = 32;
const KEM_X25519_PER_HOP_ROUTING_INFO_LEN: usize =
    NEXT_NODE_HOP_LEN + SURB_REPLY_LEN + KEM_X25519_CIPHERTEXT_LEN;
const KEM_X25519_ROUTING_INFO_LEN: usize = KEM_X25519_PER_HOP_ROUTING_INFO_LEN * NR_HOPS;
const KEM_X25519_HEADER_LEN: usize =
    SPHINX_PLAINTEXT_HEADER_LEN + KEM_X25519_CIPHERTEXT_LEN + KEM_X25519_ROUTING_INFO_LEN + MAC_LEN;
const KEM_X25519_SURB_LEN: usize =
    KEM_X25519_HEADER_LEN + NODE_ID_LEN + SPRP_KEY_LEN + STREAM_IV_LEN;
const KEM_X25519_FORWARD_PAYLOAD_LEN: usize =
    USER_FORWARD_PAYLOAD_LEN + SPHINX_PLAINTEXT_HEADER_LEN + KEM_X25519_SURB_LEN;
const KEM_X25519_PACKET_LEN: usize =
    KEM_X25519_HEADER_LEN + PAYLOAD_TAG_LEN + KEM_X25519_FORWARD_PAYLOAD_LEN;
const SPHINX_PLAINTEXT_HEADER_LEN: usize = 2;
const PAYLOAD_TAG_LEN: usize = 32;
const FORWARD_PAYLOAD_LEN: usize = 2574;
const USER_FORWARD_PAYLOAD_LEN: usize = 2000;
const NEXT_NODE_HOP_LEN: usize = 65;
const SPRP_KEY_LEN: usize = 48;
const STREAM_IV_LEN: usize = 16;
const NODE_DELAY_COMMAND: u8 = 0x80;
const NEXT_NODE_HOP_COMMAND: u8 = 0x01;
const RECIPIENT_COMMAND: u8 = 0x02;
const KDF_INFO: &[u8] = b"katzenpost-kdf-v0-hkdf-sha256";
const V0_AD: [u8; 2] = [0, 0];

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("CBOR decode failed: {0}")]
    Cbor(#[from] serde_cbor::Error),
    #[error("signature threshold is larger than trust anchor count")]
    InvalidThreshold,
    #[error("certificate version mismatch")]
    Version,
    #[error("certificate expired")]
    Expired,
    #[error("certificate key type {0:?} is not Ed25519")]
    KeyType(String),
    #[error("trust anchor length must be a multiple of 32 bytes")]
    TrustAnchorLength,
    #[error("invalid Ed25519 public key")]
    PublicKey,
    #[error("invalid Ed25519 signature")]
    Signature,
    #[error("signature threshold not met")]
    ThresholdNotMet,
    #[error("consensus epoch is stale")]
    Stale,
    #[error("consensus epoch is too far in the future")]
    Future,
}

#[derive(Debug, Error)]
pub enum PacketBuildError {
    #[error(transparent)]
    Consensus(#[from] ConsensusError),
    #[error("CBOR decode failed: {0}")]
    Cbor(#[from] serde_cbor::Error),
    #[error("consensus does not contain a WebTransport gateway for {0}")]
    GatewayNotFound(String),
    #[error("consensus does not contain service capability {0}")]
    ServiceNotFound(String),
    #[error("consensus topology has no mix layers")]
    EmptyTopology,
    #[error("consensus topology layer {0} has no nodes")]
    EmptyTopologyLayer(usize),
    #[error("selected path has {0} hops but MVP3 geometry supports at most {NR_HOPS}")]
    PathTooLong(usize),
    #[error("unsupported KEMSphinx scheme {0:?}; this MVP supports x25519 KEM adapter")]
    UnsupportedKem(String),
    #[error("descriptor {0} has no identity key")]
    MissingIdentityKey(String),
    #[error("descriptor {0} has no mix key for epoch {1}")]
    MissingMixKey(String, u64),
    #[error("descriptor {0} has invalid X25519 public key length {1}")]
    InvalidMixKey(String, usize),
    #[error("recipient endpoint is longer than {RECIPIENT_ID_LEN} bytes")]
    RecipientTooLong,
    #[error("payload is larger than {USER_FORWARD_PAYLOAD_LEN} bytes")]
    PayloadTooLong,
    #[error("routing commands overflow per-hop routing info")]
    RoutingCommandOverflow,
    #[error("random source failed: {0}")]
    Random(String),
    #[error("HKDF failed")]
    Hkdf,
    #[error("SURB length mismatch")]
    SurbLength,
    #[error("SURB decryption keys are invalid")]
    InvalidSurbKeys,
    #[error("SURB reply payload is truncated")]
    TruncatedSurbReply,
    #[error("SURB reply payload tag is invalid")]
    InvalidSurbPayloadTag,
    #[error("SURB payload decrypt failed")]
    SurbPayloadDecrypt,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Certificate {
    version: u32,
    expiration: u64,
    key_type: String,
    #[serde(with = "serde_bytes")]
    certified: Vec<u8>,
    signatures: BTreeMap<ByteBuf, CertificateSignature>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CertificateSignature {
    public_key_sum256: ByteBuf,
    payload: ByteBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Document {
    epoch: u64,
    #[serde(default)]
    topology: Vec<Vec<DescriptorEntry>>,
    gateway_nodes: Vec<DescriptorEntry>,
    #[serde(default)]
    service_nodes: Vec<DescriptorEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum DescriptorEntry {
    Encoded(ByteBuf),
    Inline(MixDescriptor),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MixDescriptor {
    name: String,
    #[serde(default, with = "serde_bytes")]
    identity_key: Vec<u8>,
    #[serde(default)]
    mix_keys: BTreeMap<u64, ByteBuf>,
    addresses: BTreeMap<String, Vec<String>>,
    #[serde(default, deserialize_with = "null_to_default")]
    kaetzchen: BTreeMap<String, BTreeMap<String, serde_cbor::Value>>,
    is_gateway_node: bool,
    #[serde(default)]
    is_service_node: bool,
}

#[derive(Debug, Serialize)]
pub struct VerifiedConsensus {
    pub epoch: u64,
    pub expiration: u64,
    pub signatures_verified: usize,
    pub webtransport_gateways: Vec<WebTransportGateway>,
}

#[derive(Debug, Serialize)]
pub struct WebTransportGateway {
    pub name: String,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ConsensusCheck {
    pub state: String,
    pub error: Option<String>,
    pub consensus: Option<VerifiedConsensus>,
}

#[derive(Debug, Serialize)]
pub struct SphinxPacketWithSURB {
    #[serde(with = "serde_bytes")]
    pub packet: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub recipient: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub surb_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub surb_keys: Vec<u8>,
}

fn blake2b_256(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = Blake2bVar::new(32).expect("32-byte BLAKE2b output is valid");
    hasher.update(input);
    hasher
        .finalize_variable(&mut out)
        .expect("output buffer has the requested BLAKE2b length");
    out
}

fn null_to_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn certificate_message(cert: &Certificate) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + cert.key_type.len() + cert.certified.len());
    out.extend_from_slice(&cert.version.to_le_bytes());
    out.extend_from_slice(&cert.expiration.to_le_bytes());
    out.extend_from_slice(cert.key_type.as_bytes());
    out.extend_from_slice(&cert.certified);
    out
}

fn parse_trust_anchors(raw: &[u8]) -> Result<Vec<VerifyingKey>, ConsensusError> {
    if raw.len() % ED25519_PUBLIC_KEY_LEN != 0 {
        return Err(ConsensusError::TrustAnchorLength);
    }
    raw.chunks_exact(ED25519_PUBLIC_KEY_LEN)
        .map(|chunk| {
            let mut key = [0u8; ED25519_PUBLIC_KEY_LEN];
            key.copy_from_slice(chunk);
            VerifyingKey::from_bytes(&key).map_err(|_| ConsensusError::PublicKey)
        })
        .collect()
}

fn verify_certificate(
    raw: &[u8],
    trust_anchors: &[u8],
    threshold: usize,
    current_epoch: u64,
    max_future_epochs: u64,
) -> Result<(Certificate, Document, usize), ConsensusError> {
    let cert: Certificate = serde_cbor::from_slice(raw)?;
    if cert.version != CERT_VERSION {
        return Err(ConsensusError::Version);
    }
    if current_epoch >= cert.expiration {
        return Err(ConsensusError::Expired);
    }
    if !cert.key_type.eq_ignore_ascii_case("ed25519") {
        return Err(ConsensusError::KeyType(cert.key_type.clone()));
    }

    let anchors = parse_trust_anchors(trust_anchors)?;
    if threshold > anchors.len() {
        return Err(ConsensusError::InvalidThreshold);
    }
    let message = certificate_message(&cert);

    let mut good = 0usize;
    for anchor in anchors {
        let key_hash = blake2b_256(anchor.as_bytes());
        let Some(sig) = cert
            .signatures
            .values()
            .find(|sig| sig.public_key_sum256.as_slice() == key_hash)
        else {
            continue;
        };
        if sig.payload.len() != ED25519_SIGNATURE_LEN {
            return Err(ConsensusError::Signature);
        }
        let signature =
            Signature::from_slice(sig.payload.as_slice()).map_err(|_| ConsensusError::Signature)?;
        if anchor.verify(&message, &signature).is_ok() {
            good += 1;
        }
    }
    if good < threshold {
        return Err(ConsensusError::ThresholdNotMet);
    }

    let doc: Document = serde_cbor::from_slice(&cert.certified)?;
    if doc.epoch < current_epoch {
        return Err(ConsensusError::Stale);
    }
    if doc.epoch > current_epoch.saturating_add(max_future_epochs) {
        return Err(ConsensusError::Future);
    }
    Ok((cert, doc, good))
}

pub fn verify_consensus_bytes(
    raw: &[u8],
    trust_anchors: &[u8],
    threshold: usize,
    current_epoch: u64,
    max_future_epochs: u64,
) -> Result<VerifiedConsensus, ConsensusError> {
    let (cert, doc, signatures_verified) = verify_certificate(
        raw,
        trust_anchors,
        threshold,
        current_epoch,
        max_future_epochs,
    )?;
    let mut webtransport_gateways = Vec::new();
    for gateway in doc.gateway_nodes {
        let gateway = match gateway {
            DescriptorEntry::Encoded(encoded) => serde_cbor::from_slice(encoded.as_slice())?,
            DescriptorEntry::Inline(gateway) => gateway,
        };
        if !gateway.is_gateway_node {
            continue;
        }
        let Some(endpoints) = gateway.addresses.get(WEBTRANSPORT_TRANSPORT) else {
            continue;
        };
        if endpoints.is_empty() {
            continue;
        }
        webtransport_gateways.push(WebTransportGateway {
            name: gateway.name,
            endpoints: endpoints.clone(),
        });
    }

    Ok(VerifiedConsensus {
        epoch: doc.epoch,
        expiration: cert.expiration,
        signatures_verified,
        webtransport_gateways,
    })
}

#[wasm_bindgen]
pub fn verify_consensus(
    raw_consensus: &[u8],
    ed25519_trust_anchors: &[u8],
    threshold: usize,
    current_epoch: u64,
    max_future_epochs: u64,
) -> Result<JsValue, JsValue> {
    let verified = verify_consensus_bytes(
        raw_consensus,
        ed25519_trust_anchors,
        threshold,
        current_epoch,
        max_future_epochs,
    )
    .map_err(|err| JsValue::from_str(&err.to_string()))?;
    serde_wasm_bindgen::to_value(&verified).map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn check_consensus(
    raw_consensus: &[u8],
    ed25519_trust_anchors: &[u8],
    threshold: usize,
    current_epoch: u64,
    max_future_epochs: u64,
) -> Result<JsValue, JsValue> {
    let check = match verify_consensus_bytes(
        raw_consensus,
        ed25519_trust_anchors,
        threshold,
        current_epoch,
        max_future_epochs,
    ) {
        Ok(consensus) => ConsensusCheck {
            state: "valid".to_string(),
            error: None,
            consensus: Some(consensus),
        },
        Err(err @ (ConsensusError::Stale | ConsensusError::Expired)) => ConsensusCheck {
            state: "stale".to_string(),
            error: Some(err.to_string()),
            consensus: None,
        },
        Err(err) => ConsensusCheck {
            state: "invalid".to_string(),
            error: Some(err.to_string()),
            consensus: None,
        },
    };
    serde_wasm_bindgen::to_value(&check).map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn encode_get_consensus2(epoch: u64, padded_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; padded_len.max(14)];
    out[0] = 32;
    out[2..6].copy_from_slice(&(8u32).to_be_bytes());
    out[6..14].copy_from_slice(&epoch.to_be_bytes());
    out
}

#[derive(Clone)]
struct PathHop {
    id: [u8; NODE_ID_LEN],
    public_key: [u8; X25519_PUBLIC_KEY_LEN],
    commands: Vec<RoutingCommand>,
}

#[derive(Clone)]
enum RoutingCommand {
    NodeDelay(u32),
    Recipient([u8; RECIPIENT_ID_LEN]),
    SurbReply([u8; SURB_ID_LEN]),
}

#[derive(Clone, Copy)]
struct SphinxGeometry {
    packet_len: usize,
    header_len: usize,
    routing_info_len: usize,
    per_hop_routing_info_len: usize,
    surb_len: usize,
    forward_payload_len: usize,
}

const NIKE_X25519_GEOMETRY: SphinxGeometry = SphinxGeometry {
    packet_len: PACKET_LEN,
    header_len: HEADER_LEN,
    routing_info_len: ROUTING_INFO_LEN,
    per_hop_routing_info_len: PER_HOP_ROUTING_INFO_LEN,
    surb_len: SURB_LEN,
    forward_payload_len: FORWARD_PAYLOAD_LEN,
};

const KEM_X25519_GEOMETRY: SphinxGeometry = SphinxGeometry {
    packet_len: KEM_X25519_PACKET_LEN,
    header_len: KEM_X25519_HEADER_LEN,
    routing_info_len: KEM_X25519_ROUTING_INFO_LEN,
    per_hop_routing_info_len: KEM_X25519_PER_HOP_ROUTING_INFO_LEN,
    surb_len: KEM_X25519_SURB_LEN,
    forward_payload_len: KEM_X25519_FORWARD_PAYLOAD_LEN,
};

struct PacketKeys {
    header_mac: [u8; MAC_LEN],
    header_encryption: [u8; 32],
    header_encryption_iv: [u8; STREAM_IV_LEN],
    payload_encryption: [u8; SPRP_KEY_LEN],
    blinding_factor: [u8; 32],
}

fn decode_descriptor(entry: &DescriptorEntry) -> Result<MixDescriptor, serde_cbor::Error> {
    match entry {
        DescriptorEntry::Encoded(encoded) => serde_cbor::from_slice(encoded.as_slice()),
        DescriptorEntry::Inline(desc) => Ok(desc.clone()),
    }
}

fn endpoint_param(params: &BTreeMap<String, serde_cbor::Value>) -> Option<String> {
    let value = params.get("endpoint")?;
    match value {
        serde_cbor::Value::Text(s) => Some(s.clone()),
        serde_cbor::Value::Bytes(b) => String::from_utf8(b.clone()).ok(),
        _ => None,
    }
}

fn service_endpoint(desc: &MixDescriptor, capability: &str) -> Option<String> {
    let capability = capability.trim_start_matches('+');
    if let Some(params) = desc.kaetzchen.get(capability) {
        return endpoint_param(params).or_else(|| Some(format!("+{capability}")));
    }
    if capability.starts_with('+') {
        for params in desc.kaetzchen.values() {
            if endpoint_param(params).as_deref() == Some(capability) {
                return Some(capability.to_string());
            }
        }
    }
    None
}

fn descriptor_id(desc: &MixDescriptor) -> Result<[u8; NODE_ID_LEN], PacketBuildError> {
    if desc.identity_key.is_empty() {
        return Err(PacketBuildError::MissingIdentityKey(desc.name.clone()));
    }
    Ok(blake2b_256(&desc.identity_key))
}

fn descriptor_mix_key(
    desc: &MixDescriptor,
    epoch: u64,
) -> Result<[u8; X25519_PUBLIC_KEY_LEN], PacketBuildError> {
    let key = desc
        .mix_keys
        .get(&epoch)
        .ok_or_else(|| PacketBuildError::MissingMixKey(desc.name.clone(), epoch))?;
    if key.len() != X25519_PUBLIC_KEY_LEN {
        return Err(PacketBuildError::InvalidMixKey(
            desc.name.clone(),
            key.len(),
        ));
    }
    let mut out = [0u8; X25519_PUBLIC_KEY_LEN];
    out.copy_from_slice(key.as_slice());
    Ok(out)
}

fn hop_from_descriptor(
    desc: &MixDescriptor,
    epoch: u64,
    commands: Vec<RoutingCommand>,
) -> Result<PathHop, PacketBuildError> {
    Ok(PathHop {
        id: descriptor_id(desc)?,
        public_key: descriptor_mix_key(desc, epoch)?,
        commands,
    })
}

fn select_mvp3_path(
    doc: &Document,
    gateway_endpoint: &str,
    service_capability: &str,
) -> Result<(Vec<PathHop>, String), PacketBuildError> {
    let mut selected_gateway = None;
    for entry in &doc.gateway_nodes {
        let desc = decode_descriptor(entry)?;
        if !desc.is_gateway_node {
            continue;
        }
        let endpoints = desc
            .addresses
            .get(WEBTRANSPORT_TRANSPORT)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let endpoint_matches = gateway_endpoint.is_empty()
            || endpoints
                .iter()
                .any(|endpoint| endpoint == gateway_endpoint);
        if endpoint_matches {
            selected_gateway = Some(desc);
            break;
        }
    }
    let gateway = selected_gateway
        .ok_or_else(|| PacketBuildError::GatewayNotFound(gateway_endpoint.to_string()))?;

    if doc.topology.is_empty() {
        return Err(PacketBuildError::EmptyTopology);
    }

    let mut service_and_endpoint = None;
    for entry in &doc.service_nodes {
        let desc = decode_descriptor(entry)?;
        if !desc.is_service_node {
            continue;
        }
        if let Some(endpoint) = service_endpoint(&desc, service_capability) {
            service_and_endpoint = Some((desc, endpoint));
            break;
        }
    }
    let (service, endpoint) = service_and_endpoint
        .ok_or_else(|| PacketBuildError::ServiceNotFound(service_capability.to_string()))?;

    let mut path = Vec::with_capacity(doc.topology.len() + 2);
    path.push(hop_from_descriptor(
        &gateway,
        doc.epoch,
        vec![RoutingCommand::NodeDelay(1)],
    )?);
    for (layer_idx, layer) in doc.topology.iter().enumerate() {
        let first = layer
            .first()
            .ok_or(PacketBuildError::EmptyTopologyLayer(layer_idx))?;
        let desc = decode_descriptor(first)?;
        path.push(hop_from_descriptor(
            &desc,
            doc.epoch,
            vec![RoutingCommand::NodeDelay(1)],
        )?);
    }

    let mut recipient = [0u8; RECIPIENT_ID_LEN];
    let endpoint_bytes = endpoint.as_bytes();
    if endpoint_bytes.len() > recipient.len() {
        return Err(PacketBuildError::RecipientTooLong);
    }
    recipient[..endpoint_bytes.len()].copy_from_slice(endpoint_bytes);
    path.push(hop_from_descriptor(
        &service,
        doc.epoch,
        vec![RoutingCommand::Recipient(recipient)],
    )?);

    if path.len() > NR_HOPS {
        return Err(PacketBuildError::PathTooLong(path.len()));
    }

    Ok((path, endpoint))
}

fn select_reply_path(
    doc: &Document,
    gateway_endpoint: &str,
    recipient: [u8; RECIPIENT_ID_LEN],
    surb_id: [u8; SURB_ID_LEN],
) -> Result<Vec<PathHop>, PacketBuildError> {
    let mut selected_gateway = None;
    for entry in &doc.gateway_nodes {
        let desc = decode_descriptor(entry)?;
        if !desc.is_gateway_node {
            continue;
        }
        let endpoints = desc
            .addresses
            .get(WEBTRANSPORT_TRANSPORT)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let endpoint_matches = gateway_endpoint.is_empty()
            || endpoints
                .iter()
                .any(|endpoint| endpoint == gateway_endpoint);
        if endpoint_matches {
            selected_gateway = Some(desc);
            break;
        }
    }
    let gateway = selected_gateway
        .ok_or_else(|| PacketBuildError::GatewayNotFound(gateway_endpoint.to_string()))?;

    let mut path = Vec::with_capacity(doc.topology.len() + 1);
    for (layer_idx, layer) in doc.topology.iter().enumerate() {
        let first = layer
            .first()
            .ok_or(PacketBuildError::EmptyTopologyLayer(layer_idx))?;
        let desc = decode_descriptor(first)?;
        path.push(hop_from_descriptor(
            &desc,
            doc.epoch,
            vec![RoutingCommand::NodeDelay(1)],
        )?);
    }
    path.push(hop_from_descriptor(
        &gateway,
        doc.epoch,
        vec![
            RoutingCommand::Recipient(recipient),
            RoutingCommand::SurbReply(surb_id),
        ],
    )?);

    if path.len() > NR_HOPS {
        return Err(PacketBuildError::PathTooLong(path.len()));
    }
    Ok(path)
}

fn service_forward_payload_for(
    geometry: SphinxGeometry,
    user_payload: &[u8],
) -> Result<Vec<u8>, PacketBuildError> {
    if user_payload.len() > USER_FORWARD_PAYLOAD_LEN {
        return Err(PacketBuildError::PayloadTooLong);
    }
    let mut payload = vec![0u8; geometry.forward_payload_len];
    let user_offset = SPHINX_PLAINTEXT_HEADER_LEN + geometry.surb_len;
    payload[user_offset..user_offset + user_payload.len()].copy_from_slice(user_payload);
    Ok(payload)
}

fn service_forward_payload(user_payload: &[u8]) -> Result<Vec<u8>, PacketBuildError> {
    service_forward_payload_for(NIKE_X25519_GEOMETRY, user_payload)
}

fn service_forward_payload_with_surb_for(
    geometry: SphinxGeometry,
    user_payload: &[u8],
    surb: &[u8],
) -> Result<Vec<u8>, PacketBuildError> {
    if user_payload.len() > USER_FORWARD_PAYLOAD_LEN {
        return Err(PacketBuildError::PayloadTooLong);
    }
    if surb.len() != geometry.surb_len {
        return Err(PacketBuildError::SurbLength);
    }
    let mut payload = vec![0u8; geometry.forward_payload_len];
    payload[0] = 1;
    payload[SPHINX_PLAINTEXT_HEADER_LEN..SPHINX_PLAINTEXT_HEADER_LEN + geometry.surb_len]
        .copy_from_slice(surb);
    let user_offset = SPHINX_PLAINTEXT_HEADER_LEN + geometry.surb_len;
    payload[user_offset..user_offset + user_payload.len()].copy_from_slice(user_payload);
    Ok(payload)
}

fn service_forward_payload_with_surb(
    user_payload: &[u8],
    surb: &[u8],
) -> Result<Vec<u8>, PacketBuildError> {
    service_forward_payload_with_surb_for(NIKE_X25519_GEOMETRY, user_payload, surb)
}

fn serialize_commands(
    commands: &[RoutingCommand],
    is_terminal: bool,
    geometry: SphinxGeometry,
) -> Result<Vec<u8>, PacketBuildError> {
    let mut out = Vec::with_capacity(geometry.per_hop_routing_info_len);
    for command in commands {
        match command {
            RoutingCommand::NodeDelay(delay) => {
                out.push(NODE_DELAY_COMMAND);
                out.extend_from_slice(&delay.to_be_bytes());
            }
            RoutingCommand::Recipient(recipient) => {
                out.push(RECIPIENT_COMMAND);
                out.extend_from_slice(recipient);
            }
            RoutingCommand::SurbReply(surb_id) => {
                out.push(0x03);
                out.extend_from_slice(surb_id);
            }
        }
    }
    if out.len() > geometry.per_hop_routing_info_len {
        return Err(PacketBuildError::RoutingCommandOverflow);
    }
    if !is_terminal && geometry.per_hop_routing_info_len - out.len() < NEXT_NODE_HOP_LEN {
        return Err(PacketBuildError::RoutingCommandOverflow);
    }
    Ok(out)
}

fn xor_in_place(dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());
    for (a, b) in dst.iter_mut().zip(src.iter()) {
        *a ^= *b;
    }
}

fn aes_ctr_keystream(key: &[u8; 32], iv: &[u8; STREAM_IV_LEN], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut cipher = Aes256Ctr::new(key.into(), iv.into());
    cipher.apply_keystream(&mut out);
    out
}

fn hmac_sha256(key: &[u8; MAC_LEN], parts: &[&[u8]]) -> [u8; MAC_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts 32-byte keys");
    for part in parts {
        Mac::update(&mut mac, part);
    }
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&tag);
    out
}

fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

fn deterministic_chacha20_first_32(key: &[u8; 32]) -> [u8; 32] {
    let mut initial = [0u32; 16];
    initial[0] = 0x6170_7865;
    initial[1] = 0x3320_646e;
    initial[2] = 0x7962_2d32;
    initial[3] = 0x6b20_6574;
    for (idx, chunk) in key.chunks_exact(4).enumerate() {
        initial[4 + idx] = u32::from_le_bytes(chunk.try_into().expect("chunk size is 4"));
    }
    // Katzenpost's deterministic reader uses original ChaCha20 with an all-zero 64-bit counter
    // and all-zero 64-bit nonce, so state words 12..15 remain zero here.
    let mut working = initial;
    for _ in 0..10 {
        chacha20_quarter_round(&mut working, 0, 4, 8, 12);
        chacha20_quarter_round(&mut working, 1, 5, 9, 13);
        chacha20_quarter_round(&mut working, 2, 6, 10, 14);
        chacha20_quarter_round(&mut working, 3, 7, 11, 15);
        chacha20_quarter_round(&mut working, 0, 5, 10, 15);
        chacha20_quarter_round(&mut working, 1, 6, 11, 12);
        chacha20_quarter_round(&mut working, 2, 7, 8, 13);
        chacha20_quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 32];
    for idx in 0..8 {
        out[idx * 4..idx * 4 + 4]
            .copy_from_slice(&working[idx].wrapping_add(initial[idx]).to_le_bytes());
    }
    out
}

fn derive_packet_keys(shared_secret: &[u8; 32]) -> Result<PacketKeys, PacketBuildError> {
    let mut okm = [0u8; MAC_LEN + 32 + STREAM_IV_LEN + SPRP_KEY_LEN + 32];
    let hk = Hkdf::<Sha256>::from_prk(shared_secret).map_err(|_| PacketBuildError::Hkdf)?;
    hk.expand(KDF_INFO, &mut okm)
        .map_err(|_| PacketBuildError::Hkdf)?;

    let mut header_mac = [0u8; MAC_LEN];
    let mut header_encryption = [0u8; 32];
    let mut header_encryption_iv = [0u8; STREAM_IV_LEN];
    let mut payload_encryption = [0u8; SPRP_KEY_LEN];
    let mut seed = [0u8; 32];
    let mut cursor = 0usize;
    header_mac.copy_from_slice(&okm[cursor..cursor + MAC_LEN]);
    cursor += MAC_LEN;
    header_encryption.copy_from_slice(&okm[cursor..cursor + 32]);
    cursor += 32;
    header_encryption_iv.copy_from_slice(&okm[cursor..cursor + STREAM_IV_LEN]);
    cursor += STREAM_IV_LEN;
    payload_encryption.copy_from_slice(&okm[cursor..cursor + SPRP_KEY_LEN]);
    cursor += SPRP_KEY_LEN;
    seed.copy_from_slice(&okm[cursor..cursor + 32]);

    Ok(PacketKeys {
        header_mac,
        header_encryption,
        header_encryption_iv,
        payload_encryption,
        blinding_factor: deterministic_chacha20_first_32(&seed),
    })
}

fn x25519_public(bytes: &[u8; 32]) -> PublicKey {
    PublicKey::from(*bytes)
}

fn x25519_secret(bytes: &[u8; 32]) -> StaticSecret {
    StaticSecret::from(*bytes)
}

fn x25519_dh(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    x25519_secret(secret)
        .diffie_hellman(&x25519_public(public))
        .to_bytes()
}

fn blind_public(public: &[u8; 32], blinding_factor: &[u8; 32]) -> [u8; 32] {
    x25519_dh(blinding_factor, public)
}

const BLAKE2B_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const BLAKE2B_SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

fn blake2b_g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn blake2b_compress(h: &mut [u64; 8], block: &[u8; 128], t: u64, f0: u64) {
    let mut m = [0u64; 16];
    for (idx, chunk) in block.chunks_exact(8).enumerate() {
        m[idx] = u64::from_le_bytes(chunk.try_into().expect("BLAKE2b chunk is 8 bytes"));
    }

    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= t;
    v[14] ^= f0;

    for sigma in BLAKE2B_SIGMA {
        blake2b_g(&mut v, 0, 4, 8, 12, m[sigma[0]], m[sigma[1]]);
        blake2b_g(&mut v, 1, 5, 9, 13, m[sigma[2]], m[sigma[3]]);
        blake2b_g(&mut v, 2, 6, 10, 14, m[sigma[4]], m[sigma[5]]);
        blake2b_g(&mut v, 3, 7, 11, 15, m[sigma[6]], m[sigma[7]]);
        blake2b_g(&mut v, 0, 5, 10, 15, m[sigma[8]], m[sigma[9]]);
        blake2b_g(&mut v, 1, 6, 11, 12, m[sigma[10]], m[sigma[11]]);
        blake2b_g(&mut v, 2, 7, 8, 13, m[sigma[12]], m[sigma[13]]);
        blake2b_g(&mut v, 3, 4, 9, 14, m[sigma[14]], m[sigma[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

fn blake2b_hash_with_config(config: &[u8; 64], key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut h = BLAKE2B_IV;
    for (idx, chunk) in config.chunks_exact(8).enumerate() {
        h[idx] ^= u64::from_le_bytes(chunk.try_into().expect("BLAKE2b config word"));
    }

    let mut t = 0u64;
    if !key.is_empty() {
        let mut block = [0u8; 128];
        block[..key.len()].copy_from_slice(key);
        t = t.wrapping_add(128);
        if msg.is_empty() {
            blake2b_compress(&mut h, &block, t, u64::MAX);
            let mut out = [0u8; 64];
            for (idx, word) in h.iter().enumerate() {
                out[idx * 8..idx * 8 + 8].copy_from_slice(&word.to_le_bytes());
            }
            return out;
        }
        blake2b_compress(&mut h, &block, t, 0);
    }

    let mut remaining = msg;
    while remaining.len() > 128 {
        let mut block = [0u8; 128];
        block.copy_from_slice(&remaining[..128]);
        t = t.wrapping_add(128);
        blake2b_compress(&mut h, &block, t, 0);
        remaining = &remaining[128..];
    }

    let mut block = [0u8; 128];
    block[..remaining.len()].copy_from_slice(remaining);
    t = t.wrapping_add(remaining.len() as u64);
    blake2b_compress(&mut h, &block, t, u64::MAX);

    let mut out = [0u8; 64];
    for (idx, word) in h.iter().enumerate() {
        out[idx * 8..idx * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn blake2xb_xof_32(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut root_config = [0u8; 64];
    root_config[0] = 64;
    root_config[1] = key.len() as u8;
    root_config[2] = 1;
    root_config[3] = 1;
    root_config[12..16].copy_from_slice(&(32u32).to_le_bytes());
    let root = blake2b_hash_with_config(&root_config, key, msg);

    let mut block_config = [0u8; 64];
    block_config[0] = 32;
    block_config[4..8].copy_from_slice(&(64u32).to_le_bytes());
    block_config[8..12].copy_from_slice(&(0u32).to_le_bytes());
    block_config[12..16].copy_from_slice(&(32u32).to_le_bytes());
    block_config[17] = 64;
    let block = blake2b_hash_with_config(&block_config, &[], &root);

    let mut out = [0u8; 32];
    out.copy_from_slice(&block[..32]);
    out
}

fn kem_adapter_x25519_hash(
    shared_secret: &[u8; 32],
    recipient_public: &[u8; 32],
    ephemeral_public: &[u8; 32],
) -> [u8; 32] {
    let mut msg = [0u8; 64];
    msg[..32].copy_from_slice(recipient_public);
    msg[32..].copy_from_slice(ephemeral_public);
    blake2xb_xof_32(shared_secret, &msg)
}

fn kem_adapter_x25519_encapsulate(
    public_key: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), PacketBuildError> {
    let mut client_secret = [0u8; 32];
    getrandom::getrandom(&mut client_secret)
        .map_err(|err| PacketBuildError::Random(err.to_string()))?;
    let client_public = PublicKey::from(&StaticSecret::from(client_secret)).to_bytes();
    let shared_secret = x25519_dh(&client_secret, public_key);
    let kem_shared_secret = kem_adapter_x25519_hash(&shared_secret, public_key, &client_public);
    Ok((client_public, kem_shared_secret))
}

fn create_sphinx_header(
    path: &[PathHop],
) -> Result<(Vec<u8>, Vec<([u8; SPRP_KEY_LEN], [u8; STREAM_IV_LEN])>), PacketBuildError> {
    let nr_hops = path.len();
    if nr_hops == 0 || nr_hops > NR_HOPS {
        return Err(PacketBuildError::PathTooLong(nr_hops));
    }

    let mut client_secret = [0u8; 32];
    getrandom::getrandom(&mut client_secret)
        .map_err(|err| PacketBuildError::Random(err.to_string()))?;
    let mut client_public = PublicKey::from(&StaticSecret::from(client_secret)).to_bytes();

    let mut group_elements = vec![[0u8; 32]; nr_hops];
    let mut keys = Vec::with_capacity(nr_hops);

    let shared_secret = x25519_dh(&client_secret, &path[0].public_key);
    keys.push(derive_packet_keys(&shared_secret)?);
    group_elements[0] = client_public;

    for i in 1..nr_hops {
        let mut shared_secret = x25519_dh(&client_secret, &path[i].public_key);
        for previous_keys in keys.iter().take(i) {
            shared_secret = blind_public(&shared_secret, &previous_keys.blinding_factor);
        }
        keys.push(derive_packet_keys(&shared_secret)?);
        client_public = blind_public(&client_public, &keys[i - 1].blinding_factor);
        group_elements[i] = client_public;
    }

    let stream_len = ROUTING_INFO_LEN + PER_HOP_ROUTING_INFO_LEN;
    let mut ri_key_stream: Vec<Vec<u8>> = Vec::with_capacity(nr_hops);
    let mut ri_padding: Vec<Vec<u8>> = Vec::with_capacity(nr_hops);
    for i in 0..nr_hops {
        let key_stream = aes_ctr_keystream(
            &keys[i].header_encryption,
            &keys[i].header_encryption_iv,
            stream_len,
        );
        let ks_len = key_stream.len() - (i + 1) * PER_HOP_ROUTING_INFO_LEN;
        ri_key_stream.push(key_stream[..ks_len].to_vec());
        let mut padding = key_stream[ks_len..].to_vec();
        if i > 0 {
            let prev = &ri_padding[i - 1];
            xor_in_place(&mut padding[..prev.len()], prev);
        }
        ri_padding.push(padding);
    }

    let mut routing_info = Vec::new();
    let skipped_hops = NR_HOPS - nr_hops;
    if skipped_hops > 0 {
        routing_info.resize(skipped_hops * PER_HOP_ROUTING_INFO_LEN, 0);
        getrandom::getrandom(&mut routing_info)
            .map_err(|err| PacketBuildError::Random(err.to_string()))?;
    }

    let mut mac = [0u8; MAC_LEN];
    for i in (0..nr_hops).rev() {
        let is_terminal = i == nr_hops - 1;
        let mut fragment =
            serialize_commands(&path[i].commands, is_terminal, NIKE_X25519_GEOMETRY)?;
        if !is_terminal {
            fragment.push(NEXT_NODE_HOP_COMMAND);
            fragment.extend_from_slice(&path[i + 1].id);
            fragment.extend_from_slice(&mac);
        }
        fragment.resize(PER_HOP_ROUTING_INFO_LEN, 0);

        let mut next_routing_info = Vec::with_capacity(fragment.len() + routing_info.len());
        next_routing_info.extend_from_slice(&fragment);
        next_routing_info.extend_from_slice(&routing_info);
        routing_info = next_routing_info;
        xor_in_place(&mut routing_info, &ri_key_stream[i]);

        let mut mac_parts: Vec<&[u8]> = vec![&V0_AD, &group_elements[i], &routing_info];
        if i > 0 {
            mac_parts.push(&ri_padding[i - 1]);
        }
        mac = hmac_sha256(&keys[i].header_mac, &mac_parts);
    }

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&V0_AD);
    header.extend_from_slice(&group_elements[0]);
    header.extend_from_slice(&routing_info);
    header.extend_from_slice(&mac);
    debug_assert_eq!(header.len(), HEADER_LEN);

    let sprp_keys = keys
        .iter()
        .map(|key| (key.payload_encryption, key.header_encryption_iv))
        .collect();
    Ok((header, sprp_keys))
}

fn create_kemsphinx_x25519_header(
    path: &[PathHop],
) -> Result<(Vec<u8>, Vec<([u8; SPRP_KEY_LEN], [u8; STREAM_IV_LEN])>), PacketBuildError> {
    let nr_hops = path.len();
    if nr_hops == 0 || nr_hops > NR_HOPS {
        return Err(PacketBuildError::PathTooLong(nr_hops));
    }

    let geometry = KEM_X25519_GEOMETRY;
    let mut kem_elements = vec![[0u8; KEM_X25519_CIPHERTEXT_LEN]; nr_hops];
    let mut keys = Vec::with_capacity(nr_hops);

    for (idx, hop) in path.iter().enumerate() {
        let (ciphertext, shared_secret) = kem_adapter_x25519_encapsulate(&hop.public_key)?;
        kem_elements[idx] = ciphertext;
        keys.push(derive_packet_keys(&shared_secret)?);
    }

    let stream_len = geometry.routing_info_len + geometry.per_hop_routing_info_len;
    let mut ri_key_stream: Vec<Vec<u8>> = Vec::with_capacity(nr_hops);
    let mut ri_padding: Vec<Vec<u8>> = Vec::with_capacity(nr_hops);
    for i in 0..nr_hops {
        let key_stream = aes_ctr_keystream(
            &keys[i].header_encryption,
            &keys[i].header_encryption_iv,
            stream_len,
        );
        let ks_len = key_stream.len() - (i + 1) * geometry.per_hop_routing_info_len;
        ri_key_stream.push(key_stream[..ks_len].to_vec());
        let mut padding = key_stream[ks_len..].to_vec();
        if i > 0 {
            let prev = &ri_padding[i - 1];
            xor_in_place(&mut padding[..prev.len()], prev);
        }
        ri_padding.push(padding);
    }

    let mut routing_info = Vec::new();
    let skipped_hops = NR_HOPS - nr_hops;
    if skipped_hops > 0 {
        routing_info.resize(skipped_hops * geometry.per_hop_routing_info_len, 0);
        getrandom::getrandom(&mut routing_info)
            .map_err(|err| PacketBuildError::Random(err.to_string()))?;
    }

    let mut mac = [0u8; MAC_LEN];
    for i in (0..nr_hops).rev() {
        let is_terminal = i == nr_hops - 1;
        let mut fragment = serialize_commands(&path[i].commands, is_terminal, geometry)?;
        if !is_terminal {
            let kem_offset = geometry.per_hop_routing_info_len - KEM_X25519_CIPHERTEXT_LEN;
            if fragment.len() + NEXT_NODE_HOP_LEN > kem_offset {
                return Err(PacketBuildError::RoutingCommandOverflow);
            }
            fragment.push(NEXT_NODE_HOP_COMMAND);
            fragment.extend_from_slice(&path[i + 1].id);
            fragment.extend_from_slice(&mac);
        }
        fragment.resize(geometry.per_hop_routing_info_len, 0);
        if !is_terminal {
            let kem_offset = geometry.per_hop_routing_info_len - KEM_X25519_CIPHERTEXT_LEN;
            fragment[kem_offset..].copy_from_slice(&kem_elements[i + 1]);
        }

        let mut next_routing_info = Vec::with_capacity(fragment.len() + routing_info.len());
        next_routing_info.extend_from_slice(&fragment);
        next_routing_info.extend_from_slice(&routing_info);
        routing_info = next_routing_info;
        xor_in_place(&mut routing_info, &ri_key_stream[i]);

        let mut mac_parts: Vec<&[u8]> = vec![&V0_AD, &kem_elements[i], &routing_info];
        if i > 0 {
            mac_parts.push(&ri_padding[i - 1]);
        }
        mac = hmac_sha256(&keys[i].header_mac, &mac_parts);
    }

    let mut header = Vec::with_capacity(geometry.header_len);
    header.extend_from_slice(&V0_AD);
    header.extend_from_slice(&kem_elements[0]);
    header.extend_from_slice(&routing_info);
    header.extend_from_slice(&mac);
    debug_assert_eq!(header.len(), geometry.header_len);

    let sprp_keys = keys
        .iter()
        .map(|key| (key.payload_encryption, key.header_encryption_iv))
        .collect();
    Ok((header, sprp_keys))
}

fn new_sphinx_packet(path: &[PathHop], payload: Vec<u8>) -> Result<Vec<u8>, PacketBuildError> {
    let (header, sprp_keys) = create_sphinx_header(path)?;
    let mut encrypted_payload = Vec::with_capacity(PAYLOAD_TAG_LEN + payload.len());
    encrypted_payload.resize(PAYLOAD_TAG_LEN, 0);
    encrypted_payload.extend_from_slice(&payload);
    for (key, iv) in sprp_keys.iter().rev() {
        encrypted_payload = zears::Aez::new(key).encrypt(iv, &[], 0, &encrypted_payload);
    }

    let mut packet = Vec::with_capacity(PACKET_LEN);
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&encrypted_payload);
    debug_assert_eq!(packet.len(), PACKET_LEN);
    Ok(packet)
}

fn new_kemsphinx_x25519_packet(
    path: &[PathHop],
    payload: Vec<u8>,
) -> Result<Vec<u8>, PacketBuildError> {
    let geometry = KEM_X25519_GEOMETRY;
    if payload.len() != geometry.forward_payload_len {
        return Err(PacketBuildError::PayloadTooLong);
    }
    let (header, sprp_keys) = create_kemsphinx_x25519_header(path)?;
    let mut encrypted_payload = Vec::with_capacity(PAYLOAD_TAG_LEN + payload.len());
    encrypted_payload.resize(PAYLOAD_TAG_LEN, 0);
    encrypted_payload.extend_from_slice(&payload);
    for (key, iv) in sprp_keys.iter().rev() {
        encrypted_payload = zears::Aez::new(key).encrypt(iv, &[], 0, &encrypted_payload);
    }

    let mut packet = Vec::with_capacity(geometry.packet_len);
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&encrypted_payload);
    debug_assert_eq!(packet.len(), geometry.packet_len);
    Ok(packet)
}

fn new_surb(path: &[PathHop]) -> Result<(Vec<u8>, Vec<u8>), PacketBuildError> {
    let mut key_payload = [0u8; SPRP_KEY_LEN + STREAM_IV_LEN];
    getrandom::getrandom(&mut key_payload)
        .map_err(|err| PacketBuildError::Random(err.to_string()))?;

    let (header, sprp_keys) = create_sphinx_header(path)?;
    let mut surb_keys = Vec::with_capacity((path.len() + 1) * (SPRP_KEY_LEN + STREAM_IV_LEN));
    for (key, iv) in sprp_keys.iter().rev() {
        surb_keys.extend_from_slice(key);
        surb_keys.extend_from_slice(iv);
    }
    surb_keys.extend_from_slice(&key_payload);

    let mut surb = Vec::with_capacity(SURB_LEN);
    surb.extend_from_slice(&header);
    surb.extend_from_slice(&path[0].id);
    surb.extend_from_slice(&key_payload);
    debug_assert_eq!(surb.len(), SURB_LEN);

    Ok((surb, surb_keys))
}

fn new_kemsphinx_x25519_surb(path: &[PathHop]) -> Result<(Vec<u8>, Vec<u8>), PacketBuildError> {
    let geometry = KEM_X25519_GEOMETRY;
    let mut key_payload = [0u8; SPRP_KEY_LEN + STREAM_IV_LEN];
    getrandom::getrandom(&mut key_payload)
        .map_err(|err| PacketBuildError::Random(err.to_string()))?;

    let (header, sprp_keys) = create_kemsphinx_x25519_header(path)?;
    let mut surb_keys = Vec::with_capacity((path.len() + 1) * (SPRP_KEY_LEN + STREAM_IV_LEN));
    for (key, iv) in sprp_keys.iter().rev() {
        surb_keys.extend_from_slice(key);
        surb_keys.extend_from_slice(iv);
    }
    surb_keys.extend_from_slice(&key_payload);

    let mut surb = Vec::with_capacity(geometry.surb_len);
    surb.extend_from_slice(&header);
    surb.extend_from_slice(&path[0].id);
    surb.extend_from_slice(&key_payload);
    debug_assert_eq!(surb.len(), geometry.surb_len);

    Ok((surb, surb_keys))
}

fn decrypt_surb_reply_bytes(
    reply_payload: &[u8],
    surb_keys: &[u8],
) -> Result<Vec<u8>, PacketBuildError> {
    let key_material_len = SPRP_KEY_LEN + STREAM_IV_LEN;
    if surb_keys.is_empty() || surb_keys.len() % key_material_len != 0 {
        return Err(PacketBuildError::InvalidSurbKeys);
    }
    if reply_payload.len() < PAYLOAD_TAG_LEN {
        return Err(PacketBuildError::TruncatedSurbReply);
    }

    let nr_keys = surb_keys.len() / key_material_len;
    let mut payload = reply_payload.to_vec();
    for i in 0..nr_keys {
        let key_off = i * key_material_len;
        let iv_off = key_off + SPRP_KEY_LEN;
        let key = &surb_keys[key_off..iv_off];
        let iv = &surb_keys[iv_off..iv_off + STREAM_IV_LEN];
        if i == nr_keys - 1 {
            payload = zears::Aez::new(key)
                .decrypt(iv, &[], 0, &payload)
                .ok_or(PacketBuildError::SurbPayloadDecrypt)?;
        } else {
            payload = zears::Aez::new(key).encrypt(iv, &[], 0, &payload);
        }
    }

    if payload.len() < PAYLOAD_TAG_LEN {
        return Err(PacketBuildError::TruncatedSurbReply);
    }
    if payload[..PAYLOAD_TAG_LEN].iter().any(|byte| *byte != 0) {
        return Err(PacketBuildError::InvalidSurbPayloadTag);
    }
    Ok(payload[PAYLOAD_TAG_LEN..].to_vec())
}

fn build_sphinx_packet_bytes(
    raw_consensus: &[u8],
    ed25519_trust_anchors: &[u8],
    threshold: usize,
    current_epoch: u64,
    max_future_epochs: u64,
    gateway_endpoint: &str,
    service_capability: &str,
    payload: &[u8],
) -> Result<Vec<u8>, PacketBuildError> {
    let (_, doc, _) = verify_certificate(
        raw_consensus,
        ed25519_trust_anchors,
        threshold,
        current_epoch,
        max_future_epochs,
    )?;
    let (path, _) = select_mvp3_path(&doc, gateway_endpoint, service_capability)?;
    let payload = service_forward_payload(payload)?;
    new_sphinx_packet(&path, payload)
}

fn build_sphinx_packet_with_surb_bytes(
    raw_consensus: &[u8],
    ed25519_trust_anchors: &[u8],
    threshold: usize,
    current_epoch: u64,
    max_future_epochs: u64,
    gateway_endpoint: &str,
    service_capability: &str,
    payload: &[u8],
) -> Result<SphinxPacketWithSURB, PacketBuildError> {
    let (_, doc, _) = verify_certificate(
        raw_consensus,
        ed25519_trust_anchors,
        threshold,
        current_epoch,
        max_future_epochs,
    )?;
    let (forward_path, _) = select_mvp3_path(&doc, gateway_endpoint, service_capability)?;

    let mut recipient = [0u8; RECIPIENT_ID_LEN];
    let mut surb_id = [0u8; SURB_ID_LEN];
    getrandom::getrandom(&mut recipient)
        .map_err(|err| PacketBuildError::Random(err.to_string()))?;
    getrandom::getrandom(&mut surb_id).map_err(|err| PacketBuildError::Random(err.to_string()))?;

    let reply_path = select_reply_path(&doc, gateway_endpoint, recipient, surb_id)?;
    let (surb, surb_keys) = new_surb(&reply_path)?;
    let payload = service_forward_payload_with_surb(payload, &surb)?;
    let packet = new_sphinx_packet(&forward_path, payload)?;

    Ok(SphinxPacketWithSURB {
        packet,
        recipient: recipient.to_vec(),
        surb_id: surb_id.to_vec(),
        surb_keys,
    })
}

fn validate_kemsphinx_scheme(kem_name: &str) -> Result<(), PacketBuildError> {
    if kem_name.eq_ignore_ascii_case(KEM_X25519_NAME) {
        return Ok(());
    }
    Err(PacketBuildError::UnsupportedKem(kem_name.to_string()))
}

fn build_kemsphinx_packet_bytes(
    raw_consensus: &[u8],
    ed25519_trust_anchors: &[u8],
    threshold: usize,
    current_epoch: u64,
    max_future_epochs: u64,
    kem_name: &str,
    gateway_endpoint: &str,
    service_capability: &str,
    payload: &[u8],
) -> Result<Vec<u8>, PacketBuildError> {
    validate_kemsphinx_scheme(kem_name)?;
    let (_, doc, _) = verify_certificate(
        raw_consensus,
        ed25519_trust_anchors,
        threshold,
        current_epoch,
        max_future_epochs,
    )?;
    let (path, _) = select_mvp3_path(&doc, gateway_endpoint, service_capability)?;
    let payload = service_forward_payload_for(KEM_X25519_GEOMETRY, payload)?;
    new_kemsphinx_x25519_packet(&path, payload)
}

fn build_kemsphinx_packet_with_surb_bytes(
    raw_consensus: &[u8],
    ed25519_trust_anchors: &[u8],
    threshold: usize,
    current_epoch: u64,
    max_future_epochs: u64,
    kem_name: &str,
    gateway_endpoint: &str,
    service_capability: &str,
    payload: &[u8],
) -> Result<SphinxPacketWithSURB, PacketBuildError> {
    validate_kemsphinx_scheme(kem_name)?;
    let (_, doc, _) = verify_certificate(
        raw_consensus,
        ed25519_trust_anchors,
        threshold,
        current_epoch,
        max_future_epochs,
    )?;
    let (forward_path, _) = select_mvp3_path(&doc, gateway_endpoint, service_capability)?;

    let mut recipient = [0u8; RECIPIENT_ID_LEN];
    let mut surb_id = [0u8; SURB_ID_LEN];
    getrandom::getrandom(&mut recipient)
        .map_err(|err| PacketBuildError::Random(err.to_string()))?;
    getrandom::getrandom(&mut surb_id).map_err(|err| PacketBuildError::Random(err.to_string()))?;

    let reply_path = select_reply_path(&doc, gateway_endpoint, recipient, surb_id)?;
    let (surb, surb_keys) = new_kemsphinx_x25519_surb(&reply_path)?;
    let payload = service_forward_payload_with_surb_for(KEM_X25519_GEOMETRY, payload, &surb)?;
    let packet = new_kemsphinx_x25519_packet(&forward_path, payload)?;

    Ok(SphinxPacketWithSURB {
        packet,
        recipient: recipient.to_vec(),
        surb_id: surb_id.to_vec(),
        surb_keys,
    })
}

#[wasm_bindgen]
pub fn build_sphinx_packet(
    raw_consensus: &[u8],
    ed25519_trust_anchors: &[u8],
    threshold: usize,
    current_epoch: u64,
    max_future_epochs: u64,
    gateway_endpoint: &str,
    service_capability: &str,
    payload: &[u8],
) -> Result<Vec<u8>, JsValue> {
    build_sphinx_packet_bytes(
        raw_consensus,
        ed25519_trust_anchors,
        threshold,
        current_epoch,
        max_future_epochs,
        gateway_endpoint,
        service_capability,
        payload,
    )
    .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn build_kemsphinx_packet(
    raw_consensus: &[u8],
    ed25519_trust_anchors: &[u8],
    threshold: usize,
    current_epoch: u64,
    max_future_epochs: u64,
    kem_name: &str,
    gateway_endpoint: &str,
    service_capability: &str,
    payload: &[u8],
) -> Result<Vec<u8>, JsValue> {
    build_kemsphinx_packet_bytes(
        raw_consensus,
        ed25519_trust_anchors,
        threshold,
        current_epoch,
        max_future_epochs,
        kem_name,
        gateway_endpoint,
        service_capability,
        payload,
    )
    .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn build_sphinx_packet_with_surb(
    raw_consensus: &[u8],
    ed25519_trust_anchors: &[u8],
    threshold: usize,
    current_epoch: u64,
    max_future_epochs: u64,
    gateway_endpoint: &str,
    service_capability: &str,
    payload: &[u8],
) -> Result<JsValue, JsValue> {
    let packet = build_sphinx_packet_with_surb_bytes(
        raw_consensus,
        ed25519_trust_anchors,
        threshold,
        current_epoch,
        max_future_epochs,
        gateway_endpoint,
        service_capability,
        payload,
    )
    .map_err(|err| JsValue::from_str(&err.to_string()))?;
    serde_wasm_bindgen::to_value(&packet).map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn build_kemsphinx_packet_with_surb(
    raw_consensus: &[u8],
    ed25519_trust_anchors: &[u8],
    threshold: usize,
    current_epoch: u64,
    max_future_epochs: u64,
    kem_name: &str,
    gateway_endpoint: &str,
    service_capability: &str,
    payload: &[u8],
) -> Result<JsValue, JsValue> {
    let packet = build_kemsphinx_packet_with_surb_bytes(
        raw_consensus,
        ed25519_trust_anchors,
        threshold,
        current_epoch,
        max_future_epochs,
        kem_name,
        gateway_endpoint,
        service_capability,
        payload,
    )
    .map_err(|err| JsValue::from_str(&err.to_string()))?;
    serde_wasm_bindgen::to_value(&packet).map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn decrypt_surb_reply(reply_payload: &[u8], surb_keys: &[u8]) -> Result<Vec<u8>, JsValue> {
    decrypt_surb_reply_bytes(reply_payload, surb_keys)
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde::Serialize;

    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct TestCertificate {
        version: u32,
        expiration: u64,
        key_type: String,
        #[serde(with = "serde_bytes")]
        certified: Vec<u8>,
        signatures: BTreeMap<ByteBuf, TestCertificateSignature>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct TestCertificateSignature {
        public_key_sum256: ByteBuf,
        payload: ByteBuf,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct TestDocument {
        epoch: u64,
        gateway_nodes: Vec<TestMixDescriptor>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct TestMixDescriptor {
        name: String,
        addresses: BTreeMap<String, Vec<String>>,
        is_gateway_node: bool,
    }

    #[derive(Serialize, Clone)]
    #[serde(rename_all = "PascalCase")]
    struct TestRouteDocument {
        epoch: u64,
        topology: Vec<Vec<TestRouteMixDescriptor>>,
        gateway_nodes: Vec<TestRouteMixDescriptor>,
        service_nodes: Vec<TestRouteMixDescriptor>,
    }

    #[derive(Serialize, Clone)]
    #[serde(rename_all = "PascalCase")]
    struct TestRouteMixDescriptor {
        name: String,
        #[serde(with = "serde_bytes")]
        identity_key: Vec<u8>,
        mix_keys: BTreeMap<u64, ByteBuf>,
        addresses: BTreeMap<String, Vec<String>>,
        kaetzchen: BTreeMap<String, BTreeMap<String, serde_cbor::Value>>,
        is_gateway_node: bool,
        is_service_node: bool,
    }

    fn wrap_signed_consensus(certified: Vec<u8>, expiration: u64) -> (Vec<u8>, Vec<u8>) {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let trust_anchor = verifying_key.to_bytes().to_vec();
        let mut message = Vec::new();
        message.extend_from_slice(&CERT_VERSION.to_le_bytes());
        message.extend_from_slice(&expiration.to_le_bytes());
        message.extend_from_slice(b"Ed25519");
        message.extend_from_slice(&certified);

        let key_hash = blake2b_256(&trust_anchor);
        let signature = signing_key.sign(&message).to_bytes().to_vec();
        let mut signatures = BTreeMap::new();
        signatures.insert(
            ByteBuf::from(key_hash.to_vec()),
            TestCertificateSignature {
                public_key_sum256: ByteBuf::from(key_hash.to_vec()),
                payload: ByteBuf::from(signature),
            },
        );

        let raw = serde_cbor::to_vec(&TestCertificate {
            version: CERT_VERSION,
            expiration,
            key_type: "Ed25519".to_string(),
            certified,
            signatures,
        })
        .unwrap();
        (raw, trust_anchor)
    }

    fn signed_consensus(epoch: u64, expiration: u64) -> (Vec<u8>, Vec<u8>) {
        let mut addresses = BTreeMap::new();
        addresses.insert(
            WEBTRANSPORT_TRANSPORT.to_string(),
            vec!["https://gateway.example:443/.well-known/katzenpost-wt".to_string()],
        );
        let certified = serde_cbor::to_vec(&TestDocument {
            epoch,
            gateway_nodes: vec![TestMixDescriptor {
                name: "gateway1".to_string(),
                addresses,
                is_gateway_node: true,
            }],
        })
        .unwrap();
        wrap_signed_consensus(certified, expiration)
    }

    fn test_x25519_public(seed: u8) -> Vec<u8> {
        PublicKey::from(&StaticSecret::from([seed; 32]))
            .to_bytes()
            .to_vec()
    }

    fn route_descriptor(
        name: &str,
        epoch: u64,
        seed: u8,
        addresses: BTreeMap<String, Vec<String>>,
        kaetzchen: BTreeMap<String, BTreeMap<String, serde_cbor::Value>>,
        is_gateway_node: bool,
        is_service_node: bool,
    ) -> TestRouteMixDescriptor {
        let mut mix_keys = BTreeMap::new();
        mix_keys.insert(epoch, ByteBuf::from(test_x25519_public(seed)));
        TestRouteMixDescriptor {
            name: name.to_string(),
            identity_key: vec![seed; 32],
            mix_keys,
            addresses,
            kaetzchen,
            is_gateway_node,
            is_service_node,
        }
    }

    fn signed_routing_consensus(epoch: u64, expiration: u64) -> (Vec<u8>, Vec<u8>, String) {
        let gateway_endpoint = "https://gateway.example:443/.well-known/katzenpost-wt".to_string();

        let mut gateway_addresses = BTreeMap::new();
        gateway_addresses.insert(
            WEBTRANSPORT_TRANSPORT.to_string(),
            vec![gateway_endpoint.clone()],
        );
        let gateway = route_descriptor(
            "gateway1",
            epoch,
            11,
            gateway_addresses,
            BTreeMap::new(),
            true,
            false,
        );

        let mut topology = Vec::new();
        for (idx, seed) in [21u8, 22, 23].into_iter().enumerate() {
            topology.push(vec![route_descriptor(
                &format!("mix{}", idx + 1),
                epoch,
                seed,
                BTreeMap::new(),
                BTreeMap::new(),
                false,
                false,
            )]);
        }

        let mut kaetzchen_params = BTreeMap::new();
        kaetzchen_params.insert(
            "endpoint".to_string(),
            serde_cbor::Value::Text("+echo".to_string()),
        );
        let mut kaetzchen = BTreeMap::new();
        kaetzchen.insert("echo".to_string(), kaetzchen_params);
        let service = route_descriptor(
            "service1",
            epoch,
            31,
            BTreeMap::new(),
            kaetzchen,
            false,
            true,
        );

        let certified = serde_cbor::to_vec(&TestRouteDocument {
            epoch,
            topology,
            gateway_nodes: vec![gateway],
            service_nodes: vec![service],
        })
        .unwrap();
        let (raw, trust_anchor) = wrap_signed_consensus(certified, expiration);
        (raw, trust_anchor, gateway_endpoint)
    }

    #[test]
    fn verifies_valid_consensus_and_extracts_webtransport_gateway() {
        let (raw, trust_anchor) = signed_consensus(42, 44);
        let verified = verify_consensus_bytes(&raw, &trust_anchor, 1, 42, 1).unwrap();
        assert_eq!(verified.epoch, 42);
        assert_eq!(verified.signatures_verified, 1);
        assert_eq!(verified.webtransport_gateways.len(), 1);
        assert_eq!(verified.webtransport_gateways[0].name, "gateway1");
    }

    #[test]
    fn rejects_tampered_consensus() {
        let (mut raw, trust_anchor) = signed_consensus(42, 44);
        let last = raw.last_mut().unwrap();
        *last ^= 1;
        let err = verify_consensus_bytes(&raw, &trust_anchor, 1, 42, 1).unwrap_err();
        assert!(matches!(
            err,
            ConsensusError::ThresholdNotMet | ConsensusError::Cbor(_)
        ));
    }

    #[test]
    fn classifies_stale_consensus() {
        let (raw, trust_anchor) = signed_consensus(41, 44);
        let err = verify_consensus_bytes(&raw, &trust_anchor, 1, 42, 1).unwrap_err();
        assert!(matches!(err, ConsensusError::Stale));
    }

    #[test]
    fn packet_construction_rejects_tampered_consensus_before_route_selection() {
        let (mut raw, trust_anchor) = signed_consensus(42, 44);
        *raw.last_mut().unwrap() ^= 1;

        let err = build_sphinx_packet_bytes(
            &raw,
            &trust_anchor,
            1,
            42,
            1,
            "https://gateway.example:443/.well-known/katzenpost-wt",
            "echo",
            b"payload",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PacketBuildError::Consensus(ConsensusError::ThresholdNotMet)
                | PacketBuildError::Consensus(ConsensusError::Cbor(_))
        ));

        let err = build_sphinx_packet_with_surb_bytes(
            &raw,
            &trust_anchor,
            1,
            42,
            1,
            "https://gateway.example:443/.well-known/katzenpost-wt",
            "echo",
            b"payload",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PacketBuildError::Consensus(ConsensusError::ThresholdNotMet)
                | PacketBuildError::Consensus(ConsensusError::Cbor(_))
        ));
    }

    #[test]
    fn packet_construction_rejects_stale_consensus_before_route_selection() {
        let (raw, trust_anchor) = signed_consensus(41, 44);

        let err = build_sphinx_packet_bytes(
            &raw,
            &trust_anchor,
            1,
            42,
            1,
            "https://gateway.example:443/.well-known/katzenpost-wt",
            "echo",
            b"payload",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PacketBuildError::Consensus(ConsensusError::Stale)
        ));

        let err = build_sphinx_packet_with_surb_bytes(
            &raw,
            &trust_anchor,
            1,
            42,
            1,
            "https://gateway.example:443/.well-known/katzenpost-wt",
            "echo",
            b"payload",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PacketBuildError::Consensus(ConsensusError::Stale)
        ));
    }

    #[test]
    fn surb_reply_decryption_is_local_and_authenticated() {
        let mut surb_keys = vec![0u8; SPRP_KEY_LEN + STREAM_IV_LEN];
        for (i, byte) in surb_keys.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let key = &surb_keys[..SPRP_KEY_LEN];
        let iv = &surb_keys[SPRP_KEY_LEN..];
        let expected_reply = b"secret reply payload";

        let mut plaintext = vec![0u8; PAYLOAD_TAG_LEN];
        plaintext.extend_from_slice(expected_reply);
        let ciphertext = zears::Aez::new(key).encrypt(iv, &[], 0, &plaintext);

        let decrypted = decrypt_surb_reply_bytes(&ciphertext, &surb_keys).unwrap();
        assert_eq!(&decrypted[..expected_reply.len()], expected_reply);

        let mut tampered_ciphertext = ciphertext.clone();
        tampered_ciphertext[0] ^= 1;
        assert!(decrypt_surb_reply_bytes(&tampered_ciphertext, &surb_keys).is_err());

        let mut wrong_keys = surb_keys.clone();
        wrong_keys[0] ^= 1;
        assert!(decrypt_surb_reply_bytes(&ciphertext, &wrong_keys).is_err());
    }

    #[test]
    fn deterministic_chacha_matches_katzenpost_reader() {
        let out = deterministic_chacha20_first_32(&[0u8; 32]);
        assert_eq!(
            hex::encode(out),
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
        );
    }

    #[test]
    fn blake2xb_xof_matches_go_kem_adapter_hash() {
        let mut shared_secret = [0u8; 32];
        let mut recipient_public = [0u8; 32];
        let mut ephemeral_public = [0u8; 32];
        for i in 0..32 {
            shared_secret[i] = i as u8;
            recipient_public[i] = (32 + i) as u8;
            ephemeral_public[i] = (64 + i) as u8;
        }

        let out = kem_adapter_x25519_hash(&shared_secret, &recipient_public, &ephemeral_public);
        assert_eq!(
            hex::encode(out),
            "ffdf4251e4df58a87f08de9a0d43d8848f9c684c1f4181d7ccce56714bb57ad1"
        );
    }

    #[test]
    fn kemsphinx_x25519_packet_uses_kem_geometry() {
        let (raw, trust_anchor, gateway_endpoint) = signed_routing_consensus(42, 44);

        let packet = build_kemsphinx_packet_bytes(
            &raw,
            &trust_anchor,
            1,
            42,
            1,
            KEM_X25519_NAME,
            &gateway_endpoint,
            "echo",
            b"kemsphinx payload",
        )
        .unwrap();

        assert_eq!(packet.len(), KEM_X25519_PACKET_LEN);
        assert_eq!(&packet[..2], &V0_AD);
        assert_ne!(
            &packet[2..2 + KEM_X25519_CIPHERTEXT_LEN],
            &[0u8; KEM_X25519_CIPHERTEXT_LEN]
        );
    }

    #[test]
    fn kemsphinx_x25519_surb_uses_kem_geometry() {
        let (raw, trust_anchor, gateway_endpoint) = signed_routing_consensus(42, 44);

        let with_surb = build_kemsphinx_packet_with_surb_bytes(
            &raw,
            &trust_anchor,
            1,
            42,
            1,
            KEM_X25519_NAME,
            &gateway_endpoint,
            "echo",
            b"kemsphinx with surb",
        )
        .unwrap();

        assert_eq!(with_surb.packet.len(), KEM_X25519_PACKET_LEN);
        assert_eq!(with_surb.recipient.len(), RECIPIENT_ID_LEN);
        assert_eq!(with_surb.surb_id.len(), SURB_ID_LEN);
        assert_eq!(
            with_surb.surb_keys.len(),
            5 * (SPRP_KEY_LEN + STREAM_IV_LEN)
        );
    }

    #[test]
    fn kemsphinx_rejects_unsupported_scheme() {
        let (raw, trust_anchor, gateway_endpoint) = signed_routing_consensus(42, 44);
        let err = build_kemsphinx_packet_bytes(
            &raw,
            &trust_anchor,
            1,
            42,
            1,
            "XWING",
            &gateway_endpoint,
            "echo",
            b"payload",
        )
        .unwrap_err();

        assert!(matches!(err, PacketBuildError::UnsupportedKem(name) if name == "XWING"));
    }
}
