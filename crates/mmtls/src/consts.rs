pub const PROTOCOL_VERSION: u16 = 0xF104;
pub const TLS_PSK_WITH_AES_128_GCM_SHA256: u16 = 0xA8;
pub const MAGIC_ABORT: u8 = 0x15;
pub const MAGIC_HANDSHAKE: u8 = 0x16;
pub const MAGIC_RECORD: u8 = 0x17;
pub const MAGIC_SYSTEM: u8 = 0x19;
pub const TCP_NOOP_REQUEST: u32 = 0x6;
pub const TCP_NOOP_RESPONSE: u32 = 0x3B9ACA06;

use p256::PublicKey;
use std::sync::OnceLock;

pub(crate) fn server_ecdh() -> &'static PublicKey {
    static KEY: OnceLock<PublicKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let bytes = hex_literal::hex!(
            "04"
            "1da177b6a5ed34dabb3f2b047697ca8bbeb78c68389ced43317a298d77316d54"
            "4175c032bc573d5ce4b3ac0b7f2b9a8d48ca4b990ce2fa3ce75cc9d12720fa35"
        );
        PublicKey::from_sec1_bytes(&bytes).expect("valid server key")
    })
}
