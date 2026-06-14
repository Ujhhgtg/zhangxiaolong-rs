#[derive(Clone)]
pub struct TrafficKeyPair {
    pub client_key: Vec<u8>,
    pub server_key: Vec<u8>,
    pub client_nonce: Vec<u8>,
    pub server_nonce: Vec<u8>,
}
