use curv::{BigInt, elliptic::curves::{traits::{ECScalar, ECPoint}}, FE, cryptographic_primitives::proofs::sigma_dlog::DLogProof};
use kms::ecdsa::two_party::{MasterKey2, party1::{self, KeyGenParty1Message2}};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::{self, KeyGenFirstMsg};
use reqwest::header::CONTENT_TYPE;
use schemars::JsonSchema;
use serde::{Serialize, Deserialize};

#[derive(JsonSchema)]
#[schemars(remote = "DLogProof")]
pub struct DLogProofDef(String);

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq)]
pub enum Protocol {
    Deposit,
    Transfer,
    Withdraw,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct KeyGenMsg1 {
    pub shared_key_id: String,
    pub protocol: Protocol,
    pub solution: Option<String>,
}

#[derive(JsonSchema)]
#[schemars(remote = "party_one::KeyGenFirstMsg")]
pub struct KeyGenFirstMsgDef(String);

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct KeyGenReply1 {
    pub user_id: String,
    #[schemars(with = "KeyGenFirstMsgDef")]
    pub msg: party_one::KeyGenFirstMsg,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct KeyGenMsg2 {
    pub shared_key_id: String,
    #[schemars(with = "DLogProofDef")]
    pub dlog_proof: DLogProof,
}

#[derive(JsonSchema)]
#[schemars(remote = "party1::KeyGenParty1Message2")]
pub struct KeyGenParty1Message2Def(String);

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct KeyGenReply2 {
    #[schemars(with = "KeyGenParty1Message2Def")]
    pub msg: party1::KeyGenParty1Message2,
}

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {

    // let url = "http://ye5bn5bmj4xqfmp7bzppseg6xedz6mvtdvp6lfk4ozf7syoxqkcxi3qd.onion";
    let server_url = "http://m3j6xt4llvo4xk7yp4qldq4vmpljgeuovzqh2ycdskivxsgjtf67frad.onion";

    let secret_key = "";
    let shared_id = "";

    let (party_one_first_message, party_one_second_message) = get_keygenfirstmsg_and_keygenparty1message2(server_url, secret_key, shared_id).await.unwrap();
    
    let _key_gen_second_message = MasterKey2::key_gen_second_message(
        &party_one_first_message,
        &party_one_second_message,
    );

    Ok(())   
}

async fn get_keygenfirstmsg_and_keygenparty1message2(server_url: &str, secret_key: &str, shared_id: &str) -> Result<(KeyGenFirstMsg, KeyGenParty1Message2), reqwest::Error> {

    let proxy = reqwest::Proxy::all("socks5h://127.0.0.1:9050")?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .expect("should be able to build reqwest client");

    let res = client.get("https://check.torproject.org").send().await?;
    println!("Status: {}", res.status());

    let text = res.text().await?;
    let is_tor = text.contains("Congratulations. This browser is configured to use Tor.");
    println!("Is Tor: {}", is_tor);
    assert!(is_tor);

    let res = client.get(format!("{}/info/fee", server_url)).send().await?;
    println!("Status: {}", res.status());
    println!("Content: {}", res.text().await?);

    let key_gen_msg1 = KeyGenMsg1 {
        shared_key_id: shared_id.to_string(),
        protocol: Protocol::Transfer,
        solution: None,
    };

    let res = client
            .post(format!("{}/ecdsa/keygen/first", server_url))
            .body(serde_json::to_string(&key_gen_msg1).unwrap())
            .header(CONTENT_TYPE, "application/json")
            .send().await?;

    let key_gen_reply1 = res.json::<KeyGenReply1>().await.unwrap();

    let secret_bytes = BigInt::from_str_radix(secret_key, 16).unwrap();

    let secret_share: FE = ECScalar::from(&secret_bytes);

    let (kg_party_two_first_message, _kg_ec_key_pair_party2) =
            MasterKey2::key_gen_first_message_predefined(&secret_share);

    let key_gen_msg2 = KeyGenMsg2 {
        shared_key_id: key_gen_msg1.shared_key_id,
        dlog_proof: kg_party_two_first_message.d_log_proof,
    };

    let res = client
            .post(format!("{}/ecdsa/keygen/second", server_url))
            .body(serde_json::to_string(&key_gen_msg2).unwrap())
            .header(CONTENT_TYPE, "application/json")
            .send().await?;
    println!("Status: {}", res.status());

    let key_gen_reply2 = res.json::<KeyGenReply2>().await.unwrap();

    println!("pk commitment");
    println!("comm_witness.pk_commitment_blind_factor: {}", key_gen_reply2.msg.ecdh_second_message.comm_witness.pk_commitment_blind_factor);
    println!("comm_witness.public_share: {}", key_gen_reply2.msg.ecdh_second_message.comm_witness.public_share.bytes_compressed_to_big_int());

    println!("zk pok commitment");
    println!("comm_witness.d_log_proof.pk_t_rand_commitment: {}", key_gen_reply2.msg.ecdh_second_message.comm_witness.d_log_proof.pk_t_rand_commitment.bytes_compressed_to_big_int());
    println!("comm_witness.d_log_proof.zk_pok_blind_factor: {}", key_gen_reply2.msg.ecdh_second_message.comm_witness.zk_pok_blind_factor);

    Ok((key_gen_reply1.msg, key_gen_reply2.msg))
}
