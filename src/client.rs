use std::io::stdin;
use std::thread;
use std::time::Duration;

pub mod zkp_auth {
    include!("./zkp_auth.rs");
}
use num_bigint::BigUint;
use tonic::transport::Channel;
use zkp_auth::auth_client::AuthClient;
use zkp_auth::RegisterRequest;

use zkp_chaum_pedersen::ZKP;

use crate::zkp_auth::{AuthenticationChallengeRequest, AuthenticationAnswerRequest};

fn zkp_instance() -> ZKP {
    let (alpha, beta, p, q, rng_upper_bound) = ZKP::get_1024_bits_config();
    ZKP::new(alpha, beta, p, q, rng_upper_bound)
}

#[tokio::main]
async fn main() {
    let mut buf = String::new();
    let domain_addr = String::from("https://127.0.0.1:50051");
    let mut client = AuthClient::connect(domain_addr.clone())
        .await
        .expect("Failed to connect to the server");

    println!("Connnected to : {domain_addr}");
    println!("Username: ");

    stdin()
        .read_line(&mut buf)
        .expect("Couldnt read username from stdin");

    let user_name = buf.trim().to_string();
    println!("Password(x):");
    stdin().read_line(&mut buf).expect("Invalid pasword");
    let x = BigUint::from_bytes_be(buf.trim().as_bytes());
    thread::sleep(Duration::from_secs(2));

    // register
    let zkp = zkp_instance();
    register(&mut client, &zkp, &user_name, &x).await;
    thread::sleep(Duration::from_secs(2));
    
    // requeste authentication challenge
    let k: BigUint = zkp.generate_random();
    let (auth_id, c) = authentication_challenge(&mut client, &zkp, &user_name, &k).await;
    thread::sleep(Duration::from_secs(2));
    
    // verify the solution
    let s = zkp.solve(&k, &c, &x);
    verify(&mut client, &auth_id, &s).await;
}

async fn register(client:&mut AuthClient<Channel> ,zkp: &ZKP, user_name: &String, x: &BigUint) {
    let request = RegisterRequest {
        user_name: user_name.clone(),
        y1: zkp.alpha.clone().modpow(x, &zkp.p).to_bytes_be(),
        y2: zkp.beta.clone().modpow(x, &zkp.p).to_bytes_be(),
    };
    println!("Sending RegisterRequest : {:#?}", request);
    let _response = client.register(request).await.unwrap();
}


async fn authentication_challenge(client:&mut AuthClient<Channel> ,zkp: &ZKP, user_name: &String, k: &BigUint) -> (String, BigUint) {
    let request = AuthenticationChallengeRequest {
        user_name: user_name.clone(),
        r1: zkp.alpha.clone().modpow(k, &zkp.p).to_bytes_be(),
        r2: zkp.beta.clone().modpow(k, &zkp.p).to_bytes_be(),
    };
    println!("Sending AuthenticationChallengeRequest : {:#?}", request);
    let response = client
        .create_authentication_challenge(request)
        .await
        .unwrap();
    println!("AuthenticationChallengeResponse: {:#?}", response);
    let response =  response.into_inner();
    let auth_id = response.auth_id;
    let c = BigUint::from_bytes_be(&response.c);

    (auth_id, c)
}

async fn verify(client:&mut AuthClient<Channel>, auth_id: &String, s: &BigUint) {
    let request = AuthenticationAnswerRequest{
        auth_id : auth_id.clone(),
        s: s.clone().to_bytes_be()
    };

    let response = client.verify_authentication(request).await.unwrap();
    let response = response.into_inner();
    let session_id = response.session_id;

    println!("Logged in, session_id : {session_id}");
}