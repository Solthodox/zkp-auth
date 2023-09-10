use num_bigint::BigUint;
use rand::Rng;
use std::{collections::HashMap, sync::Mutex};
use tonic::{transport::Server, Code, Request, Response, Status};
use zkp_chaum_pedersen::ZKP;


fn _alpha() -> BigUint {
    let (alpha, _beta, _p, _q, _rng_upper_bound) = ZKP::get_1024_bits_config();
    alpha
}
fn _beta() -> BigUint {
    let (_alpha, beta, _p, _q, _rng_upper_bound) = ZKP::get_1024_bits_config();
    beta
}

fn _p() -> BigUint {
    let (__alpha, __beta, p, _q, __rng_upper_bound) = ZKP::get_1024_bits_config();
    p
}

fn _q() -> BigUint {
    let (_alpha, _beta, _p, q, _rng_upper_bound) = ZKP::get_1024_bits_config();
    q
}

fn _rng_upper_bound() -> BigUint {
    let (_alpha, _beta, _p, _q, rng_upper_bound) = ZKP::get_1024_bits_config();
    rng_upper_bound
}

fn zkp_instance() -> ZKP {
    let (alpha, beta, p, q, rng_upper_bound) = ZKP::get_1024_bits_config();
    ZKP::new(alpha, beta, p, q, rng_upper_bound)
}
pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};

fn generate_random_string(size: usize) -> String {
    rand::thread_rng()
        .sample_iter(rand::distributions::Alphanumeric)
        .take(size)
        .map(char::from)
        .collect()
}

#[derive(Debug, Default)]
pub struct AuthImpl {
    pub user_info: Mutex<HashMap<String, UserInfo>>,
    pub auth_id_to_user: Mutex<HashMap<String, String>>,
}

#[derive(Debug, Default)]

pub struct UserInfo {
    pub user_name: String,
    // registration
    pub y1: BigUint,
    pub y2: BigUint,
    // authorization
    pub r1: BigUint,
    pub r2: BigUint,
    //verification
    pub c: BigUint,
    pub s: BigUint,
    pub session_id: String,
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        println!("Processing Register: {:#?}", request);
        let request = request.into_inner();
        let user_name = request.user_name;

        let mut user_info_cache = UserInfo::default();
        user_info_cache.user_name = user_name.clone();
        user_info_cache.y1 = BigUint::from_bytes_be(&request.y1);
        user_info_cache.y2 = BigUint::from_bytes_be(&request.y2);

        // servers should not panick
        let user_info_hashmap = &mut self.user_info.lock().unwrap();
        user_info_hashmap.insert(user_name, user_info_cache);

        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        println!("Processing AuthenticationChallenge: {:#?}", request);
        let request = request.into_inner();

        let user_name = request.user_name;

        let user_info_hashmap = &mut self.user_info.lock().unwrap();

        if let Some(user_info) = user_info_hashmap.get_mut(&user_name) {
            user_info.r1 = BigUint::from_bytes_be(&request.r1);
            user_info.r2 = BigUint::from_bytes_be(&request.r2);

            let c = zkp_instance().generate_random();
            user_info.c = c.clone();
            let auth_id = generate_random_string(48);
            let auth_id_to_user = &mut self.auth_id_to_user.lock().unwrap();
            auth_id_to_user.insert(auth_id.clone(), user_name);
            return Ok(Response::new(AuthenticationChallengeResponse {
                auth_id,
                c: c.to_bytes_be(),
            }));
        } else {
            return Err(Status::new(
                Code::NotFound,
                format!("User : {} not found in database", user_name),
            ));
        }
    }

    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        println!("Processing Verification: {:#?}", request);
        let request = request.into_inner();

        let auth_id = request.auth_id;
        let s = BigUint::from_bytes_be(&request.s);

        let auth_id_hashmap = &mut self.auth_id_to_user.lock().unwrap();

        if let Some(user_name) = auth_id_hashmap.get_mut(&auth_id) {
            let user_info_hashmap = &mut self.user_info.lock().unwrap();
            let user_info = user_info_hashmap.get_mut(&user_name.clone()).unwrap();

            match zkp_instance().verify(
                &user_info.y1,
                &user_info.y2,
                &user_info.r1,
                &user_info.r2,
                &s,
                &user_info.c,
            ) {
                true => {
                    let session_id = generate_random_string(48);
                    user_info.session_id = session_id.clone();
                    return Ok(Response::new(AuthenticationAnswerResponse { session_id }));
                }
                _ => {
                    return Err(Status::new(
                        Code::NotFound,
                        format!("S : {} wrong answer", s),
                    ));
                }
            }
        } else {
            return Err(Status::new(
                Code::NotFound,
                format!("AuthId : {} not found in database", auth_id),
            ));
        }
    }
}

#[tokio::main]
async fn main() {
    let addr = String::from("127.0.0.1:50051");
    println!("✔️ Listening to : {addr}");

    let auth_impl = AuthImpl::default();

    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(addr.parse().unwrap())
        .await
        .unwrap();
}
