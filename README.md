# ZKP Authentication Server

![GitHub License](https://img.shields.io/github/license/solthodox/zkp-auth)
![GitHub Stars](https://img.shields.io/github/stars/solthodox/zkp-auth)
![GitHub Forks](https://img.shields.io/github/forks/solthodox/zkp-auth)
![GitHub Issues](https://img.shields.io/github/issues/solthodox/zkp-auth)

## Overview

This project demonstrates a server authentication application using Zero-Knowledge Proof (Chaum-Pedersen protocol) implemented in Rust. It uses the gRPC protocol for communication between the client and server. Zero-Knowledge Proof (ZKP) is a cryptographic technique that allows one party (the prover) to prove to another party (the verifier) that they possess knowledge of a secret without revealing the secret itself.

## Features

- User registration with ZKP
- Authentication challenge generation
- Solution verification
- Secure communication with gRPC
- Chaum-Pedersen protocol implementation

## Getting Started

### Prerequisites

- Rust: Make sure you have Rust installed. You can download it from [rustup.rs](https://rustup.rs/).
- Protocol Buffers: Ensure that you have Protocol Buffers (protoc) installed. You can download it from [Protocol Buffers](https://developers.google.com/protocol-buffers).

### Building and Running

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/solthodox/zkp-auth.git
   cd zkp-auth
   ```

2. Build the project:

   ```bash
   cargo build --release
   ```

3. Start the server:

   ```bash
   cargo run --bin server
   ```

4. In a separate terminal, run the client:

   ```bash
   cargo run --bin client
   ```

## Usage

1. When running the client, you will be prompted to enter a username and a password (x).
2. The client will register the user with the server using the Chaum-Pedersen protocol.
3. It will then request an authentication challenge from the server.
4. After receiving the challenge, the client will verify the solution and log in if successful.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
