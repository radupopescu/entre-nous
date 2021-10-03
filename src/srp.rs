//
// Copyright 2021 Radu Popescu <mail@radupopescu.net>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use {
    crate::{errors::Result, password_hash::Salt},
    rand::RngCore,
    serde::{Deserialize, Serialize},
    sha2::Sha256,
    srp::{
        client::{SrpClient, SrpClientVerifier},
        groups::{G_2048, G_4096, G_8192},
        server::{SrpServer, UserRecord},
    },
};

pub fn generate_private_ephemeral() -> Vec<u8> {
    let mut eph = vec![0u8; 64];
    rand::thread_rng().fill_bytes(&mut eph);
    eph
}

#[derive(Copy, Clone, Deserialize, Serialize)]
pub enum Mode {
    Fast,
    Medium,
    Slow,
}

pub struct Client<'a> {
    srp_client: SrpClient<'a, Sha256>,
}

impl<'a> Client<'a> {
    pub fn new(a: &[u8], mode: Mode) -> Client {
        let group: &srp::types::SrpGroup = match mode {
            Mode::Fast => &G_2048,
            Mode::Medium => &G_4096,
            Mode::Slow => &G_8192,
        };
        Client {
            srp_client: SrpClient::new(a, &group),
        }
    }

    pub fn get_a_pub(&self) -> Vec<u8> {
        self.srp_client.get_a_pub()
    }

    pub fn get_verifier(&self, private_key: &[u8]) -> Verifier {
        Verifier(self.srp_client.get_password_verifier(private_key))
    }

    pub fn finalize_handshake(
        self,
        private_key: &[u8],
        b_pub: &[u8],
    ) -> Result<ClientAfterHandshake> {
        let srp_client_verifier = self.srp_client.process_reply(private_key, b_pub)?;
        Ok(ClientAfterHandshake {
            srp_client_verifier,
        })
    }
}

pub struct ClientAfterHandshake {
    srp_client_verifier: SrpClientVerifier<Sha256>,
}

impl ClientAfterHandshake {
    pub fn get_proof(&self) -> ClientProof {
        ClientProof(self.srp_client_verifier.get_proof().as_slice().to_owned())
    }

    pub fn verify_server(self, server_proof: &ServerProof) -> Result<()> {
        self.srp_client_verifier
            .verify_server(server_proof.0.as_slice())?;
        Ok(())
    }
}

pub struct Server {
    srp_server: SrpServer<Sha256>,
}

impl Server {
    pub fn new(
        username: &str,
        salt: &Salt,
        verifier: &Verifier,
        a_pub: &[u8],
        b: &[u8],
        mode: Mode,
    ) -> Result<Server> {
        let group: &srp::types::SrpGroup = match mode {
            Mode::Fast => &G_2048,
            Mode::Medium => &G_4096,
            Mode::Slow => &G_8192,
        };
        let user = UserRecord {
            username: username.as_bytes(),
            salt: &salt.0[..],
            verifier: verifier.0.as_slice(),
        };
        let srp_server = SrpServer::new(&user, a_pub, b, group)?;
        Ok(Server { srp_server })
    }

    pub fn get_b_pub(&self) -> Vec<u8> {
        self.srp_server.get_b_pub()
    }

    pub fn verify_client(&self, client_proof: &ClientProof) -> Result<ServerProof> {
        let server_proof = self.srp_server.verify(client_proof.0.as_slice())?;
        Ok(ServerProof(server_proof.as_slice().to_owned()))
    }
}

pub struct Verifier(Vec<u8>);

impl From<&[u8]> for Verifier {
    fn from(s: &[u8]) -> Self {
        Self(s.to_owned())
    }
}

impl AsRef<[u8]> for Verifier {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct ClientProof(Vec<u8>);

impl From<&[u8]> for ClientProof {
    fn from(s: &[u8]) -> Self {
        Self(s.to_owned())
    }
}

impl AsRef<[u8]> for ClientProof {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct ServerProof(Vec<u8>);

impl From<&[u8]> for ServerProof {
    fn from(s: &[u8]) -> Self {
        Self(s.to_owned())
    }
}

impl AsRef<[u8]> for ServerProof {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::password_hash::{derive_key, Salt},
    };

    #[test]
    fn full_handshake() -> Result<()> {
        let username = "some_user";
        let password = "some_pass";
        let salt = Salt::new();

        let mut private_key = vec![0u8; 32];
        derive_key(&mut private_key, password.as_bytes(), &salt)?;

        let a = generate_private_ephemeral();
        let client = Client::new(&a, Mode::Fast);

        let a_pub = client.get_a_pub();
        let verifier = client.get_verifier(&private_key);

        let b = generate_private_ephemeral();
        let server = Server::new(username, &salt, &verifier, &a_pub, &b, Mode::Fast)?;
        let b_pub = server.get_b_pub();

        let client = client.finalize_handshake(&private_key, &b_pub)?;
        let client_proof = client.get_proof();

        let server_proof = server.verify_client(&client_proof)?;

        client.verify_server(&server_proof)?;

        Ok(())
    }

    #[test]
    fn wrong_password() -> Result<()> {
        let username = "some_user";
        let password = "some_pass";
        let wrong_password = "wrong_pass";
        let salt = Salt::new();

        let mut private_key = vec![0u8; 32];
        derive_key(&mut private_key, password.as_bytes(), &salt)?;

        let a = generate_private_ephemeral();
        let client = Client::new(&a, Mode::Fast);

        let a_pub = client.get_a_pub();
        let verifier = client.get_verifier(&private_key);

        let b = generate_private_ephemeral();
        let server = Server::new(username, &salt, &verifier, &a_pub, &b, Mode::Fast)?;
        let b_pub = server.get_b_pub();

        let mut wrong_private_key = vec![0u8; 32];
        derive_key(&mut wrong_private_key, wrong_password.as_bytes(), &salt)?;

        let client = client.finalize_handshake(&wrong_private_key, &b_pub)?;
        let client_proof = client.get_proof();

        assert!(server.verify_client(&client_proof).is_err());

        Ok(())
    }

    #[test]
    fn evil_server() -> Result<()> {
        let username = "some_user";
        let password = "some_pass";
        let salt = Salt::new();

        let mut private_key = vec![0u8; 32];
        derive_key(&mut private_key, password.as_bytes(), &salt)?;

        let a = generate_private_ephemeral();
        let client = Client::new(&a, Mode::Fast);

        let a_pub = client.get_a_pub();

        let fake_verifier = Verifier(vec![1, 2, 3, 1, 2, 3]);
        let b = generate_private_ephemeral();
        let server = Server::new(username, &salt, &fake_verifier, &a_pub, &b, Mode::Fast)?;
        let b_pub = server.get_b_pub();

        let client = client.finalize_handshake(&private_key, &b_pub)?;

        let server_proof = ServerProof(vec![1, 2, 3, 4, 5, 6]);

        assert!(client.verify_server(&server_proof).is_err());

        Ok(())
    }
}
