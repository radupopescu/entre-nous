//
// Copyright 2021 Radu Popescu <mail@radupopescu.net>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use {
    crate::{
        password_hash::{derive_key, Salt},
        srp::{generate_private_ephemeral, Client, ClientProof, Mode, Server, ServerProof, Verifier},
        web::Response,
        Result,
    },
    rocket::serde::{json::Json, Deserialize, Serialize},
};

#[derive(Deserialize)]
pub struct RegistrationDataRequest {
    password: String,
    mode: Mode,
}

#[derive(Serialize)]
pub struct RegistrationData {
    private_key: String,
    salt: String,
    verifier: String,
    mode: Mode,
}

#[post("/srp/client/generate_registration_data", data = "<input>")]
pub fn srp_client_generate_registration_data(input: Json<RegistrationDataRequest>) -> Json<Response<RegistrationData>> {
    let resp: Result<RegistrationData> = (|| {
        let a = generate_private_ephemeral();
        let client = Client::new(&a, input.mode);

        let salt = Salt::new();
        let mut private_key = vec![0u8; 32];
        derive_key(&mut private_key, input.password.as_bytes(), &salt)?;

        let verifier = client.get_verifier(&private_key);

        Ok(RegistrationData {
            private_key: base64::encode(private_key),
            salt: base64::encode(&salt),
            verifier: base64::encode(&verifier),
            mode: input.mode,
        })
    })();
    match resp {
        Ok(val) => Json(Response::value(val)),
        Err(e) => Json(Response::error(format!("{}", e))),
    }
}

#[derive(Deserialize)]
pub struct ClientEphemeralsRequest {
    mode: Mode,
}

#[derive(Serialize)]
pub struct ClientEphemeralsData {
    a: String,
    a_pub: String,
}

#[post("/srp/client/generate_ephemerals", data = "<input>")]
pub fn srp_client_generate_ephemerals(input: Json<ClientEphemeralsRequest>) -> Json<Response<ClientEphemeralsData>> {
    let a = generate_private_ephemeral();
    let client = Client::new(&a, input.mode);
    let a_pub = base64::encode(client.get_a_pub());
    let a = base64::encode(a);

    Json(Response::value(ClientEphemeralsData { a, a_pub }))
}

#[derive(Deserialize)]
pub struct ClientProofRequest {
    mode: Mode,
    private_key: String,
    a: String,
    b_pub: String,
}

#[derive(Serialize)]
pub struct ClientProofData {
    client_proof: String,
}

#[post("/srp/client/generate_proof", data = "<input>")]
pub fn srp_client_generate_proof(input: Json<ClientProofRequest>) -> Json<Response<ClientProofData>> {
    let resp: Result<ClientProofData> = (|| {
        let private_key = base64::decode(&input.private_key)?;
        let b_pub = base64::decode(&input.b_pub)?;

        let a = base64::decode(&input.a)?;
        let client = Client::new(&a, input.mode);

        let client = client.finalize_handshake(&private_key, &b_pub)?;
        let client_proof = base64::encode(&client.get_proof());

        Ok(ClientProofData { client_proof })
    })();
    match resp {
        Ok(val) => Json(Response::value(val)),
        Err(e) => Json(Response::error(format!("{}", e))),
    }
}

#[derive(Deserialize)]
pub struct ServerEphemeralsRequest {
    mode: Mode,
    username: String,
    salt: String,
    verifier: String,
    a_pub: String,
}

#[derive(Serialize)]
pub struct ServerEphemeralsData {
    b: String,
    b_pub: String,
}

#[post("/srp/server/generate_ephemerals", data = "<input>")]
pub fn srp_server_generate_ephemerals(input: Json<ServerEphemeralsRequest>) -> Json<Response<ServerEphemeralsData>> {
    let resp: Result<ServerEphemeralsData> = (|| {
        let salt = Salt::from_slice(&base64::decode(&input.salt)?)?;
        let verifier = Verifier::from(base64::decode(&input.verifier)?.as_slice());
        let a_pub = base64::decode(&input.a_pub)?;
        let b = generate_private_ephemeral();
        let server = Server::new(&input.username, &salt, &verifier, &a_pub, &b, input.mode)?;
        let b = base64::encode(b);
        let b_pub = base64::encode(server.get_b_pub());
        Ok(ServerEphemeralsData { b, b_pub })
    })();
    match resp {
        Ok(val) => Json(Response::value(val)),
        Err(e) => Json(Response::error(format!("{}", e))),
    }
}

#[derive(Deserialize)]
pub struct ServerVerifyClientRequest {
    mode: Mode,
    username: String,
    salt: String,
    verifier: String,
    a_pub: String,
    b: String,
    client_proof: String,
}

#[derive(Serialize)]
pub struct ServerVerifyClientData {
    server_proof: String,
}

#[post("/srp/server/verify_client", data = "<input>")]
pub fn srp_server_verify_client(input: Json<ServerVerifyClientRequest>) -> Json<Response<ServerVerifyClientData>> {
    let resp: Result<ServerVerifyClientData> = (|| {
        let salt = Salt::from_slice(&base64::decode(&input.salt)?)?;
        let verifier = Verifier::from(base64::decode(&input.verifier)?.as_slice());
        let a_pub = base64::decode(&input.a_pub)?;
        let b = base64::decode(&input.b)?;
        let client_proof = ClientProof::from(base64::decode(&input.client_proof)?.as_slice());
        let server = Server::new(&input.username, &salt, &verifier, &a_pub, &b, input.mode)?;
        let server_proof = server.verify_client(&client_proof)?;

        Ok(ServerVerifyClientData { server_proof: base64::encode(server_proof) })
    })();
    match resp {
        Ok(val) => Json(Response::value(val)),
        Err(e) => Json(Response::error(format!("{}", e))),
    }
}

#[derive(Deserialize)]
pub struct ClientVerifyServerRequest {
    mode: Mode,
    private_key: String,
    a: String,
    b_pub: String,
    server_proof: String,
}

#[derive(Serialize)]
pub struct ClientVerifyServerData {

}

#[post("/srp/client/verify_server", data = "<input>")]
pub fn srp_client_verify_server(input: Json<ClientVerifyServerRequest>) -> Json<Response<ClientVerifyServerData>> {
    let resp: Result<ClientVerifyServerData> = (|| {
        let private_key = base64::decode(&input.private_key)?;
        let a = base64::decode(&input.a)?;
        let b_pub = base64::decode(&input.b_pub)?;
        let server_proof = ServerProof::from(base64::decode(&input.server_proof)?.as_slice());
        let client = Client::new(&a, input.mode);
        let client = client.finalize_handshake(&private_key, &b_pub)?;
        client.verify_server(&server_proof)?;

        Ok(ClientVerifyServerData {})
    })();
    match resp {
        Ok(val) => Json(Response::value(val)),
        Err(e) => Json(Response::error(format!("{}", e))),
    }
}