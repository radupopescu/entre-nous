//
// Copyright 2021 Radu Popescu <mail@radupopescu.net>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use {
    crate::{
        password_hash::{derive_key as pwhash_derive_key, Salt},
        web::Response,
        Result,
    },
    rocket::serde::{json::Json, Deserialize},
};

#[derive(Deserialize)]
pub struct Request {
    password: String,
    salt: String,
}

#[post("/pw/derive_key", data = "<input>")]
pub fn derive_key(input: Json<Request>) -> Json<Response<String>> {
    let resp: Result<String> = (|| {
        let salt_bytes = base64::decode(&input.salt)?;
        let salt = Salt::from_slice(&salt_bytes)?;
        let mut private_key = vec![0u8; 32];
        pwhash_derive_key(&mut private_key, input.password.as_bytes(), &salt)?;
        Ok(base64::encode(private_key.to_owned()))
    })();
    match resp {
        Ok(val) => Json(Response::value(val)),
        Err(e) => Json(Response::error(format!("{}", e))),
    }
}

