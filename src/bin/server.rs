//
// Copyright 2021 Radu Popescu <mail@radupopescu.net>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[macro_use]
extern crate rocket;

use entre_nous::web::{
    pw::derive_key as pw_derive_key,
    srp::{
        srp_client_generate_ephemerals, srp_client_generate_proof,
        srp_client_generate_registration_data, srp_client_verify_server,
        srp_server_generate_ephemerals, srp_server_verify_client,
    },
};

#[launch]
fn serve() -> _ {
    rocket::build().mount(
        "/",
        routes![
            pw_derive_key,
            srp_client_generate_registration_data,
            srp_client_generate_ephemerals,
            srp_client_generate_proof,
            srp_client_verify_server,
            srp_server_generate_ephemerals,
            srp_server_verify_client,
        ],
    )
}
