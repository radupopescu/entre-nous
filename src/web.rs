//
// Copyright 2021 Radu Popescu <mail@radupopescu.net>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod pw;
pub mod srp;

use serde::Serialize;

#[derive(Serialize)]
pub enum Response<T> {
    Value(T),
    Error(String),
}

impl<T> Response<T> {
    pub fn value(value: T) -> Self {
        Response::Value(value)
    }

    pub fn error(error: String) -> Self {
        Response::Error(error)
    }
}