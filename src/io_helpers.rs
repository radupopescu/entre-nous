//
// Copyright 2021 Radu Popescu <mail@radupopescu.net>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::io::ErrorKind;

use crate::{Error, Result};

pub(crate) fn read<S>(source: &mut S, buf: &mut [u8]) -> Result<usize>
where
    S: std::io::Read + ?Sized,
{
    loop {
        match source.read(buf) {
            Ok(read_bytes) => return Ok(read_bytes),
            Err(e) => {
                if e.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(Error::IO(e));
            }
        }
    }
}

pub(crate) fn write<D>(dest: &mut D, data: &[u8]) -> Result<usize>
where
    D: std::io::Write + ?Sized,
{
    loop {
        match dest.write(data) {
            Ok(written_bytes) => return Ok(written_bytes),
            Err(e) => {
                if e.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(Error::IO(e));
            }
        }
    }
}
