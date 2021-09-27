//
// Copyright 2021 Radu Popescu <mail@radupopescu.net>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::convert::TryInto;

use sodiumoxide::crypto::sign::{
    gen_keypair, sign_detached, verify_detached, PublicKey as SodiumPublicKey,
    SecretKey as SodiumSecretKey, Signature as SodiumSignature, State,
    SIGNATUREBYTES as SODIUM_SIGNATUREBYTES,
};

use crate::{errors::Result, Error};

const SIGNATUREBYTES: usize = SODIUM_SIGNATUREBYTES;

pub struct Signature(SodiumSignature);

impl Signature {
    pub fn new(buf: &[u8]) -> Result<Signature> {
        let s = SodiumSignature::new(buf.try_into()?);
        Ok(Signature(s))
    }

    pub fn to_bytes(&self) -> [u8; SIGNATUREBYTES] {
        let Signature(s) = self;
        s.to_bytes()
    }

    fn sodium_signature(&self) -> &SodiumSignature {
        let Signature(s) = self;
        s
    }
}

#[derive(Clone)]
pub struct SecretKey(SodiumSecretKey);

impl SecretKey {
    fn sodium_secret_key(&self) -> &SodiumSecretKey {
        let SecretKey(key) = &self;
        key
    }
}

#[derive(Clone)]
pub struct PublicKey(SodiumPublicKey);

impl PublicKey {
    fn sodium_public_key(&self) -> &SodiumPublicKey {
        let PublicKey(key) = &self;
        key
    }

    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> Result<()> {
        if !verify_detached(signature.sodium_signature(), msg, self.sodium_public_key()) {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

pub struct SignatureStream {
    state: State,
}

impl SignatureStream {
    pub fn new() -> SignatureStream {
        SignatureStream {
            state: State::init(),
        }
    }

    pub fn push(&mut self, m: &[u8]) {
        self.state.update(m);
    }

    pub fn finalize(self, secret_key: &SecretKey) -> Signature {
        Signature(self.state.finalize(&secret_key.sodium_secret_key()))
    }

    pub fn verify(&mut self, signature: &Signature, public_key: &PublicKey) -> Result<()> {
        if !self
            .state
            .verify(signature.sodium_signature(), public_key.sodium_public_key())
        {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct KeyPair {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl KeyPair {
    pub fn new() -> KeyPair {
        let (public_key, secret_key) = gen_keypair();
        KeyPair {
            secret_key: SecretKey(secret_key),
            public_key: PublicKey(public_key),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(sign_detached(msg, &self.secret_key.sodium_secret_key()))
    }

    pub fn verify(&self, sig: &Signature, msg: &[u8]) -> Result<()> {
        self.public_key().verify(sig, msg)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{errors::Result, init, tests::message_strategy};

    proptest! {
        #[test]
        fn sign_and_verify(msg in message_strategy(1000)) {
            init()?;
            let key_pair = KeyPair::new();

            let sig = key_pair.sign(msg.as_slice());
            prop_assert!(key_pair.verify(&sig, msg.as_slice()).is_ok());
        }
    }

    #[test]
    fn sign_and_verify_stream() -> Result<()> {
        init()?;
        let key_pair = KeyPair::new();
        let msg = "VERY LONG MESSAGE".as_bytes();

        let mut sig_stream = SignatureStream::new();
        sig_stream.push(&msg[..10]);
        sig_stream.push(&msg[10..]);
        let sig1 = sig_stream.finalize(key_pair.secret_key());

        let mut verif_stream = SignatureStream::new();
        verif_stream.push(&msg);
        verif_stream.verify(&sig1, key_pair.public_key())?;

        Ok(())
    }
}
