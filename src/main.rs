// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::Network;
use bdk::keys::bip39::{Language, Mnemonic, WordCount};
use bdk::bitcoin::util::bip32::{DerivationPath, KeySource};
use bdk::keys::{DerivableKey, DescriptorKey, ExtendedKey, GeneratableKey, GeneratedKey};
use bdk::miniscript::{ miniscript, Segwitv0};
use bdk::keys::DescriptorKey::Secret;
use bdk::keys::KeyError::Message;
use bdk::Error as BDK_ERROR;
use std::error::Error;
use std::str::FromStr;


fn main() -> Result<(), Box<dyn Error>> {
    let secp = Secp256k1::new();
    let mnemonic: GeneratedKey<_, miniscript::BareCtx> =
        Mnemonic::generate((WordCount::Words12, Language::English))
            .map_err(|_| BDK_ERROR::Generic("Mnemonic generation error".to_string()))?;
    let mnemonic = mnemonic.into_key();
    let xkey: ExtendedKey = (mnemonic.clone(), None).into_extended_key()?;
    let xprv = xkey.into_xprv(Network::Regtest).ok_or_else(|| {
        BDK_ERROR::Generic("Privatekey info not found (should not happen)".to_string())
    })?;
    let fingerprint = xprv.fingerprint(&secp);
    let phrase = mnemonic
        .word_iter()
        .fold("".to_string(), |phrase, w| phrase + w + " ")
        .trim()
        .to_string();
    println!("Mnemonic phrase: {}", phrase);
    println!("Xprv fingerprint: {}", fingerprint);

    // You can replace this derivation path with one of your choosing
    let path = DerivationPath::from_str("m/84h/0h/0h").unwrap();

    let derived_xprv = &xprv.derive_priv(&secp, &path)?;

    let origin: KeySource = (fingerprint, path);

    let derived_xprv_desc_key: DescriptorKey<Segwitv0> =
        derived_xprv.into_descriptor_key(Some(origin), DerivationPath::default())?;

    if let Secret(desc_seckey, _, _) = derived_xprv_desc_key {
        let desc_pubkey = desc_seckey
            .as_public(&secp).map_err(|e| BDK_ERROR::Generic(e.to_string()))?;
        println!("xpub {}", desc_pubkey.to_string());
        println!("xprv {}", desc_seckey.to_string());
    } else {
        return Err(Box::new(BDK_ERROR::Key(Message("Invalid key variant".to_string()))));
    }

    Ok(())
}
