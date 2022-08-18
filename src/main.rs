use bdk::keys::bip39::{Language, Mnemonic, WordCount};
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::Network;
use bdk::keys::{ GeneratedKey, GeneratableKey, ExtendedKey, DerivableKey};
use bdk::miniscript::miniscript;
use bdk::Error;


fn main() {
    let secp = Secp256k1::new();
    let mnemonic: GeneratedKey<_, miniscript::BareCtx> = Mnemonic::generate((WordCount::Words12, Language::English))
    .map_err(|_| Error::Generic("Mnemonic generation error".to_string())).expect("Failed to generate mnemonic");
    let mnemonic = mnemonic.into_key();
    let xkey: ExtendedKey = (mnemonic.clone(), None).into_extended_key().expect("key derivation failed"); //None because I don't have a password on my mnemonic
    let xprv = xkey.into_xprv(Network::Regtest).ok_or_else(|| {
                Error::Generic("Privatekey info not found (should not happen)".to_string())
    }).expect("xprv derviation failed");
    let fingerprint = xprv.fingerprint(&secp);
    let phrase = mnemonic
            .word_iter()
            .fold("".to_string(), |phrase, w| phrase + w + " ")
            .trim()
            .to_string();
    println!("Mnemonic phrase: {}", phrase);
    println!("Xprv fingerprint: {}", fingerprint)

}
