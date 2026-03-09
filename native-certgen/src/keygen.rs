use crate::error::{CertGenError, Result};
use crate::types::{Algorithm, EcCurve, GeneratedKeyPair};

pub fn generate_key_pair(
    algorithm: Algorithm,
    key_size: u32,
    ec_curve: Option<EcCurve>,
    rsa_public_exponent: u64,
) -> Result<GeneratedKeyPair> {
    match algorithm {
        Algorithm::Ec => {
            let curve = ec_curve.ok_or_else(|| CertGenError::InvalidParameter("ec_curve required for EC".into()))?;
            generate_ec_key_pair(curve)
        }
        Algorithm::Rsa => generate_rsa_key_pair(key_size, rsa_public_exponent),
    }
}

fn generate_ec_key_pair(curve: EcCurve) -> Result<GeneratedKeyPair> {
    use ring::signature::KeyPair;

    let alg = match curve {
        EcCurve::P256 => &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        EcCurve::P384 => &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        _ => return Err(CertGenError::UnsupportedEcCurve(curve as i32)),
    };

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_doc = ring::signature::EcdsaKeyPair::generate_pkcs8(alg, &rng)?;
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8_doc.as_ref(), &rng)?;

    let raw_point = key_pair.public_key().as_ref();
    let spki = build_ec_spki(curve, raw_point)?;

    Ok(GeneratedKeyPair {
        private_key_pkcs8: pkcs8_doc.as_ref().to_vec(),
        public_key_spki: spki,
    })
}

/// Build SubjectPublicKeyInfo DER from a raw EC uncompressed point.
fn build_ec_spki(curve: EcCurve, raw_point: &[u8]) -> Result<Vec<u8>> {
    // SPKI = SEQUENCE { AlgorithmIdentifier, BIT STRING(public key) }
    // AlgorithmIdentifier = SEQUENCE { OID(ecPublicKey), OID(curve) }
    //
    // DER-encode manually — the prefix is fixed per curve, only the point varies.

    // OID 1.2.840.10045.2.1 (id-ecPublicKey)
    const EC_PUBLIC_KEY_OID: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

    let curve_oid: &[u8] = match curve {
        // OID 1.2.840.10045.3.1.7 (prime256v1 / P-256)
        EcCurve::P256 => &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        // OID 1.3.132.0.34 (secp384r1 / P-384)
        EcCurve::P384 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
        _ => return Err(CertGenError::UnsupportedEcCurve(curve as i32)),
    };

    let alg_id_seq = der_sequence(EC_PUBLIC_KEY_OID, curve_oid);

    // BIT STRING: 0x03, length, 0x00 (unused bits), raw_point
    let bit_string_content_len = 1 + raw_point.len(); // 0x00 byte + point
    let mut bit_string = vec![0x03];
    encode_der_length(&mut bit_string, bit_string_content_len);
    bit_string.push(0x00); // zero unused bits
    bit_string.extend_from_slice(raw_point);

    // Outer SEQUENCE
    let inner_len = alg_id_seq.len() + bit_string.len();
    let mut spki = vec![0x30];
    encode_der_length(&mut spki, inner_len);
    spki.extend_from_slice(&alg_id_seq);
    spki.extend_from_slice(&bit_string);

    Ok(spki)
}

fn der_sequence(a: &[u8], b: &[u8]) -> Vec<u8> {
    let content_len = a.len() + b.len();
    let mut seq = vec![0x30];
    encode_der_length(&mut seq, content_len);
    seq.extend_from_slice(a);
    seq.extend_from_slice(b);
    seq
}

fn encode_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

fn generate_rsa_key_pair(key_size: u32, rsa_public_exponent: u64) -> Result<GeneratedKeyPair> {
    use pkcs8::EncodePrivateKey;
    use rsa::pkcs8::EncodePublicKey;

    if !matches!(key_size, 2048 | 3072 | 4096) {
        return Err(CertGenError::InvalidParameter(
            format!("RSA key size must be 2048, 3072, or 4096; got {key_size}")
        ));
    }

    let exp = if rsa_public_exponent == 0 {
        rsa::BigUint::from(65537u64)
    } else {
        rsa::BigUint::from(rsa_public_exponent)
    };

    let mut rng = rand::thread_rng();
    let private_key = rsa::RsaPrivateKey::new_with_exp(&mut rng, key_size as usize, &exp)
        .map_err(|e| CertGenError::KeyGenFailed(e.to_string()))?;

    let pkcs8_der = private_key.to_pkcs8_der()
        .map_err(|e| CertGenError::SerializationFailed(e.to_string()))?;

    let public_key = private_key.to_public_key();
    let pub_der = public_key.to_public_key_der()
        .map_err(|e| CertGenError::SerializationFailed(e.to_string()))?;

    Ok(GeneratedKeyPair {
        private_key_pkcs8: pkcs8_der.as_bytes().to_vec(),
        public_key_spki: pub_der.as_ref().to_vec(),
    })
}
