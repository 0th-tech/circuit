use crate::main;
use super::fixtures::{
    EXPIRY, GOOGLE, IDENTITY_HASH, Letter, OTHER_ISS, SALT, SECRET, SESSION_PUBKEY,
};

/// Runs the circuit on a letter, with the fixture's salt, session key and secret
fn login(letter: Letter, expiry: u64, base64_decode_offset: u32) -> Field {
    main(
        // from_parts_unchecked keeps the bytes after len, as a prover could send them
        BoundedVec::from_parts_unchecked(letter.data, letter.data_len),
        base64_decode_offset,
        letter.pubkey_modulus_limbs,
        letter.redc_params_limbs,
        letter.signature_limbs,
        SALT,
        SESSION_PUBKEY,
        expiry,
        SECRET,
    )
}

#[test]
fn accepts_google_letter() {
    let identity = login(GOOGLE, EXPIRY, GOOGLE.base64_decode_offset);

    assert_eq(identity, IDENTITY_HASH);
}

#[test(should_fail)]
fn rejects_tampered_payload() {
    // One byte of jti changes after signing, so the claims still parse
    let mut letter = GOOGLE;
    letter.data[GOOGLE.data_len - 10] += 1;

    let _ = login(letter, EXPIRY, GOOGLE.base64_decode_offset); // (must panic)
}

#[test(should_fail_with = "incorrect value for claim")]
fn rejects_other_iss() {
    let _ = login(OTHER_ISS, EXPIRY, OTHER_ISS.base64_decode_offset); // (must panic)
}

#[test(should_fail_with = "nonce does not match the session key")]
fn rejects_stretched_expiry() {
    let _ = login(GOOGLE, EXPIRY + 1, GOOGLE.base64_decode_offset); // (must panic)
}

#[test(should_fail_with = "decode must start at the payload")]
fn rejects_shifted_offset() {
    let _ = login(GOOGLE, EXPIRY, GOOGLE.base64_decode_offset + 4); // (must panic)
}

#[test(should_fail_with = "Attempted to read past end of BoundedVec")]
fn rejects_offset_past_data() {
    // A "." planted after len, so decoding can start right after it
    let mut letter = GOOGLE;
    letter.data[GOOGLE.data_len + 4] = 46;

    let _ = login(letter, EXPIRY, GOOGLE.data_len + 5); // (must panic)
}
