pragma circom 2.2.2;

include "templates.circom";

// Public values, in order: identity, key_hash, iat, session_key, expiry. A letter from scope
// "openid" signs about 660 base64url bytes
component main { public [session_key, expiry] } = Login(
    832,        // signed: 768 bytes and SHA-256 padding, a multiple of 64
    192,        // header and its dot
    768,        // payload and SHA-256 padding
    110, 93,    // aud field, value
    48, 31,     // iss field, value
    80, 62,     // sub field, value
    24, 12,     // iat field, value
    96, 78      // nonce field, value: up to 77 digits, AsciiDigitsToScalar needs one more
);
