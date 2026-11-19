/**
 * The login circuit: a Google letter (an RS256 JWT) approves a session key until an expiry.
 *
 * Parts of this file are adapted from aptos-labs/keyless-zk-proofs, circuit/templates/keyless.circom
 * (dc10a06), under the Apache License 2.0 in aptos/LICENSE. The templates under aptos/ are Aptos's,
 * unchanged.
 */
pragma circom 2.2.2;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

include "./aptos/helpers/strings/AssertIsConcatenation.circom";
include "./aptos/helpers/base64url/Base64UrlDecode.circom";
include "./aptos/helpers/base64url/Base64UrlDecodedLength.circom";
include "./aptos/helpers/bigint/BigLessThan.circom";
include "./aptos/helpers/hashtofield/Hash64BitLimbsToFieldWithLen.circom";
include "./aptos/helpers/jwt/BracketsMap.circom";
include "./aptos/helpers/jwt/BracketsDepthMap.circom";
include "./aptos/helpers/jwt/EnforceNotNested.circom";
include "./aptos/helpers/jwt/ParseJWTFieldWithQuotedValue.circom";
include "./aptos/helpers/jwt/ParseJWTFieldWithUnquotedValue.circom";
include "./aptos/helpers/jwt/StringBodies.circom";
include "./aptos/helpers/packing/BigEndianBitsToScalars.circom";
include "./aptos/helpers/rsa/RSA_PKCS1_v1_5_Verify.circom";
include "./aptos/helpers/sha/SHA2_256_PaddingVerify.circom";
include "./aptos/helpers/sha/SHA2_256_Prepadded_Hash.circom";
include "./aptos/helpers/strings/AsciiDigitsToScalar.circom";
include "./aptos/stdlib/circuits/ElementwiseMul.circom";
include "./aptos/stdlib/circuits/InvertBinaryArray.circom";

// The only issuer accepted, https://accounts.google.com, in ASCII
function googleIssuer() {
    var issuer[27] = [104, 116, 116, 112, 115, 58, 47, 47, 97, 99, 99, 111, 117, 110, 116, 115, 46,
        103, 111, 111, 103, 108, 101, 46, 99, 111, 109];
    return issuer;
}

// Text packed 31 bytes per field element, big-endian. The bytes from len on count as 0, so the
// result does not depend on what the prover puts after the text
template Pack31(MAX_LEN) {
    assert(MAX_LEN % 31 == 0);
    assert(MAX_LEN < 1024);
    signal input in[MAX_LEN];
    signal input len;
    signal output out[MAX_LEN \ 31];

    signal keep[MAX_LEN];
    signal masked[MAX_LEN];
    for (var i = 0; i < MAX_LEN; i++) {
        keep[i] <== LessThan(10)([i, len]);
        masked[i] <== in[i] * keep[i];
    }
    for (var i = 0; i < MAX_LEN \ 31; i++) {
        var acc = 0;
        for (var j = 0; j < 31; j++) {
            acc = acc * 256 + masked[i * 31 + j];
        }
        out[i] <== acc;
    }
}

// A "name":"value" field of the payload, at index, outside any string and at the top level of the
// JSON object
template QuotedField(MAX_PAYLOAD_LEN, MAX_KV_LEN, MAX_NAME_LEN, MAX_VALUE_LEN, NAME_LEN) {
    signal input payload[MAX_PAYLOAD_LEN];
    signal input payload_hash;
    signal input string_bodies[MAX_PAYLOAD_LEN];
    signal input depth_map[MAX_PAYLOAD_LEN];
    signal input expected_name[NAME_LEN];

    signal input field[MAX_KV_LEN];
    signal input field_string_bodies[MAX_KV_LEN];
    signal input field_len;
    signal input index;
    signal input value_index;
    signal input colon_index;
    signal input name[MAX_NAME_LEN];
    signal input value[MAX_VALUE_LEN];
    signal input value_len;

    AssertIsSubstring(MAX_PAYLOAD_LEN, MAX_KV_LEN)(payload, payload_hash, field, field_len, index);
    AssertIsSubstring(MAX_PAYLOAD_LEN, MAX_KV_LEN)(string_bodies, payload_hash, field_string_bodies, field_len, index);
    EnforceNotNested(MAX_PAYLOAD_LEN)(index, field_len, depth_map);

    ParseJWTFieldWithQuotedValue(MAX_KV_LEN, MAX_NAME_LEN, MAX_VALUE_LEN)(
        field, name, value, field_string_bodies, field_len, NAME_LEN, value_index, value_len, colon_index, 0
    );
    for (var i = 0; i < NAME_LEN; i++) {
        name[i] === expected_name[i];
    }
}

template AssertIssuer(MAX_LEN) {
    signal input value[MAX_LEN];
    signal input len;

    var ISSUER[27] = googleIssuer();
    len === 27;
    for (var i = 0; i < 27; i++) {
        value[i] === ISSUER[i];
    }
}

// The nonce Google signed, in decimal, is Poseidon(session key, expiry, secret)
template AssertNonce(MAX_LEN) {
    signal input digits[MAX_LEN];
    signal input len;
    signal input session_key;
    signal input expiry;
    signal input secret;

    signal nonce <== AsciiDigitsToScalar(MAX_LEN)(digits, len);
    signal expected <== Poseidon(3)([session_key, expiry, secret]);
    nonce === expected;
}

// The account's identity, Poseidon(iss, aud, its length, sub, its length, salt), each text packed by
// Pack31. The browser computes the same hash to find the account's address, so this layout must never
// change
template IdentityHash(MAX_AUD_LEN, MAX_SUB_LEN) {
    signal input aud[MAX_AUD_LEN];
    signal input aud_len;
    signal input sub[MAX_SUB_LEN];
    signal input sub_len;
    signal input salt;
    signal output out;

    var ISSUER[27] = googleIssuer();
    var issuer_packed = 0;
    for (var i = 0; i < 31; i++) {
        issuer_packed = issuer_packed * 256 + (i < 27 ? ISSUER[i] : 0);
    }
    signal aud_packed[MAX_AUD_LEN \ 31] <== Pack31(MAX_AUD_LEN)(aud, aud_len);
    signal sub_packed[MAX_SUB_LEN \ 31] <== Pack31(MAX_SUB_LEN)(sub, sub_len);
    out <== Poseidon(9)([
        issuer_packed,
        aud_packed[0], aud_packed[1], aud_packed[2], aud_len,
        sub_packed[0], sub_packed[1], sub_len,
        salt
    ]);
}

// RSA-2048 with e = 65537 over the 256-bit SHA-256 of the letter
template RSA_2048_e_65537_PKCS1_V1_5_Verify(LIMB_BITS, LIMBS) {
    signal input signature[LIMBS];
    signal input modulus[LIMBS];
    signal input message_bits[256];

    signal message_limbs[4] <== BigEndianBitsToScalars(256, LIMB_BITS)(message_bits);

    AssertIs64BitLimbs(LIMBS)(signature);
    signal below_modulus <== BigLessThan(252, LIMBS)(signature, modulus);
    below_modulus === 1;

    var message_limbs_le[4];
    for (var i = 0; i < 4; i++) {
        message_limbs_le[i] = message_limbs[3 - i];
    }

    RSA_PKCS1_v1_5_Verify(LIMB_BITS, LIMBS)(signature, modulus, message_limbs_le);
}

template Login(
    MAX_SIGNED_LEN,         // base64url header, dot and payload, with SHA-256 padding
    MAX_HEADER_LEN,         // base64url header and its dot
    MAX_PAYLOAD_LEN,        // base64url payload with SHA-256 padding
    MAX_AUD_KV_LEN, MAX_AUD_LEN,
    MAX_ISS_KV_LEN, MAX_ISS_LEN,
    MAX_SUB_KV_LEN, MAX_SUB_LEN,
    MAX_IAT_KV_LEN, MAX_IAT_LEN,
    MAX_NONCE_KV_LEN, MAX_NONCE_LEN
) {
    _ = assert_bits_fit_scalar(253);

    var MAX_NAME_LEN = 10;
    var LIMBS = 32;
    var MAX_DECODED_LEN = (3 * MAX_PAYLOAD_LEN) \ 4;

    /** Public values **/

    signal input session_key;
    signal input expiry;

    signal output identity;
    signal output key_hash;
    signal output iat;

    /** Private inputs **/

    signal input secret;
    signal input salt;

    //
    // The signed letter: header, dot and payload, then SHA-256 and RSA over them
    //

    signal input signed[MAX_SIGNED_LEN];
    signal input header[MAX_HEADER_LEN];
    signal input header_len;
    signal input payload_padded[MAX_PAYLOAD_LEN];
    signal input payload_len;

    AssertIsConcatenation(MAX_SIGNED_LEN, MAX_HEADER_LEN, MAX_PAYLOAD_LEN)(
        signed, header, payload_padded, header_len, payload_len
    );

    // The payload starts right after the dot, so no claim can be read from the header
    signal dot <== SelectArrayValue(MAX_SIGNED_LEN)(signed, header_len - 1);
    dot === 46;

    signal input payload[MAX_PAYLOAD_LEN];
    AssertIsSubstring(MAX_PAYLOAD_LEN, MAX_PAYLOAD_LEN)(
        str <== payload_padded,
        str_hash <== HashBytesToFieldWithLen(MAX_PAYLOAD_LEN)(payload_padded, payload_len),
        substr <== payload,
        substr_len <== payload_len,
        start_index <== 0
    );

    signal input sha2_num_blocks;
    signal input sha2_num_bits[8];
    signal input sha2_padding[64];
    SHA2_256_PaddingVerify(MAX_SIGNED_LEN)(
        signed, sha2_num_blocks, header_len + payload_len, sha2_num_bits, sha2_padding
    );
    signal hash[256] <== SHA2_256_Prepadded_Hash((MAX_SIGNED_LEN * 8) \ 512)(
        in <== Bytes2BigEndianBits(MAX_SIGNED_LEN)(signed),
        tBlock <== sha2_num_blocks - 1
    );

    signal input signature[LIMBS];
    signal input modulus[LIMBS];
    RSA_2048_e_65537_PKCS1_V1_5_Verify(64, LIMBS)(signature, modulus, hash);

    //
    // The payload decoded, and the maps that keep a claim out of strings and nested objects
    //

    signal decoded[MAX_DECODED_LEN] <== Base64UrlDecode(MAX_DECODED_LEN)(payload);
    signal decoded_len <== Base64UrlDecodedLength(MAX_PAYLOAD_LEN)(payload_len);
    signal decoded_hash <== HashBytesToFieldWithLen(MAX_DECODED_LEN)(decoded, decoded_len);

    signal string_bodies[MAX_DECODED_LEN] <== StringBodies(MAX_DECODED_LEN)(decoded);
    signal outside_strings[MAX_DECODED_LEN] <== InvertBinaryArray(MAX_DECODED_LEN)(string_bodies);
    signal brackets[MAX_DECODED_LEN] <== BracketsMap(MAX_DECODED_LEN)(decoded);
    signal unquoted_brackets[MAX_DECODED_LEN] <== ElementwiseMul(MAX_DECODED_LEN)(outside_strings, brackets);
    signal depth[MAX_DECODED_LEN] <== BracketsDepthMap(MAX_DECODED_LEN)(unquoted_brackets);

    //
    // The claims
    //

    signal input aud_field[MAX_AUD_KV_LEN];
    signal input aud_field_string_bodies[MAX_AUD_KV_LEN];
    signal input aud_field_len;
    signal input aud_index;
    signal input aud_value_index;
    signal input aud_colon_index;
    signal input aud_name[MAX_NAME_LEN];
    signal input aud_value[MAX_AUD_LEN];
    signal input aud_value_len;
    QuotedField(MAX_DECODED_LEN, MAX_AUD_KV_LEN, MAX_NAME_LEN, MAX_AUD_LEN, 3)(
        decoded, decoded_hash, string_bodies, depth, [97, 117, 100],
        aud_field, aud_field_string_bodies, aud_field_len, aud_index, aud_value_index, aud_colon_index,
        aud_name, aud_value, aud_value_len
    );

    signal input sub_field[MAX_SUB_KV_LEN];
    signal input sub_field_string_bodies[MAX_SUB_KV_LEN];
    signal input sub_field_len;
    signal input sub_index;
    signal input sub_value_index;
    signal input sub_colon_index;
    signal input sub_name[MAX_NAME_LEN];
    signal input sub_value[MAX_SUB_LEN];
    signal input sub_value_len;
    QuotedField(MAX_DECODED_LEN, MAX_SUB_KV_LEN, MAX_NAME_LEN, MAX_SUB_LEN, 3)(
        decoded, decoded_hash, string_bodies, depth, [115, 117, 98],
        sub_field, sub_field_string_bodies, sub_field_len, sub_index, sub_value_index, sub_colon_index,
        sub_name, sub_value, sub_value_len
    );

    signal input iss_field[MAX_ISS_KV_LEN];
    signal input iss_field_string_bodies[MAX_ISS_KV_LEN];
    signal input iss_field_len;
    signal input iss_index;
    signal input iss_value_index;
    signal input iss_colon_index;
    signal input iss_name[MAX_NAME_LEN];
    signal input iss_value[MAX_ISS_LEN];
    signal input iss_value_len;
    QuotedField(MAX_DECODED_LEN, MAX_ISS_KV_LEN, MAX_NAME_LEN, MAX_ISS_LEN, 3)(
        decoded, decoded_hash, string_bodies, depth, [105, 115, 115],
        iss_field, iss_field_string_bodies, iss_field_len, iss_index, iss_value_index, iss_colon_index,
        iss_name, iss_value, iss_value_len
    );
    AssertIssuer(MAX_ISS_LEN)(iss_value, iss_value_len);

    signal input nonce_field[MAX_NONCE_KV_LEN];
    signal input nonce_field_string_bodies[MAX_NONCE_KV_LEN];
    signal input nonce_field_len;
    signal input nonce_index;
    signal input nonce_value_index;
    signal input nonce_colon_index;
    signal input nonce_name[MAX_NAME_LEN];
    signal input nonce_value[MAX_NONCE_LEN];
    signal input nonce_value_len;
    QuotedField(MAX_DECODED_LEN, MAX_NONCE_KV_LEN, MAX_NAME_LEN, MAX_NONCE_LEN, 5)(
        decoded, decoded_hash, string_bodies, depth, [110, 111, 110, 99, 101],
        nonce_field, nonce_field_string_bodies, nonce_field_len, nonce_index, nonce_value_index,
        nonce_colon_index, nonce_name, nonce_value, nonce_value_len
    );

    // iat is a bare number: no quotes, so no string bodies to compare
    signal input iat_field[MAX_IAT_KV_LEN];
    signal input iat_field_len;
    signal input iat_index;
    signal input iat_value_index;
    signal input iat_colon_index;
    signal input iat_name[MAX_NAME_LEN];
    signal input iat_value[MAX_IAT_LEN];
    signal input iat_value_len;
    AssertIsSubstring(MAX_DECODED_LEN, MAX_IAT_KV_LEN)(decoded, decoded_hash, iat_field, iat_field_len, iat_index);
    EnforceNotNested(MAX_DECODED_LEN)(iat_index, iat_field_len, depth);
    ParseJWTFieldWithUnquotedValue(MAX_IAT_KV_LEN, MAX_NAME_LEN, MAX_IAT_LEN)(
        iat_field, iat_name, iat_value, iat_field_len, 3, iat_value_index, iat_value_len, iat_colon_index, 0
    );
    signal iat_in_string <== SelectArrayValue(MAX_DECODED_LEN)(string_bodies, iat_index);
    iat_in_string === 0;
    var IAT_NAME[3] = [105, 97, 116];
    for (var i = 0; i < 3; i++) {
        iat_name[i] === IAT_NAME[i];
    }

    //
    // The public values
    //

    _ <== Num2Bits(64)(expiry);
    AssertNonce(MAX_NONCE_LEN)(nonce_value, nonce_value_len, session_key, expiry, secret);

    identity <== IdentityHash(MAX_AUD_LEN, MAX_SUB_LEN)(
        aud_value, aud_value_len, sub_value, sub_value_len, salt
    );

    // The registry knows Google's keys by this hash
    AssertIs64BitLimbs(LIMBS)(modulus);
    signal {maxbits} modulus_limbs[LIMBS];
    modulus_limbs.maxbits = 64;
    modulus_limbs <== modulus;
    key_hash <== Hash64BitLimbsToFieldWithLen(LIMBS)(modulus_limbs, 256);

    iat <== AsciiDigitsToScalar(MAX_IAT_LEN)(iat_value, iat_value_len);
}
