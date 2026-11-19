import crypto from "node:crypto";
import fs from "node:fs";
import { getStarkKey } from "@scure/starknet";
import { poseidon3, poseidon9 } from "poseidon-lite";
import type { Session } from "./inputs.ts";

const GOOGLE_ISS = "https://accounts.google.com";
export const CLIENT_ID =
  "123456789012-0123456789abcdef0123456789abcdef.apps.googleusercontent.com";
export const SUB = "123456789012345678901";
export const KID = "0123456789abcdef0123456789abcdef01234567";

// A real Stark key pair: contract tests sign with it
export const SESSION_PRIVKEY = "0x1234567890abcdef";

export const SESSION: Session = {
  sessionKey: BigInt(getStarkKey(SESSION_PRIVKEY)),
  expiry: 1800000000n, // Unix seconds (2027-01-15)
  secret: 2n,
  salt: 12345n, // the real one is derived per user
};

// A test key shaped like Google's: 2048 bits, exponent 65537
const privateKey = crypto.createPrivateKey(
  fs.readFileSync(new URL("../fixtures/test_rsa_key.pem", import.meta.url)),
);
export const jwk = crypto.createPublicKey(privateKey).export({ format: "jwk" });
export const modulus = BigInt(
  `0x${Buffer.from(jwk.n!, "base64url").toString("hex")}`,
);

// Browser side: nonce = H(session key, expiry, secret), in decimal
const nonce = (session: Session) =>
  poseidon3([session.sessionKey, session.expiry, session.secret]).toString();

// The claims, order and formats of Google's letter for scope "openid"
export const claims = (session: Session) => ({
  iss: GOOGLE_ISS,
  azp: CLIENT_ID,
  aud: CLIENT_ID,
  sub: SUB,
  nonce: nonce(session),
  nbf: 1737641917,
  iat: 1737642217,
  // Far ahead, since the server checks it against the real clock
  exp: 4102444799, // 2099-12-31
  jti: "0123456789abcdef0123456789abcdef01234567",
});

// A JWT signed by the test key
export function sign(payload: object) {
  const header = { alg: "RS256", kid: KID, typ: "JWT" };
  const b64 = (part: object) =>
    Buffer.from(JSON.stringify(part)).toString("base64url");
  const signedData = `${b64(header)}.${b64(payload)}`;
  const signature = crypto.sign("sha256", Buffer.from(signedData), privateKey);
  return `${signedData}.${signature.toString("base64url")}`;
}

// Same as the circuit's Pack31: 31 bytes per element, big-endian, padded with 0 bytes
const pack = (text: string, max: number) => {
  const padded = Buffer.alloc(max);
  Buffer.from(text).copy(padded);
  return Array.from({ length: max / 31 }, (_, i) =>
    BigInt(`0x${padded.subarray(i * 31, (i + 1) * 31).toString("hex")}`),
  );
};

// Same as the circuit's IdentityHash
export const identityHash = (aud: string, sub: string, salt: bigint) =>
  poseidon9([
    ...pack(GOOGLE_ISS, 31),
    ...pack(aud, 93),
    BigInt(aud.length),
    ...pack(sub, 62),
    BigInt(sub.length),
    salt,
  ]);
