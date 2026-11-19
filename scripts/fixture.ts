import fs from "node:fs";
import { circuitInputs, keyHash } from "./inputs.ts";
import {
  CLIENT_ID,
  KID,
  SESSION,
  SESSION_PRIVKEY,
  SUB,
  claims,
  identityHash,
  jwk,
  modulus,
  sign,
} from "./letter.ts";

const write = (path: string, text: string) =>
  fs.writeFileSync(new URL(path, import.meta.url), text);

const payload = claims(SESSION);
const jwt = sign(payload);

// The fixture letter's circuit inputs, which `make proof` proves
write(
  "../fixtures/input.json",
  `${JSON.stringify(circuitInputs(jwt, modulus, SESSION))}\n`,
);

// The valid letter as text, with the key that signed it and the values its proof makes public
const fixture = {
  jwt,
  jwk: { ...jwk, kid: KID, alg: "RS256" },
  aud: CLIENT_ID,
  sub: SUB,
  session_privkey: SESSION_PRIVKEY,
  session_pubkey: String(SESSION.sessionKey),
  expiry: String(SESSION.expiry),
  secret: String(SESSION.secret),
  salt: String(SESSION.salt),
  iat: String(payload.iat),
  key_hash: String(keyHash(modulus)),
  identity_hash: String(identityHash(CLIENT_ID, SUB, SESSION.salt)),
};
write("../fixtures/fixture.json", `${JSON.stringify(fixture, null, 2)}\n`);
