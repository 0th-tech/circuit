import { poseidon12 } from "poseidon-lite";

// Same sizes as src/login.circom
const MAX = {
  signed: 832,
  header: 192,
  payload: 768,
  name: 10,
  aud: { field: 110, value: 93 },
  iss: { field: 48, value: 31 },
  sub: { field: 80, value: 62 },
  iat: { field: 24, value: 12 },
  nonce: { field: 96, value: 78 },
} as const;

type Claim = "aud" | "iss" | "sub" | "iat" | "nonce";

// Inputs the letter does not hold
export type Session = {
  sessionKey: bigint;
  expiry: bigint;
  secret: bigint;
  salt: bigint;
};

type Inputs = Record<string, string | string[]>;

const bytes = (text: string) => [...Buffer.from(text, "latin1")];

const padded = (values: number[], max: number) => {
  if (values.length > max)
    throw new Error(`${values.length} bytes, the circuit takes ${max}`);
  return [...values, ...Array(max - values.length).fill(0)].map(String);
};

// RSA-2048 numbers as 32 limbs of 64 bits, least significant first
export const limbs = (n: bigint) =>
  Array.from(
    { length: 32 },
    (_, i) => (n >> BigInt(64 * i)) & (2n ** 64n - 1n),
  );

// The circuit's key_hash: 3 limbs per element, then the key's size in bytes
export function keyHash(modulus: bigint) {
  const l = limbs(modulus);
  const elements = Array.from({ length: 11 }, (_, i) =>
    l
      .slice(3 * i, 3 * i + 3)
      .reduce((acc, limb, j) => acc + (limb << BigInt(64 * j)), 0n),
  );
  return poseidon12([...elements, 256n]);
}

// The circuit's StringBodies: 1 strictly inside a string, 0 on its quotes and outside
function stringBodies(json: string) {
  const out = [0];
  let parity = json[0] === '"' ? 1 : 0;
  let escaped = json[0] === "\\";
  for (let i = 1; i < json.length; i++) {
    const quote = json[i] === '"' && !escaped ? 1 : 0;
    const next = parity ^ quote;
    out.push(parity & next);
    parity = next;
    escaped = json[i] === "\\" && !escaped;
  }
  return out;
}

// The field "name":value at index in the decoded payload, as the circuit's parsers take it
function field(
  json: string,
  bodies: number[],
  name: Claim,
  index: number,
  quoted: boolean,
) {
  const colon = json.indexOf(":", index) - index;
  const valueIndex = colon + (quoted ? 2 : 1);
  const valueEnd = quoted
    ? json.indexOf('"', index + valueIndex) - index
    : json.slice(index).search(/[,}]/);
  const length = valueEnd + (quoted ? 2 : 1);
  const text = json.slice(index, index + length);
  const value = text.slice(valueIndex, valueEnd);
  const inputs: Inputs = {
    [`${name}_field`]: padded(bytes(text), MAX[name].field),
    [`${name}_field_len`]: String(text.length),
    [`${name}_index`]: String(index),
    [`${name}_value_index`]: String(valueIndex),
    [`${name}_colon_index`]: String(colon),
    [`${name}_name`]: padded(bytes(name), MAX.name),
    [`${name}_value`]: padded(bytes(value), MAX[name].value),
    [`${name}_value_len`]: String(value.length),
  };
  if (quoted)
    inputs[`${name}_field_string_bodies`] = padded(
      bodies.slice(index, index + length),
      MAX[name].field,
    );
  return inputs;
}

// Circuit inputs for a letter signed by the RSA key with this modulus. Each claim is read at its first
// occurrence
export function circuitInputs(
  jwt: string,
  modulus: bigint,
  session: Session,
): Inputs {
  const [header, payload, signature] = jwt.split(".");
  if (!header || !payload || !signature) throw new Error("not a JWT");
  const signed = `${header}.${payload}`;

  // SHA-256 padding: 0x80, zeros up to 56 bytes mod 64, then the length in bits on 8 bytes
  const bits = BigInt(signed.length * 8);
  const zeros = (119 - (signed.length % 64)) % 64;
  const length = Array.from({ length: 8 }, (_, i) =>
    Number((bits >> BigInt(8 * (7 - i))) & 0xffn),
  );
  const signedPadded = [
    ...bytes(signed),
    0x80,
    ...Array(zeros).fill(0),
    ...length,
  ];
  const headerWithDot = bytes(`${header}.`);

  const json = Buffer.from(payload, "base64url").toString("latin1");
  const bodies = stringBodies(json);
  const read = (name: Claim, quoted = true) => {
    const index = json.indexOf(`"${name}":`);
    if (index < 0) throw new Error(`the letter has no ${name}`);
    return field(json, bodies, name, index, quoted);
  };

  return {
    signed: padded(signedPadded, MAX.signed),
    header: padded(headerWithDot, MAX.header),
    header_len: String(headerWithDot.length),
    payload_padded: padded(
      signedPadded.slice(headerWithDot.length),
      MAX.payload,
    ),
    payload_len: String(payload.length),
    payload: padded(bytes(payload), MAX.payload),
    sha2_num_blocks: String(signedPadded.length / 64),
    sha2_num_bits: length.map(String),
    sha2_padding: padded([0x80], 64),
    signature: limbs(
      BigInt(`0x${Buffer.from(signature, "base64url").toString("hex")}`),
    ).map(String),
    modulus: limbs(modulus).map(String),
    ...read("aud"),
    ...read("iss"),
    ...read("sub"),
    ...read("nonce"),
    ...read("iat", false),
    session_key: String(session.sessionKey),
    expiry: String(session.expiry),
    secret: String(session.secret),
    salt: String(session.salt),
  };
}
