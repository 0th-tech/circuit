import assert from "node:assert/strict";
import { after, test } from "node:test";
import * as snarkjs from "snarkjs";
import fixture from "../fixtures/fixture.json" with { type: "json" };
import input from "../fixtures/input.json" with { type: "json" };
import { circuitInputs, limbs } from "../scripts/inputs.ts";
import { SESSION, claims, modulus, sign } from "../scripts/letter.ts";

const WASM = new URL("../target/login_js/login.wasm", import.meta.url).pathname;
const R1CS = new URL("../target/login.r1cs", import.meta.url).pathname;

/** Computes the witness, which fails on the first constraint the input breaks */
async function witness(input: object) {
  const wtns = { type: "mem" };
  await snarkjs.wtns.calculate(input, WASM, wtns);
  return wtns;
}

/** Inputs for the fixture letter, or for the given claims signed by the same key */
const inputs = (payload: object = claims(SESSION)) =>
  circuitInputs(sign(payload), modulus, SESSION);

// snarkjs keeps the curve's worker threads alive until they are terminated
after(async () => {
  await (
    globalThis as { curve_bn128?: { terminate(): Promise<void> } }
  ).curve_bn128?.terminate();
});

test("fixtures/input.json holds the fixture letter's inputs", () => {
  assert.deepEqual(input, circuitInputs(fixture.jwt, modulus, SESSION));
});

test("accepts the fixture letter with its five public values", async () => {
  const wtns = await witness(inputs());

  const values = (await snarkjs.wtns.exportJson(wtns)).slice(1, 6).map(String);
  assert.deepEqual(values, [
    fixture.identity_hash,
    fixture.key_hash,
    fixture.iat,
    fixture.session_pubkey,
    fixture.expiry,
  ]);
  assert.ok(await snarkjs.wtns.check(R1CS, wtns));
});

test("refuses a letter changed after signing", async () => {
  const [header, , signature] = sign(claims(SESSION)).split(".");
  const changed = { ...claims(SESSION), sub: "123456789012345678902" };
  const payload = Buffer.from(JSON.stringify(changed)).toString("base64url");
  const input = circuitInputs(
    `${header}.${payload}.${signature}`,
    modulus,
    SESSION,
  );

  await assert.rejects(witness(input), /RSA_PKCS1_v1_5_Verify/);
});

test("refuses another RSA key", async () => {
  const input = inputs();
  input.modulus = limbs(modulus + 2n ** 600n).map(String);

  await assert.rejects(witness(input), /RSA_PKCS1_v1_5_Verify/);
});

test("refuses another issuer", async () => {
  const input = inputs({
    ...claims(SESSION),
    iss: "https://accounts.goggle.com",
  });

  await assert.rejects(witness(input), /AssertIssuer/);
});

test("refuses another session key or expiry", async () => {
  const otherKey = { ...inputs(), session_key: "123" };
  const longerSession = { ...inputs(), expiry: String(SESSION.expiry + 1n) };

  await assert.rejects(witness(otherKey), /AssertNonce/);
  await assert.rejects(witness(longerSession), /AssertNonce/);
});

test("refuses a payload start moved off the dot", async () => {
  const input = inputs();
  input.header_len = String(Number(input.header_len) + 4);

  await assert.rejects(witness(input), /Assert Failed/);
});

test("refuses a claim inside a nested object", async () => {
  // The nested claim comes first, so it is the one read
  const { sub, iat, ...rest } = claims(SESSION);
  const nestedSub = { ...rest, iat, extra: { sub: "999" }, sub };
  const nestedIat = { ...rest, sub, extra: { iat: 1 }, iat };

  await assert.rejects(witness(inputs(nestedSub)), /EnforceNotNested/);
  await assert.rejects(witness(inputs(nestedIat)), /EnforceNotNested/);
});

test("refuses string bodies that disagree with the payload", async () => {
  const input = inputs();
  const bodies = [...(input.aud_field_string_bodies as string[])];
  bodies[0] = "1";
  input.aud_field_string_bodies = bodies;

  await assert.rejects(witness(input), /Assert Failed/);
});
