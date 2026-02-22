#!/usr/bin/env node

import fs from "node:fs";

const MIN_NODE_VERSION = process.env.MIN_NODE_VERSION || "18.0.0";

function fail(message) {
  console.error(message);
  process.exit(1);
}

function parseSemver(value) {
  const match = String(value).match(/(\d+)\.(\d+)\.(\d+)/);
  if (!match) {
    return null;
  }
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function versionGte(observed, minimum) {
  for (let i = 0; i < 3; i += 1) {
    if (observed[i] > minimum[i]) {
      return true;
    }
    if (observed[i] < minimum[i]) {
      return false;
    }
  }
  return true;
}

function nodeInstallHint() {
  if (process.platform === "darwin") {
    return "Install Node.js with 'brew install node' or from https://nodejs.org/.";
  }
  return "Install Node.js from your package manager or https://nodejs.org/.";
}

function assertNodeVersion() {
  const observed = parseSemver(process.version);
  const minimum = parseSemver(MIN_NODE_VERSION);
  if (!observed || !minimum) {
    fail(
      `unable to parse Node.js version (observed '${process.version}', minimum '${MIN_NODE_VERSION}').`
    );
  }

  if (!versionGte(observed, minimum)) {
    fail(
      `Node.js ${process.version} is too old; require >= ${MIN_NODE_VERSION}. ${nodeInstallHint()}`
    );
  }
}

function usage() {
  fail("usage: encode_bn254_for_soroban.mjs <vk|proof|public> <input.json>");
}

function toBigInt(value) {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      fail(`non-integer numeric field element: ${value}`);
    }
    return BigInt(value);
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed.length === 0) {
      fail("empty string field element");
    }
    return trimmed.startsWith("0x") || trimmed.startsWith("0X")
      ? BigInt(trimmed)
      : BigInt(trimmed);
  }
  fail(`unsupported field element type: ${typeof value}`);
}

function u32be(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    fail(`value out of u32 range: ${value}`);
  }
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value, 0);
  return out;
}

function fieldToBe32(value) {
  const n = toBigInt(value);
  if (n < 0n) {
    fail(`negative field element: ${n.toString()}`);
  }
  const max = 1n << 256n;
  if (n >= max) {
    fail(`field element exceeds 32 bytes: ${n.toString()}`);
  }
  let hex = n.toString(16);
  if (hex.length > 64) {
    fail(`field element exceeds 32 bytes: ${n.toString()}`);
  }
  hex = hex.padStart(64, "0");
  return Buffer.from(hex, "hex");
}

function expectArray(value, label) {
  if (!Array.isArray(value)) {
    fail(`${label} must be an array`);
  }
  return value;
}

function encodeG1(point, label) {
  const arr = expectArray(point, label);
  if (arr.length < 2) {
    fail(`${label} must have at least 2 coordinates`);
  }
  if (arr.length >= 3) {
    const z = toBigInt(arr[2]);
    if (z === 0n) {
      return Buffer.alloc(64, 0);
    }
    if (z !== 1n) {
      fail(`${label} has unsupported projective z coordinate ${z.toString()}`);
    }
  }
  return Buffer.concat([fieldToBe32(arr[0]), fieldToBe32(arr[1])]);
}

function encodeFp2(value, label) {
  const arr = expectArray(value, label);
  if (arr.length < 2) {
    fail(`${label} must have 2 coefficients`);
  }
  // snarkjs stores Fp2 as [c0, c1], Soroban expects c1 || c0.
  return Buffer.concat([fieldToBe32(arr[1]), fieldToBe32(arr[0])]);
}

function encodeG2(point, label) {
  const arr = expectArray(point, label);
  if (arr.length < 2) {
    fail(`${label} must contain X and Y Fp2 coordinates`);
  }
  if (arr.length >= 3) {
    const z = expectArray(arr[2], `${label}.z`);
    if (z.length < 2) {
      fail(`${label}.z must have 2 coefficients`);
    }
    const z0 = toBigInt(z[0]);
    const z1 = toBigInt(z[1]);
    if (z0 === 0n && z1 === 0n) {
      return Buffer.alloc(128, 0);
    }
    if (z0 !== 1n || z1 !== 0n) {
      fail(
        `${label} has unsupported projective z coordinate [${z0.toString()}, ${z1.toString()}]`
      );
    }
  }
  return Buffer.concat([encodeFp2(arr[0], `${label}.x`), encodeFp2(arr[1], `${label}.y`)]);
}

function encodeVk(vk) {
  const ic = expectArray(vk.IC, "IC");
  return Buffer.concat([
    encodeG1(vk.vk_alpha_1, "vk_alpha_1"),
    encodeG2(vk.vk_beta_2, "vk_beta_2"),
    encodeG2(vk.vk_gamma_2, "vk_gamma_2"),
    encodeG2(vk.vk_delta_2, "vk_delta_2"),
    u32be(ic.length),
    ...ic.map((point, i) => encodeG1(point, `IC[${i}]`)),
  ]);
}

function encodeProof(proof) {
  return Buffer.concat([
    encodeG1(proof.pi_a, "pi_a"),
    encodeG2(proof.pi_b, "pi_b"),
    encodeG1(proof.pi_c, "pi_c"),
  ]);
}

function encodePublic(publicSignals) {
  const arr = expectArray(publicSignals, "public");
  return Buffer.concat([u32be(arr.length), ...arr.map((value) => fieldToBe32(value))]);
}

function main() {
  assertNodeVersion();

  const mode = process.argv[2];
  const inputPath = process.argv[3];
  if (!mode || !inputPath) {
    usage();
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(inputPath, "utf8"));
  } catch (err) {
    fail(`failed to parse JSON at ${inputPath}: ${err.message}`);
  }

  let encoded;
  if (mode === "vk") {
    encoded = encodeVk(parsed);
  } else if (mode === "proof") {
    encoded = encodeProof(parsed);
  } else if (mode === "public") {
    encoded = encodePublic(parsed);
  } else {
    usage();
  }

  process.stdout.write(encoded.toString("hex"));
}

main();
