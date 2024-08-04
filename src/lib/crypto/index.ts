import { COSEALG, COSEKEYS, COSEPublicKey } from "@/lib/auth";
import { COSECRV, SubtleCryptoAlg, SubtleCryptoCrv, SubtleCryptoKeyAlgName } from "./types";
import { concat } from "@/lib/uint";
import { AsnParser, ECDSASigValue } from '@/lib/asn'
import { isCOSEAlg, isCOSECrv, isCOSEPublicKeyEC2, isCOSEPublicKeyOKP, isCOSEPublicKeyRSA } from "@/lib/cose";
import { COSEPublicKeyEC2, COSEPublicKeyOKP, COSEPublicKeyRSA } from "../cose/types";
import { fromBuffer } from "../base64";

let webCrypto: Crypto | undefined = undefined;

/**
 * Generate a digest of the provided data.
 *
 * @param data The data to generate a digest of
 * @param algorithm A COSE algorithm ID that maps to a desired SHA algorithm
 */
export async function digest(
  data: Uint8Array,
  algorithm: COSEALG,
): Promise<Uint8Array> {
  const WebCrypto = await getWebCrypto();

  const subtleAlgorithm = mapCoseAlgToWebCryptoAlg(algorithm);

  const hashed = await WebCrypto.subtle.digest(subtleAlgorithm, data);

  return new Uint8Array(hashed);
}

/**
 * Fill up the provided bytes array with random bytes equal to its length.
 *
 * @returns the same bytes array passed into the method
 */
export async function getRandomValues(array: Uint8Array): Promise<Uint8Array> {
  const WebCrypto = await getWebCrypto();

  WebCrypto.getRandomValues(array);

  return array;
}

export class MissingWebCrypto extends Error {
  constructor() {
    const message = 'An instance of the Crypto API could not be located';
    super(message);
    this.name = 'MissingWebCrypto';
  }
}

// Make it possible to stub return values during testing
export const _getWebCryptoInternals = {
  stubThisGlobalThisCrypto: () => globalThis.crypto,
  // Make it possible to reset the `webCrypto` at the top of the file
  setCachedCrypto: (newCrypto: Crypto | undefined) => {
    webCrypto = newCrypto;
  },
};

/**
 * Try to get an instance of the Crypto API from the current runtime. Should support Node,
 * as well as others, like Deno, that implement Web APIs.
 */
export function getWebCrypto(): Promise<Crypto> {
  /**
   * Hello there! If you came here wondering why this method is asynchronous when use of
   * `globalThis.crypto` is not, it's to minimize a bunch of refactor related to making this
   * synchronous. For example, `generateRegistrationOptions()` and `generateAuthenticationOptions()`
   * become synchronous if we make this synchronous (since nothing else in that method is async)
   * which represents a breaking API change in this library's core API.
   */
  const toResolve = new Promise<Crypto>((resolve, reject) => {
    if (webCrypto) {
      return resolve(webCrypto);
    }

    /**
     * Naively attempt to access Crypto as a global object, which popular ESM-centric run-times
     * support (and Node v20+)
     */
    const _globalThisCrypto = _getWebCryptoInternals.stubThisGlobalThisCrypto();

    if (_globalThisCrypto) {
      webCrypto = _globalThisCrypto;
      return resolve(webCrypto);
    }

    // We tried to access it both in Node and globally, so bail out
    return reject(new MissingWebCrypto());
  });

  return toResolve;
}

export async function importKey(opts: {
  keyData: JsonWebKey;
  algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;
}): Promise<CryptoKey> {
  const WebCrypto = await getWebCrypto();

  const { keyData, algorithm } = opts;

  return WebCrypto.subtle.importKey('jwk', keyData, algorithm, false, [
    'verify',
  ]);
}

/**
 * Convert a COSE alg ID into a corresponding string value that WebCrypto APIs expect
 */
export function mapCoseAlgToWebCryptoAlg(alg: COSEALG): SubtleCryptoAlg {
  if ([COSEALG.RS1].indexOf(alg) >= 0) {
    return 'SHA-1';
  } else if ([COSEALG.ES256, COSEALG.PS256, COSEALG.RS256].indexOf(alg) >= 0) {
    return 'SHA-256';
  } else if ([COSEALG.ES384, COSEALG.PS384, COSEALG.RS384].indexOf(alg) >= 0) {
    return 'SHA-384';
  } else if (
    [COSEALG.ES512, COSEALG.PS512, COSEALG.RS512, COSEALG.EdDSA].indexOf(alg) >=
      0
  ) {
    return 'SHA-512';
  }

  throw new Error(`Could not map COSE alg value of ${alg} to a WebCrypto alg`);
}

/**
 * Convert a COSE alg ID into a corresponding key algorithm string value that WebCrypto APIs expect
 */
export function mapCoseAlgToWebCryptoKeyAlgName(
  alg: COSEALG,
): SubtleCryptoKeyAlgName {
  if ([COSEALG.EdDSA].indexOf(alg) >= 0) {
    return 'Ed25519';
  } else if (
    [COSEALG.ES256, COSEALG.ES384, COSEALG.ES512, COSEALG.ES256K].indexOf(
      alg,
    ) >= 0
  ) {
    return 'ECDSA';
  } else if (
    [COSEALG.RS256, COSEALG.RS384, COSEALG.RS512, COSEALG.RS1].indexOf(alg) >= 0
  ) {
    return 'RSASSA-PKCS1-v1_5';
  } else if ([COSEALG.PS256, COSEALG.PS384, COSEALG.PS512].indexOf(alg) >= 0) {
    return 'RSA-PSS';
  }

  throw new Error(
    `Could not map COSE alg value of ${alg} to a WebCrypto key alg name`,
  );
}

/**
 * In WebAuthn, EC2 signatures are wrapped in ASN.1 structure so we need to peel r and s apart.
 *
 * See https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types
 */
export function unwrapEC2Signature(signature: Uint8Array, crv: COSECRV): Uint8Array {
  const parsedSignature = AsnParser.parse(signature, ECDSASigValue);
  const rBytes = new Uint8Array(parsedSignature.r);
  const sBytes = new Uint8Array(parsedSignature.s);

  const componentLength = getSignatureComponentLength(crv);
  const rNormalizedBytes = toNormalizedBytes(rBytes, componentLength);
  const sNormalizedBytes = toNormalizedBytes(sBytes, componentLength);

  const finalSignature = concat([
    rNormalizedBytes,
    sNormalizedBytes,
  ]);

  return finalSignature;
}

/**
 * The SubtleCrypto Web Crypto API expects ECDSA signatures with `r` and `s` values to be encoded
 * to a specific length depending on the order of the curve. This function returns the expected
 * byte-length for each of the `r` and `s` signature components.
 *
 * See <https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations>
 */
function getSignatureComponentLength(crv: COSECRV): number {
  switch (crv) {
    case COSECRV.P256:
      return 32;
    case COSECRV.P384:
      return 48;
    case COSECRV.P521:
      return 66;
    default:
      throw new Error(`Unexpected COSE crv value of ${crv} (EC2)`);
  }
}

/**
 * Converts the ASN.1 integer representation to bytes of a specific length `n`.
 *
 * DER encodes integers as big-endian byte arrays, with as small as possible representation and
 * requires a leading `0` byte to disambiguate between negative and positive numbers. This means
 * that `r` and `s` can potentially not be the expected byte-length that is needed by the
 * SubtleCrypto Web Crypto API: if there are leading `0`s it can be shorter than expected, and if
 * it has a leading `1` bit, it can be one byte longer.
 *
 * See <https://www.itu.int/rec/T-REC-X.690-202102-I/en>
 * See <https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations>
 */
function toNormalizedBytes(bytes: Uint8Array, componentLength: number): Uint8Array {
  let normalizedBytes;
  if (bytes.length < componentLength) {
    // In case the bytes are shorter than expected, we need to pad it with leading `0`s.
    normalizedBytes = new Uint8Array(componentLength);
    normalizedBytes.set(bytes, componentLength - bytes.length);
  } else if (bytes.length === componentLength) {
    normalizedBytes = bytes;
  } else if (bytes.length === componentLength + 1 && bytes[0] === 0 && (bytes[1] & 0x80) === 0x80) {
    // The bytes contain a leading `0` to encode that the integer is positive. This leading `0`
    // needs to be removed for compatibility with the SubtleCrypto Web Crypto API.
    normalizedBytes = bytes.subarray(1);
  } else {
    throw new Error(
      `Invalid signature component length ${bytes.length}, expected ${componentLength}`,
    );
  }

  return normalizedBytes;
}

/**
 * Verify signatures with their public key. Supports EC2 and RSA public keys.
 */
export function verify(opts: {
  cosePublicKey: COSEPublicKey;
  signature: Uint8Array;
  data: Uint8Array;
  shaHashOverride?: COSEALG;
}): Promise<boolean> {
  const { cosePublicKey, signature, data, shaHashOverride } = opts;

  if (isCOSEPublicKeyEC2(cosePublicKey)) {
    const crv = cosePublicKey.get(COSEKEYS.crv);
    if (!isCOSECrv(crv)) {
      throw new Error(`unknown COSE curve ${crv}`);
    }
    const unwrappedSignature = unwrapEC2Signature(signature, crv);
    return verifyEC2({
      cosePublicKey,
      signature: unwrappedSignature,
      data,
      shaHashOverride,
    });
  } else if (isCOSEPublicKeyRSA(cosePublicKey)) {
    return verifyRSA({ cosePublicKey, signature, data, shaHashOverride });
  } else if (isCOSEPublicKeyOKP(cosePublicKey)) {
    return verifyOKP({ cosePublicKey, signature, data });
  }

  const kty = cosePublicKey.get(COSEKEYS.kty);
  throw new Error(
    `Signature verification with public key of kty ${kty} is not supported by this method`,
  );
}

/**
 * Verify a signature using an EC2 public key
 */
export async function verifyEC2(opts: {
  cosePublicKey: COSEPublicKeyEC2;
  signature: Uint8Array;
  data: Uint8Array;
  shaHashOverride?: COSEALG;
}): Promise<boolean> {
  const { cosePublicKey, signature, data, shaHashOverride } = opts;

  const WebCrypto = await getWebCrypto();

  // Import the public key
  const alg = cosePublicKey.get(COSEKEYS.alg);
  const crv = cosePublicKey.get(COSEKEYS.crv);
  const x = cosePublicKey.get(COSEKEYS.x);
  const y = cosePublicKey.get(COSEKEYS.y);

  if (!alg) {
    throw new Error('Public key was missing alg (EC2)');
  }

  if (!crv) {
    throw new Error('Public key was missing crv (EC2)');
  }

  if (!x) {
    throw new Error('Public key was missing x (EC2)');
  }

  if (!y) {
    throw new Error('Public key was missing y (EC2)');
  }

  let _crv: SubtleCryptoCrv;
  if (crv === COSECRV.P256) {
    _crv = 'P-256';
  } else if (crv === COSECRV.P384) {
    _crv = 'P-384';
  } else if (crv === COSECRV.P521) {
    _crv = 'P-521';
  } else {
    throw new Error(`Unexpected COSE crv value of ${crv} (EC2)`);
  }

  const keyData: JsonWebKey = {
    kty: 'EC',
    crv: _crv,
    x: fromBuffer(x),
    y: fromBuffer(y),
    ext: false,
  };

  const keyAlgorithm: EcKeyImportParams = {
    /**
     * Note to future self: you can't use `mapCoseAlgToWebCryptoKeyAlgName()` here because some
     * leaf certs from actual devices specified an RSA SHA value for `alg` (e.g. `-257`) which
     * would then map here to `'RSASSA-PKCS1-v1_5'`. We always want `'ECDSA'` here so we'll
     * hard-code this.
     */
    name: 'ECDSA',
    namedCurve: _crv,
  };

  const key = await importKey({
    keyData,
    algorithm: keyAlgorithm,
  });

  // Determine which SHA algorithm to use for signature verification
  let subtleAlg = mapCoseAlgToWebCryptoAlg(alg);
  if (shaHashOverride) {
    subtleAlg = mapCoseAlgToWebCryptoAlg(shaHashOverride);
  }

  const verifyAlgorithm: EcdsaParams = {
    name: 'ECDSA',
    hash: { name: subtleAlg },
  };

  return WebCrypto.subtle.verify(verifyAlgorithm, key, signature, data);
}

export async function verifyOKP(opts: {
  cosePublicKey: COSEPublicKeyOKP;
  signature: Uint8Array;
  data: Uint8Array;
}): Promise<boolean> {
  const { cosePublicKey, signature, data } = opts;

  const WebCrypto = await getWebCrypto();

  const alg = cosePublicKey.get(COSEKEYS.alg);
  const crv = cosePublicKey.get(COSEKEYS.crv);
  const x = cosePublicKey.get(COSEKEYS.x);

  if (!alg) {
    throw new Error('Public key was missing alg (OKP)');
  }

  if (!isCOSEAlg(alg)) {
    throw new Error(`Public key had invalid alg ${alg} (OKP)`);
  }

  if (!crv) {
    throw new Error('Public key was missing crv (OKP)');
  }

  if (!x) {
    throw new Error('Public key was missing x (OKP)');
  }

  // Pulled key import steps from here:
  // https://wicg.github.io/webcrypto-secure-curves/#ed25519-operations
  let _crv: SubtleCryptoCrv;
  if (crv === COSECRV.ED25519) {
    _crv = 'Ed25519';
  } else {
    throw new Error(`Unexpected COSE crv value of ${crv} (OKP)`);
  }

  const keyData: JsonWebKey = {
    kty: 'OKP',
    crv: _crv,
    alg: 'EdDSA',
    x: fromBuffer(x),
    ext: false,
  };

  const keyAlgorithm: EcKeyImportParams = {
    name: _crv,
    namedCurve: _crv,
  };

  const key = await importKey({
    keyData,
    algorithm: keyAlgorithm,
  });

  const verifyAlgorithm: AlgorithmIdentifier = {
    name: _crv,
  };

  return WebCrypto.subtle.verify(verifyAlgorithm, key, signature, data);
}

/**
 * Verify a signature using an RSA public key
 */
export async function verifyRSA(opts: {
  cosePublicKey: COSEPublicKeyRSA;
  signature: Uint8Array;
  data: Uint8Array;
  shaHashOverride?: COSEALG;
}): Promise<boolean> {
  const { cosePublicKey, signature, data, shaHashOverride } = opts;

  const WebCrypto = await getWebCrypto();

  const alg = cosePublicKey.get(COSEKEYS.alg);
  const n = cosePublicKey.get(COSEKEYS.n);
  const e = cosePublicKey.get(COSEKEYS.e);

  if (!alg) {
    throw new Error('Public key was missing alg (RSA)');
  }

  if (!isCOSEAlg(alg)) {
    throw new Error(`Public key had invalid alg ${alg} (RSA)`);
  }

  if (!n) {
    throw new Error('Public key was missing n (RSA)');
  }

  if (!e) {
    throw new Error('Public key was missing e (RSA)');
  }

  const keyData: JsonWebKey = {
    kty: 'RSA',
    alg: '',
    n: fromBuffer(n),
    e: fromBuffer(e),
    ext: false,
  };

  const keyAlgorithm = {
    name: mapCoseAlgToWebCryptoKeyAlgName(alg),
    hash: { name: mapCoseAlgToWebCryptoAlg(alg) },
  };

  const verifyAlgorithm: AlgorithmIdentifier | RsaPssParams = {
    name: mapCoseAlgToWebCryptoKeyAlgName(alg),
  };

  if (shaHashOverride) {
    keyAlgorithm.hash.name = mapCoseAlgToWebCryptoAlg(shaHashOverride);
  }

  if (keyAlgorithm.name === 'RSASSA-PKCS1-v1_5') {
    if (keyAlgorithm.hash.name === 'SHA-256') {
      keyData.alg = 'RS256';
    } else if (keyAlgorithm.hash.name === 'SHA-384') {
      keyData.alg = 'RS384';
    } else if (keyAlgorithm.hash.name === 'SHA-512') {
      keyData.alg = 'RS512';
    } else if (keyAlgorithm.hash.name === 'SHA-1') {
      keyData.alg = 'RS1';
    }
  } else if (keyAlgorithm.name === 'RSA-PSS') {
    /**
     * salt length. The default value is 20 but the convention is to use hLen, the length of the
     * output of the hash function in bytes. A salt length of zero is permitted and will result in
     * a deterministic signature value. The actual salt length used can be determined from the
     * signature value.
     *
     * From https://www.cryptosys.net/pki/manpki/pki_rsaschemes.html
     */
    let saltLength = 0;

    if (keyAlgorithm.hash.name === 'SHA-256') {
      keyData.alg = 'PS256';
      saltLength = 32; // 256 bits => 32 bytes
    } else if (keyAlgorithm.hash.name === 'SHA-384') {
      keyData.alg = 'PS384';
      saltLength = 48; // 384 bits => 48 bytes
    } else if (keyAlgorithm.hash.name === 'SHA-512') {
      keyData.alg = 'PS512';
      saltLength = 64; // 512 bits => 64 bytes
    }

    (verifyAlgorithm as RsaPssParams).saltLength = saltLength;
  } else {
    throw new Error(
      `Unexpected RSA key algorithm ${alg} (${keyAlgorithm.name})`,
    );
  }

  const key = await importKey({
    keyData,
    algorithm: keyAlgorithm,
  });

  return WebCrypto.subtle.verify(verifyAlgorithm, key, signature, data);
}
