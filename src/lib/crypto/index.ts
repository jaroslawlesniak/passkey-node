import { AsnParser, ECDSASigValue } from "@/lib/asn";
import {
  COSEALG,
  COSECRV,
  COSEKEYS,
  COSEPublicKey,
  COSEPublicKeyEC2,
  COSEPublicKeyOKP,
  COSEPublicKeyRSA,
  CryptoKey,
  SubtleCryptoAlg,
  SubtleCryptoCrv,
  SubtleCryptoKeyAlgName,
} from "@/lib/auth";
import { fromBuffer } from "@/lib/base64";
import {
  isCOSEAlg,
  isCOSECrv,
  isCOSEPublicKeyEC2,
  isCOSEPublicKeyOKP,
  isCOSEPublicKeyRSA,
} from "@/lib/cose";
import { concat } from "@/lib/uint";

import {
  Algorithm,
  CryptoApiFoundCallback,
  CryptoApiNotFoundCallback,
  ImportKeyPayload,
  Key,
  KeyUsage,
} from "./types";

let webCrypto: Crypto | undefined = undefined;

class CryptoApiNotFoundError extends Error {
  constructor() {
    super("Crypto API not found");

    this.name = "CryptoApiNotFound";
  }
}

export const digest = (
  data: Uint8Array,
  algorithm: COSEALG,
): Promise<Uint8Array> =>
  Promise.all([getWebCrypto(), mapCoseAlgToWebCryptoAlg(algorithm)])
    .then(([crypto, cryptoAlgorithm]) =>
      crypto.subtle.digest(cryptoAlgorithm, data),
    )
    .then((hash) => new Uint8Array(hash));

export const getRandomValues = (array: Uint8Array): Promise<Uint8Array> =>
  getWebCrypto()
    .then((crypto) => crypto.getRandomValues(array))
    .then(() => array); // uhh, we are modifying original array

const tryGetCachedCryptoApi = (resolve: CryptoApiFoundCallback) =>
  webCrypto && resolve(webCrypto);

const tryGetNativeCryptoApi = (resolve: CryptoApiFoundCallback) => {
  const nativeLibrary = globalThis.crypto;

  if (nativeLibrary) {
    webCrypto = nativeLibrary;

    return resolve(nativeLibrary);
  }
};

const throwCryptoApiNotFound = (reject: CryptoApiNotFoundCallback) =>
  reject(new CryptoApiNotFoundError());

export const getWebCrypto = (): Promise<Crypto> =>
  new Promise<Crypto>((resolve, reject) => {
    tryGetCachedCryptoApi(resolve);
    tryGetNativeCryptoApi(resolve);

    throwCryptoApiNotFound(reject);
  });

const EXTRACTABLE = false;

export const importKey = ({
  keyData,
  algorithm,
}: ImportKeyPayload): Promise<CryptoKey> =>
  getWebCrypto().then((crypto) =>
    crypto.subtle.importKey(Key.JWK, keyData, algorithm, EXTRACTABLE, [
      KeyUsage.VERIFY,
    ]),
  );

const isOfType = (algorithms: COSEALG[]) => (algorithm: COSEALG) =>
  algorithms.indexOf(algorithm) >= 0;

const isSha1 = isOfType([COSEALG.RS1]);
const isSha256 = isOfType([COSEALG.ES256, COSEALG.PS256, COSEALG.RS256]);
const isSha384 = isOfType([COSEALG.ES384, COSEALG.PS384, COSEALG.RS384]);
const isSha512 = isOfType([
  COSEALG.ES512,
  COSEALG.PS512,
  COSEALG.RS512,
  COSEALG.EdDSA,
]);

const getHashingAlgorithm = (algorithm: COSEALG) => ({
  isSha1: isSha1(algorithm),
  isSha256: isSha256(algorithm),
  isSha384: isSha384(algorithm),
  isSha512: isSha512(algorithm),
});

export const mapCoseAlgToWebCryptoAlg = (
  algorithm: COSEALG,
): SubtleCryptoAlg => {
  const { isSha1, isSha256, isSha384, isSha512 } =
    getHashingAlgorithm(algorithm);

  if (isSha1) {
    return Algorithm.SHA1;
  } else if (isSha256) {
    return Algorithm.SHA256;
  } else if (isSha384) {
    return Algorithm.SHA384;
  } else if (isSha512) {
    return Algorithm.SHA512;
  }

  throw new Error(`Algorithm of type ${algorithm} not found`);
};

const isEd25519 = isOfType([COSEALG.EdDSA]);
const isECDSA = isOfType([
  COSEALG.ES256,
  COSEALG.ES384,
  COSEALG.ES512,
  COSEALG.ES256K,
]);
const isRsaPkcs15 = isOfType([
  COSEALG.RS256,
  COSEALG.RS384,
  COSEALG.RS512,
  COSEALG.RS1,
]);
const isRsaPss = isOfType([COSEALG.PS256, COSEALG.PS384, COSEALG.PS512]);

const getEncryptionAlgorithm = (algorithm: COSEALG) => ({
  isEd25519: isEd25519(algorithm),
  isECDSA: isECDSA(algorithm),
  isRsaPkcs15: isRsaPkcs15(algorithm),
  isRsaPss: isRsaPss(algorithm),
});

export const mapCoseAlgToWebCryptoKeyAlgName = (
  algorithm: COSEALG,
): SubtleCryptoKeyAlgName => {
  const { isECDSA, isEd25519, isRsaPkcs15, isRsaPss } =
    getEncryptionAlgorithm(algorithm);

  if (isECDSA) {
    return Algorithm.ECDSA;
  } else if (isEd25519) {
    return Algorithm.ED25519;
  } else if (isRsaPkcs15) {
    return Algorithm.RSA_PKCS1_v1_5;
  } else if (isRsaPss) {
    return Algorithm.RSA_PSS;
  }

  throw new Error(`Algorithm of type ${algorithm} not found`);
}

/**
 * In WebAuthn, EC2 signatures are wrapped in ASN.1 structure so we need to peel r and s apart.
 *
 * See https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types
 */
export function unwrapEC2Signature(
  signature: Uint8Array,
  crv: COSECRV,
): Uint8Array {
  const parsedSignature = AsnParser.parse(signature, ECDSASigValue);
  const rBytes = new Uint8Array(parsedSignature.r);
  const sBytes = new Uint8Array(parsedSignature.s);

  const componentLength = getSignatureComponentLength(crv);
  const rNormalizedBytes = toNormalizedBytes(rBytes, componentLength);
  const sNormalizedBytes = toNormalizedBytes(sBytes, componentLength);

  const finalSignature = concat([rNormalizedBytes, sNormalizedBytes]);

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
function toNormalizedBytes(
  bytes: Uint8Array,
  componentLength: number,
): Uint8Array {
  let normalizedBytes;
  if (bytes.length < componentLength) {
    // In case the bytes are shorter than expected, we need to pad it with leading `0`s.
    normalizedBytes = new Uint8Array(componentLength);
    normalizedBytes.set(bytes, componentLength - bytes.length);
  } else if (bytes.length === componentLength) {
    normalizedBytes = bytes;
  } else if (
    bytes.length === componentLength + 1 &&
    bytes[0] === 0 &&
    (bytes[1] & 0x80) === 0x80
  ) {
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
    throw new Error("Public key was missing alg (EC2)");
  }

  if (!crv) {
    throw new Error("Public key was missing crv (EC2)");
  }

  if (!x) {
    throw new Error("Public key was missing x (EC2)");
  }

  if (!y) {
    throw new Error("Public key was missing y (EC2)");
  }

  let _crv: SubtleCryptoCrv;
  if (crv === COSECRV.P256) {
    _crv = "P-256";
  } else if (crv === COSECRV.P384) {
    _crv = "P-384";
  } else if (crv === COSECRV.P521) {
    _crv = "P-521";
  } else {
    throw new Error(`Unexpected COSE crv value of ${crv} (EC2)`);
  }

  const keyData: JsonWebKey = {
    kty: "EC",
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
    name: "ECDSA",
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
    name: "ECDSA",
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
    throw new Error("Public key was missing alg (OKP)");
  }

  if (!isCOSEAlg(alg)) {
    throw new Error(`Public key had invalid alg ${alg} (OKP)`);
  }

  if (!crv) {
    throw new Error("Public key was missing crv (OKP)");
  }

  if (!x) {
    throw new Error("Public key was missing x (OKP)");
  }

  // Pulled key import steps from here:
  // https://wicg.github.io/webcrypto-secure-curves/#ed25519-operations
  let _crv: SubtleCryptoCrv;
  if (crv === COSECRV.ED25519) {
    _crv = "Ed25519";
  } else {
    throw new Error(`Unexpected COSE crv value of ${crv} (OKP)`);
  }

  const keyData: JsonWebKey = {
    kty: "OKP",
    crv: _crv,
    alg: "EdDSA",
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
    throw new Error("Public key was missing alg (RSA)");
  }

  if (!isCOSEAlg(alg)) {
    throw new Error(`Public key had invalid alg ${alg} (RSA)`);
  }

  if (!n) {
    throw new Error("Public key was missing n (RSA)");
  }

  if (!e) {
    throw new Error("Public key was missing e (RSA)");
  }

  const keyData: JsonWebKey = {
    kty: "RSA",
    alg: "",
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

  if (keyAlgorithm.name === "RSASSA-PKCS1-v1_5") {
    if (keyAlgorithm.hash.name === "SHA-256") {
      keyData.alg = "RS256";
    } else if (keyAlgorithm.hash.name === "SHA-384") {
      keyData.alg = "RS384";
    } else if (keyAlgorithm.hash.name === "SHA-512") {
      keyData.alg = "RS512";
    } else if (keyAlgorithm.hash.name === "SHA-1") {
      keyData.alg = "RS1";
    }
  } else if (keyAlgorithm.name === "RSA-PSS") {
    /**
     * salt length. The default value is 20 but the convention is to use hLen, the length of the
     * output of the hash function in bytes. A salt length of zero is permitted and will result in
     * a deterministic signature value. The actual salt length used can be determined from the
     * signature value.
     *
     * From https://www.cryptosys.net/pki/manpki/pki_rsaschemes.html
     */
    let saltLength = 0;

    if (keyAlgorithm.hash.name === "SHA-256") {
      keyData.alg = "PS256";
      saltLength = 32; // 256 bits => 32 bytes
    } else if (keyAlgorithm.hash.name === "SHA-384") {
      keyData.alg = "PS384";
      saltLength = 48; // 384 bits => 48 bytes
    } else if (keyAlgorithm.hash.name === "SHA-512") {
      keyData.alg = "PS512";
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
