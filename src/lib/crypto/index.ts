import { AsnParser, ECDSASigValue } from "@/lib/asn";
import {
  COSEALG,
  COSECRV,
  COSEKEYS,
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
  ByteTransformation,
  CryptoApiFoundCallback,
  CryptoApiNotFoundCallback,
  EC2PublicKey,
  ImportKeyPayload,
  Key,
  KeyAlgorithm,
  KeyUsage,
  NormalizedFormInput,
  OKPPublicKey,
  Parsable,
  RSAKeyAlgorithm,
  RSAPublicKey,
  VerifyEC2Input,
  VerifyInput,
  verifyOKPInput,
  verifyRSAInput,
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
};

const P256_LENGTH = 32;
const P384_LENGTH = 48;
const P521_LENGTH = 66;

const getSignatureComponentLength = (crv: COSECRV): number => {
  switch (crv) {
    case COSECRV.P256:
      return P256_LENGTH;
    case COSECRV.P384:
      return P384_LENGTH;
    case COSECRV.P521:
      return P521_LENGTH;
    default:
      throw new Error(`Invalid ${crv} value`);
  }
};

const isShorten = ({ bytes, length }: ByteTransformation): boolean =>
  bytes.length < length;

const padToStart = ({ bytes, length }: ByteTransformation): Uint8Array => {
  const array = new Uint8Array(length);

  array.set(bytes, length - bytes.length);

  return array;
};

const isSameLength = ({ bytes, length }: ByteTransformation): boolean =>
  bytes.length === length;

const rewriteBytesArray = ({ bytes }: ByteTransformation): Uint8Array => bytes;

const startsFromZero = ({ bytes, length }: ByteTransformation): boolean =>
  bytes.length === length + 1 && bytes[0] === 0 && (bytes[1] & 0x80) === 0x80;

const trimStart = ({ bytes }: ByteTransformation): Uint8Array =>
  bytes.subarray(1);

const transformations: Parsable<ByteTransformation, Uint8Array>[] = [
  {
    parsable: isShorten,
    parse: padToStart,
  },
  {
    parsable: isSameLength,
    parse: rewriteBytesArray,
  },
  {
    parsable: startsFromZero,
    parse: trimStart,
  },
];

const toNormalizedBytes = async (
  bytes: Uint8Array,
  length: number,
): Promise<Uint8Array> => {
  const normalized = await transformations
    .find(({ parsable }) => parsable({ bytes, length }))
    ?.parse({ bytes, length });

  if (normalized) {
    return Promise.resolve(normalized);
  }

  throw new Error(
    `Invalid component length ${bytes.length}, expected ${length}`,
  );
};

const splitBytes = (payload: ECDSASigValue): Uint8Array[] => [
  new Uint8Array(payload.r),
  new Uint8Array(payload.s),
];

const calculateBytes = (crv: COSECRV) => (signature: ECDSASigValue) =>
  Promise.all([splitBytes(signature), getSignatureComponentLength(crv)]);

const toNormalizedForm = ([[rBytes, sBytes], length]: NormalizedFormInput) =>
  Promise.all([
    toNormalizedBytes(rBytes, length),
    toNormalizedBytes(sBytes, length),
  ]);

const unwrapEC2Signature = (
  signature: Uint8Array,
  crv: COSECRV,
): Promise<Uint8Array> =>
  Promise.resolve()
    .then(() => AsnParser.parse(signature, ECDSASigValue))
    .then(calculateBytes(crv))
    .then(toNormalizedForm)
    .then(concat);

const parseToEC2 = async ({
  cosePublicKey,
  signature,
  ...passThrough
}: VerifyInput) => {
  if (!isCOSEPublicKeyEC2(cosePublicKey)) {
    throw new Error("Parser failed");
  }

  const crv = cosePublicKey.get(COSEKEYS.crv);

  if (!isCOSECrv(crv)) {
    throw new Error("Unknown COSE value");
  }

  return unwrapEC2Signature(signature, crv).then((unwrappedSignature) =>
    verifyEC2({
      ...passThrough,
      cosePublicKey,
      signature: unwrappedSignature,
    }),
  );
};

const parseToRSA = ({ cosePublicKey, ...passThrough }: VerifyInput) => {
  if (!isCOSEPublicKeyRSA(cosePublicKey)) {
    throw new Error("Parser failed");
  }

  return verifyRSA({
    ...passThrough,
    cosePublicKey,
  });
};

const parseToOKP = ({ cosePublicKey, ...passThrough }: VerifyInput) => {
  if (!isCOSEPublicKeyOKP(cosePublicKey)) {
    throw new Error("Parser failed");
  }

  return verifyOKP({
    ...passThrough,
    cosePublicKey,
  });
};

const verifications: Parsable<VerifyInput, boolean>[] = [
  {
    parsable: ({ cosePublicKey }) => isCOSEPublicKeyEC2(cosePublicKey),
    parse: parseToEC2,
  },
  {
    parsable: ({ cosePublicKey }) => isCOSEPublicKeyRSA(cosePublicKey),
    parse: parseToRSA,
  },
  {
    parsable: ({ cosePublicKey }) => isCOSEPublicKeyOKP(cosePublicKey),
    parse: parseToOKP,
  },
];

export const verify = async (input: VerifyInput): Promise<boolean> => {
  const verified = await verifications
    .find(({ parsable }) => parsable(input))
    ?.parse(input);

  if (verified) {
    return Promise.resolve(verified);
  }

  throw new Error("Signature verification failed");
};

const validatePublicKeyPartial = <T>(message: string, value?: T): T => {
  if (value) {
    return value;
  }

  throw new Error(message);
};

const importEC2PublicKey = (cosePublicKey: COSEPublicKeyEC2): EC2PublicKey => ({
  alg: validatePublicKeyPartial(
    "[EC2] Missing alg in public key",
    cosePublicKey.get(COSEKEYS.alg),
  ),
  crv: validatePublicKeyPartial(
    "[EC2] Missing crv in public key",
    cosePublicKey.get(COSEKEYS.crv),
  ),
  x: validatePublicKeyPartial(
    "[EC2] Missing x in public key",
    cosePublicKey.get(COSEKEYS.x),
  ),
  y: validatePublicKeyPartial(
    "[EC2] Missing y in public key",
    cosePublicKey.get(COSEKEYS.y),
  ),
});

const toEC2Crv = (crv: number): SubtleCryptoCrv => {
  switch (crv) {
    case COSECRV.P256:
      return KeyAlgorithm.P256;

    case COSECRV.P384:
      return KeyAlgorithm.P384;

    case COSECRV.P521:
      return KeyAlgorithm.P521;

    default:
      throw new Error(`[EC2] Invalid crv value`);
  }
};

const toEC2KeyData = ({ crv, x, y }: EC2PublicKey): JsonWebKey => ({
  kty: "EC",
  crv: toEC2Crv(crv),
  x: fromBuffer(x),
  y: fromBuffer(y),
  ext: false,
});

const toEC2KeyAlgorithm = ({ crv }: EC2PublicKey): EcKeyImportParams => ({
  name: "ECDSA",
  namedCurve: toEC2Crv(crv),
});

const toEC2VerifyAlgorithm = (algorithm: SubtleCryptoAlg): EcdsaParams => ({
  name: "ECDSA",
  hash: { name: algorithm },
});

export const verifyEC2 = ({
  cosePublicKey,
  data,
  signature,
  shaHashOverride,
}: VerifyEC2Input): Promise<boolean> =>
  getWebCrypto().then(async (crypto) => {
    const publicKey = importEC2PublicKey(cosePublicKey);
    const keyData = toEC2KeyData(publicKey);
    const algorithm = toEC2KeyAlgorithm(publicKey);
    const subtleAlg = mapCoseAlgToWebCryptoAlg(
      shaHashOverride || publicKey.alg,
    );
    const verifyAlgorithm = toEC2VerifyAlgorithm(subtleAlg);

    const key = await importKey({
      keyData,
      algorithm,
    });

    return crypto.subtle.verify(verifyAlgorithm, key, signature, data);
  });

const importOKPPublicKey = (cosePublicKey: COSEPublicKeyOKP): OKPPublicKey => {
  const alg = validatePublicKeyPartial(
    "[OKP] Missing alg in public key",
    cosePublicKey.get(COSEKEYS.alg),
  );
  const crv = validatePublicKeyPartial(
    "[OKP] Missing crv in public key",
    cosePublicKey.get(COSEKEYS.crv),
  );
  const x = validatePublicKeyPartial(
    "[OKP] Missing x in public key",
    cosePublicKey.get(COSEKEYS.x),
  );

  if (!isCOSEAlg(alg)) {
    throw new Error("[OKP] Invalid alg");
  }

  return { alg, crv, x };
};

const toOKPCrv = (crv: number) => {
  switch (crv) {
    case COSECRV.ED25519:
      return KeyAlgorithm.ED25519;
    default:
      throw new Error(`[OKP] Invalid crv value`);
  }
};

const toOKPKeyData = ({ crv, x }: OKPPublicKey): JsonWebKey => ({
  kty: "OKP",
  alg: "EdDSA",
  crv: toOKPCrv(crv),
  x: fromBuffer(x),
  ext: false,
});

const toOKPKeyAlgorithm = ({ crv }: OKPPublicKey): EcKeyImportParams => ({
  name: toOKPCrv(crv),
  namedCurve: toOKPCrv(crv),
});

const toOKPVerifyAlgorithm = ({ crv }: OKPPublicKey): AlgorithmIdentifier => ({
  name: toOKPCrv(crv),
});

export const verifyOKP = ({
  cosePublicKey,
  data,
  signature,
}: verifyOKPInput): Promise<boolean> =>
  getWebCrypto().then(async (crypto) => {
    const publicKey = importOKPPublicKey(cosePublicKey);

    const keyData = toOKPKeyData(publicKey);
    const keyAlgorithm = toOKPKeyAlgorithm(publicKey);
    const verifyAlgorithm = toOKPVerifyAlgorithm(publicKey);

    const key = await importKey({
      keyData,
      algorithm: keyAlgorithm,
    });

    return crypto.subtle.verify(verifyAlgorithm, key, signature, data);
  });

const toRSAPublicKey = (cosePublicKey: COSEPublicKeyRSA): RSAPublicKey => {
  const alg = validatePublicKeyPartial(
    "[RSA] Missing alg in public key",
    cosePublicKey.get(COSEKEYS.alg),
  );
  const n = validatePublicKeyPartial(
    "[RSA] Missing n in public key",
    cosePublicKey.get(COSEKEYS.n),
  );
  const e = validatePublicKeyPartial(
    "[RSA] Missing e in public key",
    cosePublicKey.get(COSEKEYS.e),
  );

  if (!isCOSEAlg(alg)) {
    throw new Error("[RSA] Invalid alg");
  }

  return { alg, n, e };
};

const toRsaPkcs15Name = (algorithm: string) => {
  switch (algorithm) {
    case Algorithm.SHA256:
      return KeyAlgorithm.RS256;

    case Algorithm.SHA384:
      return KeyAlgorithm.RS384;

    case Algorithm.SHA512:
      return KeyAlgorithm.RS512;

    case Algorithm.SHA1:
      return KeyAlgorithm.RS1;

    default:
      throw new Error(`Unsupported algorithm ${algorithm}`);
  }
};

const toRsaPssName = (algorithm: string) => {
  switch (algorithm) {
    case Algorithm.SHA256:
      return KeyAlgorithm.PS256;

    case Algorithm.SHA384:
      return KeyAlgorithm.PS384;

    case Algorithm.SHA512:
      return KeyAlgorithm.PS512;

    default:
      throw new Error(`Unsupported algorithm ${algorithm}`);
  }
};

const toKeyAlgorithmName = (keyAlgorithm: RSAKeyAlgorithm) => {
  switch (keyAlgorithm.name) {
    case Algorithm.RSA_PKCS1_v1_5:
      return toRsaPkcs15Name(keyAlgorithm.hash.name);

    case Algorithm.RSA_PSS:
      return toRsaPssName(keyAlgorithm.hash.name);

    default:
      throw new Error(`Unsupported algorithm name ${keyAlgorithm.name}`);
  }
};

const toRSAKeyData = (
  { n, e }: RSAPublicKey,
  keyAlgorithm: RSAKeyAlgorithm,
) => ({
  kty: "RSA",
  alg: toKeyAlgorithmName(keyAlgorithm),
  n: fromBuffer(n),
  e: fromBuffer(e),
  ext: false,
});

const toRSAKeyAlgorithm = (
  { alg }: RSAPublicKey,
  shaHashOverride?: COSEALG,
): RSAKeyAlgorithm => ({
  name: mapCoseAlgToWebCryptoKeyAlgName(alg),
  hash: { name: toRSAVerifyAlgorithmName(alg, shaHashOverride) },
});

const toRSAVerifyAlgorithmName = (
  algorithm: COSEALG,
  shaHashOverride?: COSEALG,
) => {
  if (shaHashOverride) {
    return mapCoseAlgToWebCryptoAlg(shaHashOverride);
  }

  return mapCoseAlgToWebCryptoAlg(algorithm);
};

const toRSAPssSaltLength = ({ hash, name }: RSAKeyAlgorithm): number => {
  const DEFAULT_SALT_LENGTH = 0;

  switch (name) {
    case Algorithm.RSA_PSS:
      switch (hash.name) {
        case Algorithm.SHA256:
          return 32;

        case Algorithm.SHA384:
          return 48;

        case Algorithm.SHA512:
          return 64;

        default:
          return DEFAULT_SALT_LENGTH;
      }

    default:
      return DEFAULT_SALT_LENGTH;
  }
};

const toRSAVerifyAlgorithm = (
  { alg }: RSAPublicKey,
  keyAlgorithm: RSAKeyAlgorithm,
): AlgorithmIdentifier | RsaPssParams => ({
  name: mapCoseAlgToWebCryptoKeyAlgName(alg),
  saltLength: toRSAPssSaltLength(keyAlgorithm),
});

export const verifyRSA = ({
  cosePublicKey,
  data,
  signature,
  shaHashOverride,
}: verifyRSAInput): Promise<boolean> =>
  getWebCrypto().then(async (crypto) => {
    const publicKey = toRSAPublicKey(cosePublicKey);

    const keyAlgorithm = toRSAKeyAlgorithm(publicKey, shaHashOverride);
    const keyData = toRSAKeyData(publicKey, keyAlgorithm);
    const verifyAlgorithm = toRSAVerifyAlgorithm(publicKey, keyAlgorithm);

    const key = await importKey({
      keyData,
      algorithm: keyAlgorithm,
    });

    return crypto.subtle.verify(verifyAlgorithm, key, signature, data);
  });
