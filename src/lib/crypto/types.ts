import type {
  AlgorithmIdentifier,
  COSEALG,
  COSEPublicKey,
  COSEPublicKeyEC2,
  COSEPublicKeyOKP,
  COSEPublicKeyRSA,
  EcKeyImportParams,
  RsaHashedImportParams,
  SubtleCryptoAlg,
  SubtleCryptoKeyAlgName,
} from "../auth";

export type CryptoApiFoundCallback = (crypto: Crypto) => void;

export type CryptoApiNotFoundCallback = (error: Error) => void;

export type ImportKeyPayload = {
  keyData: JsonWebKey;
  algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;
};

export enum Key {
  JWK = "jwk",
}

export enum KeyUsage {
  VERIFY = "verify",
}

export enum Algorithm {
  SHA1 = "SHA-1",
  SHA256 = "SHA-256",
  SHA384 = "SHA-384",
  SHA512 = "SHA-512",
  ED25519 = "Ed25519",
  ECDSA = "ECDSA",
  RSA_PKCS1_v1_5 = "RSASSA-PKCS1-v1_5",
  RSA_PSS = "RSA-PSS",
}

export type NormalizedFormInput = [Uint8Array[], number];

export type ByteTransformation = {
  bytes: Uint8Array;
  length: number;
};

export type Parsable<T, Q> = {
  parsable: (data: T) => boolean;
  parse: (data: T) => Q | Promise<Q>;
};

export type VerifyInput = {
  cosePublicKey: COSEPublicKey;
  signature: Uint8Array;
  data: Uint8Array;
  shaHashOverride?: COSEALG;
};

export type Void<T> = (payload: T) => void;

export type VerifyEC2Input = {
  cosePublicKey: COSEPublicKeyEC2;
  signature: Uint8Array;
  data: Uint8Array;
  shaHashOverride?: COSEALG;
};

export type verifyOKPInput = {
  cosePublicKey: COSEPublicKeyOKP;
  signature: Uint8Array;
  data: Uint8Array;
};

export type verifyRSAInput = {
  cosePublicKey: COSEPublicKeyRSA;
  signature: Uint8Array;
  data: Uint8Array;
  shaHashOverride?: COSEALG;
};

export type EC2PublicKey = {
  alg: COSEALG;
  crv: number;
  x: Uint8Array;
  y: Uint8Array;
};

export type OKPPublicKey = {
  alg: COSEALG;
  crv: number;
  x: Uint8Array;
};

export type RSAPublicKey = {
  alg: COSEALG;
  n: Uint8Array;
  e: Uint8Array;
};

export enum KeyAlgorithm {
  RS256 = "RS256",
  RS384 = "RS384",
  RS512 = "RS512",
  PS256 = "PS256",
  PS384 = "PS384",
  PS512 = "PS512",
  RS1 = "RS1",
  P256 = "P-256",
  P384 = "P-384",
  P521 = "P-521",
  ED25519 = "Ed25519",
}

export type RSAKeyAlgorithm = {
  name: SubtleCryptoKeyAlgName;
  hash: {
    name: SubtleCryptoAlg;
  };
};
