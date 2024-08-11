import type {
  AlgorithmIdentifier,
  EcKeyImportParams,
  RsaHashedImportParams,
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
  RSASSA_PKCS1_v1_5 = "RSASSA-PKCS1-v1_5",
  RSA_PSS = "RSA-PSS",
}
