import {
  COSEALG,
  COSECRV,
  COSEKEYS,
  COSEKTY,
  COSEPublicKey,
  COSEPublicKeyEC2,
  COSEPublicKeyOKP,
  COSEPublicKeyRSA,
} from "../types";

const isOfType = <T extends typeof COSEKTY | typeof COSECRV | typeof COSEALG>(
  type: T,
  value?: number,
): type is T => Object.values(type).indexOf(value) >= 0;

export const isCOSEKty = (value?: number): value is COSEKTY =>
  isOfType(COSEKTY, value);

export const isCOSECrv = (value?: number): value is COSECRV =>
  isOfType(COSECRV, value);

export const isCOSEAlg = (value?: number): value is COSEALG =>
  isOfType(COSEALG, value);

const withKty = (
  publicKey: COSEPublicKey,
  callback: (kty?: COSEKTY) => boolean,
): boolean => callback(publicKey.get(COSEKEYS.kty));

const publicKeyIsTypeOf = <T extends COSEKTY | COSECRV | COSEALG>(
  type: T,
  publicKey: COSEPublicKey,
): boolean => withKty(publicKey, (kty) => isCOSEKty(kty) && kty === type);

export const isCOSEPublicKeyOKP = (
  publicKey: COSEPublicKey,
): publicKey is COSEPublicKeyOKP => publicKeyIsTypeOf(COSEKTY.OKP, publicKey);

export const isCOSEPublicKeyEC2 = (
  publicKey: COSEPublicKey,
): publicKey is COSEPublicKeyEC2 => publicKeyIsTypeOf(COSEKTY.EC2, publicKey);

export const isCOSEPublicKeyRSA = (
  publicKey: COSEPublicKey,
): publicKey is COSEPublicKeyRSA => publicKeyIsTypeOf(COSEKTY.RSA, publicKey);
