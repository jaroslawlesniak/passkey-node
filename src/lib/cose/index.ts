import { COSEALG, COSECRV, COSEKEYS, COSEKTY, COSEPublicKey, COSEPublicKeyEC2, COSEPublicKeyOKP, COSEPublicKeyRSA } from "@/lib/auth";


export function isCOSEPublicKeyOKP(
  cosePublicKey: COSEPublicKey,
): cosePublicKey is COSEPublicKeyOKP {
  const kty = cosePublicKey.get(COSEKEYS.kty);
  return isCOSEKty(kty) && kty === COSEKTY.OKP;
}

export function isCOSEPublicKeyEC2(
  cosePublicKey: COSEPublicKey,
): cosePublicKey is COSEPublicKeyEC2 {
  const kty = cosePublicKey.get(COSEKEYS.kty);
  return isCOSEKty(kty) && kty === COSEKTY.EC2;
}

export function isCOSEPublicKeyRSA(
  cosePublicKey: COSEPublicKey,
): cosePublicKey is COSEPublicKeyRSA {
  const kty = cosePublicKey.get(COSEKEYS.kty);
  return isCOSEKty(kty) && kty === COSEKTY.RSA;
}

export function isCOSEKty(kty: number | undefined): kty is COSEKTY {
  return Object.values(COSEKTY).indexOf(kty as COSEKTY) >= 0;
}

export function isCOSECrv(crv: number | undefined): crv is COSECRV {
  return Object.values(COSECRV).indexOf(crv as COSECRV) >= 0;
}

export function isCOSEAlg(alg: number | undefined): alg is COSEALG {
  return Object.values(COSEALG).indexOf(alg as COSEALG) >= 0;
}
