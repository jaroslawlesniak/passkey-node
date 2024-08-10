import { toBuffer, toUTF8String } from "@/lib/base64";
import { isCOSEPublicKeyEC2, isCOSEPublicKeyRSA } from "@/lib/cose";
import { verifyEC2, verifyRSA } from "@/lib/crypto";
import { fromUTF8String } from "@/lib/uint";

import {
  AlgSign,
  Base64URLString,
  COSEALG,
  COSECRV,
  COSEKEYS,
  COSEKTY,
  MetadataStatement,
} from "../types";
import {
  convertX509PublicKeyToCOSE,
  decodeCredentialPublicKey,
} from "../utils";
import { validateCertificatePath } from "./certificates";
import { convertCertBufferToPEM } from "./verifications";

/**
 * Match properties of the authenticator's attestation statement against expected values as
 * registered with the FIDO Alliance Metadata Service
 */
export async function verifyAttestationWithMetadata({
  statement,
  credentialPublicKey,
  x5c,
  attestationStatementAlg,
}: {
  statement: MetadataStatement;
  credentialPublicKey: Uint8Array;
  x5c: Uint8Array[] | Base64URLString[];
  attestationStatementAlg?: number;
}): Promise<boolean> {
  const {
    authenticationAlgorithms,
    authenticatorGetInfo,
    attestationRootCertificates,
  } = statement;

  // Make sure the alg in the attestation statement matches one of the ones specified in metadata
  const keypairCOSEAlgs: Set<COSEInfo> = new Set();
  authenticationAlgorithms.forEach((algSign) => {
    // Map algSign string to { kty, alg, crv }
    const algSignCOSEINFO = algSignToCOSEInfoMap[algSign];

    // Keeping this statement here just in case MDS returns something unexpected
    if (algSignCOSEINFO) {
      keypairCOSEAlgs.add(algSignCOSEINFO);
    }
  });

  // Extract the public key's COSE info for comparison
  const decodedPublicKey = decodeCredentialPublicKey(credentialPublicKey);

  const kty = decodedPublicKey.get(COSEKEYS.kty);
  const alg = decodedPublicKey.get(COSEKEYS.alg);

  if (!kty) {
    throw new Error("Credential public key was missing kty");
  }

  if (!alg) {
    throw new Error("Credential public key was missing alg");
  }

  if (!kty) {
    throw new Error("Credential public key was missing kty");
  }

  // Assume everything is a number because these values should be
  const publicKeyCOSEInfo: COSEInfo = { kty, alg };

  if (isCOSEPublicKeyEC2(decodedPublicKey)) {
    const crv = decodedPublicKey.get(COSEKEYS.crv);
    publicKeyCOSEInfo.crv = crv;
  }

  /**
   * Attempt to match the credential public key's algorithm to one specified in the device's
   * metadata
   */
  let foundMatch = false;
  for (const keypairAlg of keypairCOSEAlgs) {
    // Make sure algorithm and key type match
    if (
      keypairAlg.alg === publicKeyCOSEInfo.alg &&
      keypairAlg.kty === publicKeyCOSEInfo.kty
    ) {
      // If not an RSA keypair then make sure curve numbers match too
      if (
        (keypairAlg.kty === COSEKTY.EC2 || keypairAlg.kty === COSEKTY.OKP) &&
        keypairAlg.crv === publicKeyCOSEInfo.crv
      ) {
        foundMatch = true;
      } else {
        // We've matched an RSA public key's properties
        foundMatch = true;
      }
    }

    if (foundMatch) {
      break;
    }
  }

  // Make sure the public key is one of the allowed algorithms
  if (!foundMatch) {
    /**
     * Craft some useful error output from the MDS algorithms
     *
     * Example:
     *
     * ```
     * [
     *   'rsassa_pss_sha256_raw' (COSE info: { kty: 3, alg: -37 }),
     *   'secp256k1_ecdsa_sha256_raw' (COSE info: { kty: 2, alg: -47, crv: 8 })
     * ]
     * ```
     */
    const debugMDSAlgs = authenticationAlgorithms.map(
      (algSign) =>
        `'${algSign}' (COSE info: ${stringifyCOSEInfo(algSignToCOSEInfoMap[algSign])})`,
    );
    const strMDSAlgs = JSON.stringify(debugMDSAlgs, null, 2).replace(/"/g, "");

    /**
     * Construct useful error output about the public key
     */
    const strPubKeyAlg = stringifyCOSEInfo(publicKeyCOSEInfo);

    throw new Error(
      `Public key parameters ${strPubKeyAlg} did not match any of the following metadata algorithms:\n${strMDSAlgs}`,
    );
  }

  /**
   * Confirm the attestation statement's algorithm is one supported according to metadata
   */
  if (
    attestationStatementAlg !== undefined &&
    authenticatorGetInfo?.algorithms !== undefined
  ) {
    const getInfoAlgs = authenticatorGetInfo.algorithms.map((_alg) => _alg.alg);
    if (getInfoAlgs.indexOf(attestationStatementAlg) < 0) {
      throw new Error(
        `Attestation statement alg ${attestationStatementAlg} did not match one of ${getInfoAlgs}`,
      );
    }
  }

  // Prepare to check the certificate chain
  const authenticatorCerts = x5c.map(convertCertBufferToPEM);
  const statementRootCerts = attestationRootCertificates.map(
    convertCertBufferToPEM,
  );

  /**
   * If an authenticator returns exactly one certificate in its x5c, and that cert is found in the
   * metadata statement then the authenticator is "self-referencing". In this case we forego
   * certificate chain validation.
   */
  let authenticatorIsSelfReferencing = false;
  if (
    authenticatorCerts.length === 1 &&
    statementRootCerts.indexOf(authenticatorCerts[0]) >= 0
  ) {
    authenticatorIsSelfReferencing = true;
  }

  if (!authenticatorIsSelfReferencing) {
    try {
      await validateCertificatePath(authenticatorCerts, statementRootCerts);
    } catch (err) {
      const _err = err as Error;
      throw new Error(
        `Could not validate certificate path with any metadata root certificates: ${_err.message}`,
      );
    }
  }

  return true;
}

type COSEInfo = {
  kty: COSEKTY;
  alg: COSEALG;
  crv?: COSECRV;
};

/**
 * Convert ALG_SIGN values to COSE info
 *
 * Values pulled from `ALG_KEY_COSE` definitions in the FIDO Registry of Predefined Values
 *
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authentication-algorithms
 */
export const algSignToCOSEInfoMap: { [key in AlgSign]: COSEInfo } = {
  secp256r1_ecdsa_sha256_raw: { kty: 2, alg: -7, crv: 1 },
  secp256r1_ecdsa_sha256_der: { kty: 2, alg: -7, crv: 1 },
  rsassa_pss_sha256_raw: { kty: 3, alg: -37 },
  rsassa_pss_sha256_der: { kty: 3, alg: -37 },
  secp256k1_ecdsa_sha256_raw: { kty: 2, alg: -47, crv: 8 },
  secp256k1_ecdsa_sha256_der: { kty: 2, alg: -47, crv: 8 },
  rsassa_pss_sha384_raw: { kty: 3, alg: -38 },
  rsassa_pkcsv15_sha256_raw: { kty: 3, alg: -257 },
  rsassa_pkcsv15_sha384_raw: { kty: 3, alg: -258 },
  rsassa_pkcsv15_sha512_raw: { kty: 3, alg: -259 },
  rsassa_pkcsv15_sha1_raw: { kty: 3, alg: -65535 },
  secp384r1_ecdsa_sha384_raw: { kty: 2, alg: -35, crv: 2 },
  secp512r1_ecdsa_sha256_raw: { kty: 2, alg: -36, crv: 3 },
  ed25519_eddsa_sha512_raw: { kty: 1, alg: -8, crv: 6 },
};

/**
 * A helper to format COSEInfo a little nicer than we can achieve with JSON.stringify()
 *
 * Input: `{ "kty": 3, "alg": -257 }`
 *
 * Output: `"{ kty: 3, alg: -257 }"`
 */
function stringifyCOSEInfo(info: COSEInfo): string {
  const { kty, alg, crv } = info;

  let toReturn = "";
  if (kty !== COSEKTY.RSA) {
    toReturn = `{ kty: ${kty}, alg: ${alg}, crv: ${crv} }`;
  } else {
    toReturn = `{ kty: ${kty}, alg: ${alg} }`;
  }

  return toReturn;
}

/**
 * Lightweight verification for FIDO MDS JWTs. Supports use of EC2 and RSA.
 *
 * If this ever needs to support more JWS algorithms, here's the list of them:
 *
 * https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1
 *
 * (Pulled from https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1)
 */
export function verifyJWT(jwt: string, leafCert: Uint8Array): Promise<boolean> {
  const [header, payload, signature] = jwt.split(".");

  const certCOSE = convertX509PublicKeyToCOSE(leafCert);
  const data = fromUTF8String(`${header}.${payload}`);
  const signatureBytes = toBuffer(signature);

  if (isCOSEPublicKeyEC2(certCOSE)) {
    return verifyEC2({
      data,
      signature: signatureBytes,
      cosePublicKey: certCOSE,
      shaHashOverride: COSEALG.ES256,
    });
  } else if (isCOSEPublicKeyRSA(certCOSE)) {
    return verifyRSA({
      data,
      signature: signatureBytes,
      cosePublicKey: certCOSE,
    });
  }

  const kty = certCOSE.get(COSEKEYS.kty);
  throw new Error(
    `JWT verification with public key of kty ${kty} is not supported by this method`,
  );
}

/**
 * Process a JWT into Javascript-friendly data structures
 */
export function parseJWT<T1, T2>(jwt: string): [T1, T2, string] {
  const parts = jwt.split(".");
  return [
    JSON.parse(toUTF8String(parts[0])) as T1,
    JSON.parse(toUTF8String(parts[1])) as T2,
    parts[2],
  ];
}
