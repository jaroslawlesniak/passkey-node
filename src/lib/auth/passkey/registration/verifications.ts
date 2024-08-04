import { areEqual, concat, fromUTF8String, toDataView, toHex, toUTF8String } from "@/lib/uint";
import { AttestationFormatVerifierOpts, Base64URLString, COSEALG, COSEKEYS, COSEPublicKeyEC2, ECCParameters, ParsedPubArea, RSAParameters, SafetyNetJWTHeader, SafetyNetJWTPayload, SafetyNetJWTSignature } from "../types";
import { decodeCredentialPublicKey, toHash, verifySignature } from "../utils";
import { decodeFirst } from "@/lib/cbor";
import { getCertificateInfo, parseCertInfo, validateCertificatePath } from "./certificates";
import { fromBuffer, isBase64, isBase64URL, toBase64, toBuffer } from "@/lib/base64";
import { isCOSEAlg, isCOSEPublicKeyEC2, isCOSEPublicKeyRSA } from "@/lib/cose";
import { verifyAttestationWithMetadata } from "./metadata";
import { AsnParser, Certificate, ExtendedKeyUsage, id_ce_extKeyUsage, id_ce_keyDescription, id_ce_subjectAltName, KeyDescription, Name, SubjectAlternativeName } from '@/lib/asn'

import * as base64 from '@/lib/base64'
import { TPM_ALG, TPM_ECC_CURVE, TPM_ECC_CURVE_COSE_CRV_MAP, TPM_MANUFACTURERS } from "./constants";
import { MetadataService } from "./services";

/**
 * Convert buffer to an OpenSSL-compatible PEM text format.
 */
export function convertCertBufferToPEM(
  certBuffer: Uint8Array | Base64URLString,
): string {
  let b64cert: string;

  /**
   * Get certBuffer to a base64 representation
   */
  if (typeof certBuffer === 'string') {
    if (isBase64URL(certBuffer)) {
      b64cert = toBase64(certBuffer);
    } else if (isBase64(certBuffer)) {
      b64cert = certBuffer;
    } else {
      throw new Error('Certificate is not a valid base64 or base64url string');
    }
  } else {
    b64cert = fromBuffer(certBuffer, 'base64');
  }

  let PEMKey = '';
  for (let i = 0; i < Math.ceil(b64cert.length / 64); i += 1) {
    const start = 64 * i;

    PEMKey += `${b64cert.substr(start, 64)}\n`;
  }

  PEMKey = `-----BEGIN CERTIFICATE-----\n${PEMKey}-----END CERTIFICATE-----\n`;

  return PEMKey;
}

/**
 * Takes COSE-encoded public key and converts it to PKCS key
 */
export function convertCOSEtoPKCS(cosePublicKey: Uint8Array): Uint8Array {
  // This is a little sloppy, I'm using COSEPublicKeyEC2 since it could have both x and y, but when
  // there's no y it means it's probably better typed as COSEPublicKeyOKP. I'll leave this for now
  // and revisit it later if it ever becomes an actual problem.
  const struct = decodeFirst<COSEPublicKeyEC2>(cosePublicKey);

  const tag = Uint8Array.from([0x04]);
  const x = struct.get(COSEKEYS.x);
  const y = struct.get(COSEKEYS.y);

  if (!x) {
    throw new Error('COSE public key was missing x');
  }

  if (y) {
    return concat([tag, x, y]);
  }

  return concat([tag, x]);
}

/**
 * Verify an attestation response with fmt 'fido-u2f'
 */
export async function verifyAttestationFIDOU2F(
  options: AttestationFormatVerifierOpts,
): Promise<boolean> {
  const {
    attStmt,
    clientDataHash,
    rpIdHash,
    credentialID,
    credentialPublicKey,
    aaguid,
    rootCertificates,
  } = options;

  const reservedByte = Uint8Array.from([0x00]);
  const publicKey = convertCOSEtoPKCS(credentialPublicKey);

  const signatureBase = concat([
    reservedByte,
    rpIdHash,
    clientDataHash,
    credentialID,
    publicKey,
  ]);

  const sig = attStmt.get('sig');
  const x5c = attStmt.get('x5c');

  if (!x5c) {
    throw new Error(
      'No attestation certificate provided in attestation statement (FIDOU2F)',
    );
  }

  if (!sig) {
    throw new Error(
      'No attestation signature provided in attestation statement (FIDOU2F)',
    );
  }

  // FIDO spec says that aaguid _must_ equal 0x00 here to be legit
  const aaguidToHex = Number.parseInt(toHex(aaguid), 16);
  if (aaguidToHex !== 0x00) {
    throw new Error(`AAGUID "${aaguidToHex}" was not expected value`);
  }

  try {
    // Try validating the certificate path using the root certificates set via SettingsService
    await validateCertificatePath(
      x5c.map(convertCertBufferToPEM),
      rootCertificates,
    );
  } catch (err) {
    const _err = err as Error;
    throw new Error(`${_err.message} (FIDOU2F)`);
  }

  return verifySignature({
    signature: sig,
    data: signatureBase,
    x509Certificate: x5c[0],
    hashAlgorithm: COSEALG.ES256,
  });
}

/**
 * Verify an attestation response with fmt 'packed'
 */
export async function verifyAttestationPacked(
  options: AttestationFormatVerifierOpts,
): Promise<boolean> {
  const {
    attStmt,
    clientDataHash,
    authData,
    credentialPublicKey,
    aaguid,
    rootCertificates,
  } = options;

  const sig = attStmt.get('sig');
  const x5c = attStmt.get('x5c');
  const alg = attStmt.get('alg');

  if (!sig) {
    throw new Error(
      'No attestation signature provided in attestation statement (Packed)',
    );
  }

  if (!alg) {
    throw new Error('Attestation statement did not contain alg (Packed)');
  }

  if (!isCOSEAlg(alg)) {
    throw new Error(
      `Attestation statement contained invalid alg ${alg} (Packed)`,
    );
  }

  const signatureBase = concat([authData, clientDataHash]);

  let verified = false;

  if (x5c) {
    const { subject, basicConstraintsCA, version, notBefore, notAfter } = getCertificateInfo(
      x5c[0],
    );

    const { OU, CN, O, C } = subject;

    if (OU !== 'Authenticator Attestation') {
      throw new Error(
        'Certificate OU was not "Authenticator Attestation" (Packed|Full)',
      );
    }

    if (!CN) {
      throw new Error('Certificate CN was empty (Packed|Full)');
    }

    if (!O) {
      throw new Error('Certificate O was empty (Packed|Full)');
    }

    if (!C || C.length !== 2) {
      throw new Error(
        'Certificate C was not two-character ISO 3166 code (Packed|Full)',
      );
    }

    if (basicConstraintsCA) {
      throw new Error(
        'Certificate basic constraints CA was not `false` (Packed|Full)',
      );
    }

    if (version !== 2) {
      throw new Error(
        'Certificate version was not `3` (ASN.1 value of 2) (Packed|Full)',
      );
    }

    let now = new Date();
    if (notBefore > now) {
      throw new Error(
        `Certificate not good before "${notBefore.toString()}" (Packed|Full)`,
      );
    }

    now = new Date();
    if (notAfter < now) {
      throw new Error(
        `Certificate not good after "${notAfter.toString()}" (Packed|Full)`,
      );
    }

    // TODO: If certificate contains id-fido-gen-ce-aaguid(1.3.6.1.4.1.45724.1.1.4) extension, check
    // that it’s value is set to the same AAGUID as in authData.

    // If available, validate attestation alg and x5c with info in the metadata statement
    const statement = await MetadataService.getStatement(aaguid);
    if (statement) {
      // The presence of x5c means this is a full attestation. Check to see if attestationTypes
      // includes packed attestations.
      if (statement.attestationTypes.indexOf('basic_full') < 0) {
        throw new Error(
          'Metadata does not indicate support for full attestations (Packed|Full)',
        );
      }

      try {
        await verifyAttestationWithMetadata({
          statement,
          credentialPublicKey,
          x5c,
          attestationStatementAlg: alg,
        });
      } catch (err) {
        const _err = err as Error;
        throw new Error(`${_err.message} (Packed|Full)`);
      }
    } else {
      try {
        // Try validating the certificate path using the root certificates set via SettingsService
        await validateCertificatePath(
          x5c.map(convertCertBufferToPEM),
          rootCertificates,
        );
      } catch (err) {
        const _err = err as Error;
        throw new Error(`${_err.message} (Packed|Full)`);
      }
    }

    verified = await verifySignature({
      signature: sig,
      data: signatureBase,
      x509Certificate: x5c[0],
    });
  } else {
    verified = await verifySignature({
      signature: sig,
      data: signatureBase,
      credentialPublicKey,
      hashAlgorithm: alg,
    });
  }

  return verified;
}

/**
 * Verify an attestation response with fmt 'android-safetynet'
 */
export async function verifyAttestationAndroidSafetyNet(
  options: AttestationFormatVerifierOpts,
): Promise<boolean> {
  const {
    attStmt,
    clientDataHash,
    authData,
    aaguid,
    rootCertificates,
    verifyTimestampMS = true,
    credentialPublicKey,
  } = options;
  const alg = attStmt.get('alg');
  const response = attStmt.get('response');
  const ver = attStmt.get('ver');

  if (!ver) {
    throw new Error('No ver value in attestation (SafetyNet)');
  }

  if (!response) {
    throw new Error(
      'No response was included in attStmt by authenticator (SafetyNet)',
    );
  }

  // Prepare to verify a JWT
  const jwt = toUTF8String(response);
  const jwtParts = jwt.split('.');

  const HEADER: SafetyNetJWTHeader = JSON.parse(
    base64.toUTF8String(jwtParts[0]),
  );
  const PAYLOAD: SafetyNetJWTPayload = JSON.parse(
    base64.toUTF8String(jwtParts[1]),
  );
  const SIGNATURE: SafetyNetJWTSignature = jwtParts[2];

  /**
   * START Verify PAYLOAD
   */
  const { nonce, ctsProfileMatch, timestampMs } = PAYLOAD;

  if (verifyTimestampMS) {
    // Make sure timestamp is in the past
    let now = Date.now();
    if (timestampMs > Date.now()) {
      throw new Error(
        `Payload timestamp "${timestampMs}" was later than "${now}" (SafetyNet)`,
      );
    }

    // Consider a SafetyNet attestation valid within a minute of it being performed
    const timestampPlusDelay = timestampMs + 60 * 1000;
    now = Date.now();
    if (timestampPlusDelay < now) {
      throw new Error(
        `Payload timestamp "${timestampPlusDelay}" has expired (SafetyNet)`,
      );
    }
  }

  const nonceBase = concat([authData, clientDataHash]);
  const nonceBuffer = await toHash(nonceBase);
  const expectedNonce = fromBuffer(nonceBuffer, 'base64');

  if (nonce !== expectedNonce) {
    throw new Error('Could not verify payload nonce (SafetyNet)');
  }

  if (!ctsProfileMatch) {
    throw new Error('Could not verify device integrity (SafetyNet)');
  }
  /**
   * END Verify PAYLOAD
   */

  /**
   * START Verify Header
   */
  // `HEADER.x5c[0]` is definitely a base64 string
  const leafCertBuffer = toBuffer(HEADER.x5c[0], 'base64');
  const leafCertInfo = getCertificateInfo(leafCertBuffer);

  const { subject } = leafCertInfo;

  // Ensure the certificate was issued to this hostname
  // See https://developer.android.com/training/safetynet/attestation#verify-attestation-response
  if (subject.CN !== 'attest.android.com') {
    throw new Error(
      'Certificate common name was not "attest.android.com" (SafetyNet)',
    );
  }

  const statement = await MetadataService.getStatement(aaguid);
  if (statement) {
    try {
      await verifyAttestationWithMetadata({
        statement,
        credentialPublicKey,
        x5c: HEADER.x5c,
        attestationStatementAlg: alg,
      });
    } catch (err) {
      const _err = err as Error;
      throw new Error(`${_err.message} (SafetyNet)`);
    }
  } else {
    try {
      // Try validating the certificate path using the root certificates set via SettingsService
      await validateCertificatePath(
        HEADER.x5c.map(convertCertBufferToPEM),
        rootCertificates,
      );
    } catch (err) {
      const _err = err as Error;
      throw new Error(`${_err.message} (SafetyNet)`);
    }
  }
  /**
   * END Verify Header
   */

  /**
   * START Verify Signature
   */
  const signatureBaseBuffer = fromUTF8String(
    `${jwtParts[0]}.${jwtParts[1]}`,
  );
  const signatureBuffer = toBuffer(SIGNATURE);

  const verified = await verifySignature({
    signature: signatureBuffer,
    data: signatureBaseBuffer,
    x509Certificate: leafCertBuffer,
  });
  /**
   * END Verify Signature
   */

  return verified;
}

/**
 * Verify an attestation response with fmt 'android-key'
 */
export async function verifyAttestationAndroidKey(
  options: AttestationFormatVerifierOpts,
): Promise<boolean> {
  const {
    authData,
    clientDataHash,
    attStmt,
    credentialPublicKey,
    aaguid,
    rootCertificates,
  } = options;
  const x5c = attStmt.get('x5c');
  const sig = attStmt.get('sig');
  const alg = attStmt.get('alg');

  if (!x5c) {
    throw new Error(
      'No attestation certificate provided in attestation statement (AndroidKey)',
    );
  }

  if (!sig) {
    throw new Error(
      'No attestation signature provided in attestation statement (AndroidKey)',
    );
  }

  if (!alg) {
    throw new Error(`Attestation statement did not contain alg (AndroidKey)`);
  }

  if (!isCOSEAlg(alg)) {
    throw new Error(
      `Attestation statement contained invalid alg ${alg} (AndroidKey)`,
    );
  }

  // Check that credentialPublicKey matches the public key in the attestation certificate
  // Find the public cert in the certificate as PKCS
  const parsedCert = AsnParser.parse(x5c[0], Certificate);
  const parsedCertPubKey = new Uint8Array(
    parsedCert.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,
  );

  // Convert the credentialPublicKey to PKCS
  const credPubKeyPKCS = convertCOSEtoPKCS(credentialPublicKey);

  if (!areEqual(credPubKeyPKCS, parsedCertPubKey)) {
    throw new Error(
      'Credential public key does not equal leaf cert public key (AndroidKey)',
    );
  }

  // Find Android KeyStore Extension in certificate extensions
  const extKeyStore = parsedCert.tbsCertificate.extensions?.find(
    (ext) => ext.extnID === id_ce_keyDescription,
  );

  if (!extKeyStore) {
    throw new Error('Certificate did not contain extKeyStore (AndroidKey)');
  }

  const parsedExtKeyStore = AsnParser.parse(
    extKeyStore.extnValue,
    KeyDescription,
  );

  // Verify extKeyStore values
  const { attestationChallenge, teeEnforced, softwareEnforced } = parsedExtKeyStore;

  if (
    !areEqual(
      new Uint8Array(attestationChallenge.buffer),
      clientDataHash,
    )
  ) {
    throw new Error(
      'Attestation challenge was not equal to client data hash (AndroidKey)',
    );
  }

  // Ensure that the key is strictly bound to the caller app identifier (shouldn't contain the
  // [600] tag)
  if (teeEnforced.allApplications !== undefined) {
    throw new Error(
      'teeEnforced contained "allApplications [600]" tag (AndroidKey)',
    );
  }

  if (softwareEnforced.allApplications !== undefined) {
    throw new Error(
      'teeEnforced contained "allApplications [600]" tag (AndroidKey)',
    );
  }

  const statement = await MetadataService.getStatement(aaguid);
  if (statement) {
    try {
      await verifyAttestationWithMetadata({
        statement,
        credentialPublicKey,
        x5c,
        attestationStatementAlg: alg,
      });
    } catch (err) {
      const _err = err as Error;
      throw new Error(`${_err.message} (AndroidKey)`);
    }
  } else {
    try {
      // Try validating the certificate path using the root certificates set via SettingsService
      await validateCertificatePath(
        x5c.map(convertCertBufferToPEM),
        rootCertificates,
      );
    } catch (err) {
      const _err = err as Error;
      throw new Error(`${_err.message} (AndroidKey)`);
    }
  }

  const signatureBase = concat([authData, clientDataHash]);

  return verifySignature({
    signature: sig,
    data: signatureBase,
    x509Certificate: x5c[0],
    hashAlgorithm: alg,
  });
}

/**
 * Break apart a TPM attestation's pubArea buffer
 *
 * See 12.2.4 TPMT_PUBLIC here:
 * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
 */
export function parsePubArea(pubArea: Uint8Array): ParsedPubArea {
  let pointer = 0;
  const dataView = toDataView(pubArea);

  const type = TPM_ALG[dataView.getUint16(pointer)];
  pointer += 2;

  const nameAlg = TPM_ALG[dataView.getUint16(pointer)];
  pointer += 2;

  // Get some authenticator attributes(?)
  // const objectAttributesInt = pubArea.slice(pointer, (pointer += 4)).readUInt32BE(0);
  const objectAttributesInt = dataView.getUint32(pointer);
  pointer += 4;
  const objectAttributes = {
    fixedTPM: !!(objectAttributesInt & 1),
    stClear: !!(objectAttributesInt & 2),
    fixedParent: !!(objectAttributesInt & 8),
    sensitiveDataOrigin: !!(objectAttributesInt & 16),
    userWithAuth: !!(objectAttributesInt & 32),
    adminWithPolicy: !!(objectAttributesInt & 64),
    noDA: !!(objectAttributesInt & 512),
    encryptedDuplication: !!(objectAttributesInt & 1024),
    restricted: !!(objectAttributesInt & 32768),
    decrypt: !!(objectAttributesInt & 65536),
    signOrEncrypt: !!(objectAttributesInt & 131072),
  };

  // Slice out the authPolicy of dynamic length
  const authPolicyLength = dataView.getUint16(pointer);
  pointer += 2;
  const authPolicy = pubArea.slice(pointer, pointer += authPolicyLength);

  // Extract additional curve params according to type
  const parameters: { rsa?: RSAParameters; ecc?: ECCParameters } = {};
  let unique = Uint8Array.from([]);

  if (type === 'TPM_ALG_RSA') {
    const symmetric = TPM_ALG[dataView.getUint16(pointer)];
    pointer += 2;

    const scheme = TPM_ALG[dataView.getUint16(pointer)];
    pointer += 2;

    const keyBits = dataView.getUint16(pointer);
    pointer += 2;

    const exponent = dataView.getUint32(pointer);
    pointer += 4;

    parameters.rsa = { symmetric, scheme, keyBits, exponent };

    /**
     * See 11.2.4.5 TPM2B_PUBLIC_KEY_RSA here:
     * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
     */
    // const uniqueLength = pubArea.slice(pointer, (pointer += 2)).readUInt16BE(0);
    const uniqueLength = dataView.getUint16(pointer);
    pointer += 2;

    unique = pubArea.slice(pointer, pointer += uniqueLength);
  } else if (type === 'TPM_ALG_ECC') {
    const symmetric = TPM_ALG[dataView.getUint16(pointer)];
    pointer += 2;

    const scheme = TPM_ALG[dataView.getUint16(pointer)];
    pointer += 2;

    const curveID = TPM_ECC_CURVE[dataView.getUint16(pointer)];
    pointer += 2;

    const kdf = TPM_ALG[dataView.getUint16(pointer)];
    pointer += 2;

    parameters.ecc = { symmetric, scheme, curveID, kdf };

    /**
     * See 11.2.5.1 TPM2B_ECC_PARAMETER here:
     * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
     */
    // Retrieve X
    const uniqueXLength = dataView.getUint16(pointer);
    pointer += 2;

    const uniqueX = pubArea.slice(pointer, pointer += uniqueXLength);

    // Retrieve Y
    const uniqueYLength = dataView.getUint16(pointer);
    pointer += 2;

    const uniqueY = pubArea.slice(pointer, pointer += uniqueYLength);

    unique = concat([uniqueX, uniqueY]);
  } else {
    throw new Error(`Unexpected type "${type}" (TPM)`);
  }

  return {
    type,
    nameAlg,
    objectAttributes,
    authPolicy,
    parameters,
    unique,
  };
}

export async function verifyAttestationTPM(
  options: AttestationFormatVerifierOpts,
): Promise<boolean> {
  const {
    aaguid,
    attStmt,
    authData,
    credentialPublicKey,
    clientDataHash,
    rootCertificates,
  } = options;
  const ver = attStmt.get('ver');
  const sig = attStmt.get('sig');
  const alg = attStmt.get('alg');
  const x5c = attStmt.get('x5c');
  const pubArea = attStmt.get('pubArea');
  const certInfo = attStmt.get('certInfo');

  /**
   * Verify structures
   */
  if (ver !== '2.0') {
    throw new Error(`Unexpected ver "${ver}", expected "2.0" (TPM)`);
  }

  if (!sig) {
    throw new Error(
      'No attestation signature provided in attestation statement (TPM)',
    );
  }

  if (!alg) {
    throw new Error(`Attestation statement did not contain alg (TPM)`);
  }

  if (!isCOSEAlg(alg)) {
    throw new Error(`Attestation statement contained invalid alg ${alg} (TPM)`);
  }

  if (!x5c) {
    throw new Error(
      'No attestation certificate provided in attestation statement (TPM)',
    );
  }

  if (!pubArea) {
    throw new Error('Attestation statement did not contain pubArea (TPM)');
  }

  if (!certInfo) {
    throw new Error('Attestation statement did not contain certInfo (TPM)');
  }

  const parsedPubArea = parsePubArea(pubArea);
  const { unique, type: pubType, parameters } = parsedPubArea;

  // Verify that the public key specified by the parameters and unique fields of pubArea is
  // identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.
  const cosePublicKey = decodeCredentialPublicKey(credentialPublicKey);

  if (pubType === 'TPM_ALG_RSA') {
    if (!isCOSEPublicKeyRSA(cosePublicKey)) {
      throw new Error(
        `Credential public key with kty ${
          cosePublicKey.get(
            COSEKEYS.kty,
          )
        } did not match ${pubType}`,
      );
    }

    const n = cosePublicKey.get(COSEKEYS.n);
    const e = cosePublicKey.get(COSEKEYS.e);

    if (!n) {
      throw new Error('COSE public key missing n (TPM|RSA)');
    }
    if (!e) {
      throw new Error('COSE public key missing e (TPM|RSA)');
    }

    if (!areEqual(unique, n)) {
      throw new Error(
        'PubArea unique is not same as credentialPublicKey (TPM|RSA)',
      );
    }

    if (!parameters.rsa) {
      throw new Error(
        `Parsed pubArea type is RSA, but missing parameters.rsa (TPM|RSA)`,
      );
    }

    const eBuffer = e as Uint8Array;
    // If `exponent` is equal to 0x00, then exponent is the default RSA exponent of 2^16+1 (65537)
    const pubAreaExponent = parameters.rsa.exponent || 65537;

    // Do some bit shifting to get to an integer
    const eSum = eBuffer[0] + (eBuffer[1] << 8) + (eBuffer[2] << 16);

    if (pubAreaExponent !== eSum) {
      throw new Error(
        `Unexpected public key exp ${eSum}, expected ${pubAreaExponent} (TPM|RSA)`,
      );
    }
  } else if (pubType === 'TPM_ALG_ECC') {
    if (!isCOSEPublicKeyEC2(cosePublicKey)) {
      throw new Error(
        `Credential public key with kty ${
          cosePublicKey.get(
            COSEKEYS.kty,
          )
        } did not match ${pubType}`,
      );
    }

    const crv = cosePublicKey.get(COSEKEYS.crv);
    const x = cosePublicKey.get(COSEKEYS.x);
    const y = cosePublicKey.get(COSEKEYS.y);

    if (!crv) {
      throw new Error('COSE public key missing crv (TPM|ECC)');
    }
    if (!x) {
      throw new Error('COSE public key missing x (TPM|ECC)');
    }
    if (!y) {
      throw new Error('COSE public key missing y (TPM|ECC)');
    }

    if (!areEqual(unique, concat([x, y]))) {
      throw new Error(
        'PubArea unique is not same as public key x and y (TPM|ECC)',
      );
    }

    if (!parameters.ecc) {
      throw new Error(
        `Parsed pubArea type is ECC, but missing parameters.ecc (TPM|ECC)`,
      );
    }

    const pubAreaCurveID = parameters.ecc.curveID;
    const pubAreaCurveIDMapToCOSECRV = TPM_ECC_CURVE_COSE_CRV_MAP[pubAreaCurveID];
    if (pubAreaCurveIDMapToCOSECRV !== crv) {
      throw new Error(
        `Public area key curve ID "${pubAreaCurveID}" mapped to "${pubAreaCurveIDMapToCOSECRV}" which did not match public key crv of "${crv}" (TPM|ECC)`,
      );
    }
  } else {
    throw new Error(`Unsupported pubArea.type "${pubType}"`);
  }

  const parsedCertInfo = parseCertInfo(certInfo);
  const { magic, type: certType, attested, extraData } = parsedCertInfo;

  if (magic !== 0xff544347) {
    throw new Error(
      `Unexpected magic value "${magic}", expected "0xff544347" (TPM)`,
    );
  }

  if (certType !== 'TPM_ST_ATTEST_CERTIFY') {
    throw new Error(
      `Unexpected type "${certType}", expected "TPM_ST_ATTEST_CERTIFY" (TPM)`,
    );
  }

  // Hash pubArea to create pubAreaHash using the nameAlg in attested
  const pubAreaHash = await toHash(
    pubArea,
    attestedNameAlgToCOSEAlg(attested.nameAlg),
  );

  // Concatenate attested.nameAlg and pubAreaHash to create attestedName.
  const attestedName = concat([
    attested.nameAlgBuffer,
    pubAreaHash,
  ]);

  // Check that certInfo.attested.name is equals to attestedName.
  if (!areEqual(attested.name, attestedName)) {
    throw new Error(`Attested name comparison failed (TPM)`);
  }

  // Concatenate authData with clientDataHash to create attToBeSigned
  const attToBeSigned = concat([authData, clientDataHash]);

  // Hash attToBeSigned using the algorithm specified in attStmt.alg to create attToBeSignedHash
  const attToBeSignedHash = await toHash(attToBeSigned, alg);

  // Check that certInfo.extraData is equals to attToBeSignedHash.
  if (!areEqual(extraData, attToBeSignedHash)) {
    throw new Error(
      'CertInfo extra data did not equal hashed attestation (TPM)',
    );
  }

  /**
   * Verify signature
   */
  if (x5c.length < 1) {
    throw new Error('No certificates present in x5c array (TPM)');
  }

  // Pick a leaf AIK certificate of the x5c array and parse it.
  const leafCertInfo = getCertificateInfo(x5c[0]);
  const { basicConstraintsCA, version, subject, notAfter, notBefore } = leafCertInfo;

  if (basicConstraintsCA) {
    throw new Error('Certificate basic constraints CA was not `false` (TPM)');
  }

  // Check that certificate is of version 3 (value must be set to 2).
  if (version !== 2) {
    throw new Error('Certificate version was not `3` (ASN.1 value of 2) (TPM)');
  }

  // Check that Subject sequence is empty.
  if (subject.combined.length > 0) {
    throw new Error('Certificate subject was not empty (TPM)');
  }

  // Check that certificate is currently valid
  let now = new Date();
  if (notBefore > now) {
    throw new Error(
      `Certificate not good before "${notBefore.toString()}" (TPM)`,
    );
  }

  // Check that certificate has not expired
  now = new Date();
  if (notAfter < now) {
    throw new Error(
      `Certificate not good after "${notAfter.toString()}" (TPM)`,
    );
  }

  /**
   * Plumb the depths of the certificate's ASN.1-formatted data for some values we need to verify
   */
  const parsedCert = AsnParser.parse(x5c[0], Certificate);

  if (!parsedCert.tbsCertificate.extensions) {
    throw new Error('Certificate was missing extensions (TPM)');
  }

  let subjectAltNamePresent: SubjectAlternativeName | undefined;
  let extKeyUsage: ExtendedKeyUsage | undefined;
  parsedCert.tbsCertificate.extensions.forEach((ext) => {
    if (ext.extnID === id_ce_subjectAltName) {
      subjectAltNamePresent = AsnParser.parse(
        ext.extnValue,
        SubjectAlternativeName,
      );
    } else if (ext.extnID === id_ce_extKeyUsage) {
      extKeyUsage = AsnParser.parse(ext.extnValue, ExtendedKeyUsage);
    }
  });

  // Check that certificate contains subjectAltName (2.5.29.17) extension,
  if (!subjectAltNamePresent) {
    throw new Error(
      'Certificate did not contain subjectAltName extension (TPM)',
    );
  }

  // TPM-specific values are buried within `directoryName`, so first make sure there are values
  // there.
  if (!subjectAltNamePresent[0].directoryName?.[0].length) {
    throw new Error(
      'Certificate subjectAltName extension directoryName was empty (TPM)',
    );
  }

  const { tcgAtTpmManufacturer, tcgAtTpmModel, tcgAtTpmVersion } = getTcgAtTpmValues(
    subjectAltNamePresent[0].directoryName,
  );

  if (!tcgAtTpmManufacturer || !tcgAtTpmModel || !tcgAtTpmVersion) {
    throw new Error(
      'Certificate contained incomplete subjectAltName data (TPM)',
    );
  }

  if (!extKeyUsage) {
    throw new Error(
      'Certificate did not contain ExtendedKeyUsage extension (TPM)',
    );
  }

  // Check that tcpaTpmManufacturer (2.23.133.2.1) field is set to a valid manufacturer ID.
  if (!TPM_MANUFACTURERS[tcgAtTpmManufacturer]) {
    throw new Error(
      `Could not match TPM manufacturer "${tcgAtTpmManufacturer}" (TPM)`,
    );
  }

  // Check that certificate contains extKeyUsage (2.5.29.37) extension and it must contain
  // tcg-kp-AIKCertificate (2.23.133.8.3) OID.
  if (extKeyUsage[0] !== '2.23.133.8.3') {
    throw new Error(
      `Unexpected extKeyUsage "${extKeyUsage[0]}", expected "2.23.133.8.3" (TPM)`,
    );
  }

  // TODO: If certificate contains id-fido-gen-ce-aaguid(1.3.6.1.4.1.45724.1.1.4) extension, check
  // that it’s value is set to the same AAGUID as in authData.

  // Run some metadata checks if a statement exists for this authenticator
  const statement = await MetadataService.getStatement(aaguid);
  if (statement) {
    try {
      await verifyAttestationWithMetadata({
        statement,
        credentialPublicKey,
        x5c,
        attestationStatementAlg: alg,
      });
    } catch (err) {
      const _err = err as Error;
      throw new Error(`${_err.message} (TPM)`);
    }
  } else {
    try {
      // Try validating the certificate path using the root certificates set via SettingsService
      await validateCertificatePath(
        x5c.map(convertCertBufferToPEM),
        rootCertificates,
      );
    } catch (err) {
      const _err = err as Error;
      throw new Error(`${_err.message} (TPM)`);
    }
  }

  // Verify signature over certInfo with the public key extracted from AIK certificate.
  // In the wise words of Yuriy Ackermann: "Get Martini friend, you are done!"
  return verifySignature({
    signature: sig,
    data: certInfo,
    x509Certificate: x5c[0],
    hashAlgorithm: alg,
  });
}

/**
 * Contain logic for pulling TPM-specific values out of subjectAlternativeName extension
 */
function getTcgAtTpmValues(root: Name): {
  tcgAtTpmManufacturer?: string;
  tcgAtTpmModel?: string;
  tcgAtTpmVersion?: string;
} {
  const oidManufacturer = '2.23.133.2.1';
  const oidModel = '2.23.133.2.2';
  const oidVersion = '2.23.133.2.3';

  let tcgAtTpmManufacturer: string | undefined;
  let tcgAtTpmModel: string | undefined;
  let tcgAtTpmVersion: string | undefined;

  /**
   * Iterate through the following potential structures:
   *
   * (Good, follows the spec)
   * https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p3_r2_pub.pdf (page 33)
   * Name [
   *   RelativeDistinguishedName [
   *     AttributeTypeAndValue { type, value }
   *   ]
   *   RelativeDistinguishedName [
   *     AttributeTypeAndValue { type, value }
   *   ]
   *   RelativeDistinguishedName [
   *     AttributeTypeAndValue { type, value }
   *   ]
   * ]
   *
   * (Bad, does not follow the spec)
   * Name [
   *   RelativeDistinguishedName [
   *     AttributeTypeAndValue { type, value }
   *     AttributeTypeAndValue { type, value }
   *     AttributeTypeAndValue { type, value }
   *   ]
   * ]
   *
   * Both structures have been seen in the wild and need to be supported
   */
  root.forEach((relName) => {
    relName.forEach((attr) => {
      if (attr.type === oidManufacturer) {
        tcgAtTpmManufacturer = attr.value.toString();
      } else if (attr.type === oidModel) {
        tcgAtTpmModel = attr.value.toString();
      } else if (attr.type === oidVersion) {
        tcgAtTpmVersion = attr.value.toString();
      }
    });
  });

  return {
    tcgAtTpmManufacturer,
    tcgAtTpmModel,
    tcgAtTpmVersion,
  };
}

/**
 * Convert TPM-specific SHA algorithm ID's with COSE-specific equivalents. Note that the choice to
 * use ECDSA SHA IDs is arbitrary; any such COSEALG that would map to SHA-256 in
 * `mapCoseAlgToWebCryptoAlg()`
 *
 * SHA IDs referenced from here:
 *
 * https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf
 */
function attestedNameAlgToCOSEAlg(alg: string): COSEALG {
  if (alg === 'TPM_ALG_SHA256') {
    return COSEALG.ES256;
  } else if (alg === 'TPM_ALG_SHA384') {
    return COSEALG.ES384;
  } else if (alg === 'TPM_ALG_SHA512') {
    return COSEALG.ES512;
  }

  throw new Error(`Unexpected TPM attested name alg ${alg}`);
}

export async function verifyAttestationApple(
  options: AttestationFormatVerifierOpts,
): Promise<boolean> {
  const {
    attStmt,
    authData,
    clientDataHash,
    credentialPublicKey,
    rootCertificates,
  } = options;
  const x5c = attStmt.get('x5c');

  if (!x5c) {
    throw new Error(
      'No attestation certificate provided in attestation statement (Apple)',
    );
  }

  /**
   * Verify certificate path
   */
  try {
    await validateCertificatePath(
      x5c.map(convertCertBufferToPEM),
      rootCertificates,
    );
  } catch (err) {
    const _err = err as Error;
    throw new Error(`${_err.message} (Apple)`);
  }

  /**
   * Compare nonce in certificate extension to computed nonce
   */
  const parsedCredCert = AsnParser.parse(x5c[0], Certificate);
  const { extensions, subjectPublicKeyInfo } = parsedCredCert.tbsCertificate;

  if (!extensions) {
    throw new Error('credCert missing extensions (Apple)');
  }

  const extCertNonce = extensions.find((ext) => ext.extnID === '1.2.840.113635.100.8.2');

  if (!extCertNonce) {
    throw new Error(
      'credCert missing "1.2.840.113635.100.8.2" extension (Apple)',
    );
  }

  const nonceToHash = concat([authData, clientDataHash]);
  const nonce = await toHash(nonceToHash);
  /**
   * Ignore the first six ASN.1 structure bytes that define the nonce as an OCTET STRING. Should
   * trim off <Buffer 30 24 a1 22 04 20>
   *
   * TODO: Try and get @peculiar (GitHub) to add a schema for "1.2.840.113635.100.8.2" when we
   * find out where it's defined (doesn't seem to be publicly documented at the moment...)
   */
  const extNonce = new Uint8Array(extCertNonce.extnValue.buffer).slice(6);

  if (!areEqual(nonce, extNonce)) {
    throw new Error(`credCert nonce was not expected value (Apple)`);
  }

  /**
   * Verify credential public key matches the Subject Public Key of credCert
   */
  const credPubKeyPKCS = convertCOSEtoPKCS(credentialPublicKey);
  const credCertSubjectPublicKey = new Uint8Array(
    subjectPublicKeyInfo.subjectPublicKey,
  );

  if (!areEqual(credPubKeyPKCS, credCertSubjectPublicKey)) {
    throw new Error(
      'Credential public key does not equal credCert public key (Apple)',
    );
  }

  return true;
}
