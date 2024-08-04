import { isBase64URL, toBuffer, toUTF8String } from "@/lib/base64";
import { AuthenticationExtensionsAuthenticatorOutputs, Base64URLString, ClientDataJSON, COSEALG, COSEKEYS, COSEKTY, COSEPublicKey, CredentialDeviceType, ParsedAuthenticatorData, VerifiedAuthenticationResponse, VerifyAuthenticationResponseOpts } from "../types";
import { areEqual, concat, fromASCIIString, fromHex, fromUTF8String, toDataView } from "@/lib/uint";
import { decodeFirst, encode } from "@/lib/cbor";
import { digest, verify } from "@/lib/crypto";
import { AsnParser, Certificate, ECParameters, id_ecPublicKey, id_secp256r1, id_secp384r1, RSAPublicKey } from '@/lib/asn'
import { COSECRV } from "@/lib/crypto/types";
import { COSEPublicKeyEC2, COSEPublicKeyRSA } from "@/lib/cose/types";

/**
 * Make sense of Bits 3 and 4 in authenticator indicating:
 *
 * - Whether the credential can be used on multiple devices
 * - Whether the credential is backed up or not
 *
 * Invalid configurations will raise an `Error`
 */
 function parseBackupFlags({ be, bs }: { be: boolean; bs: boolean }): {
  credentialDeviceType: CredentialDeviceType;
  credentialBackedUp: boolean;
} {
  const credentialBackedUp = bs;
  let credentialDeviceType: CredentialDeviceType = 'singleDevice';

  if (be) {
    credentialDeviceType = 'multiDevice';
  }

  if (credentialDeviceType === 'singleDevice' && credentialBackedUp) {
    throw new InvalidBackupFlags(
      'Single-device credential indicated that it was backed up, which should be impossible.',
    );
  }

  return { credentialDeviceType, credentialBackedUp };
}

 class InvalidBackupFlags extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidBackupFlags';
  }
}

/**
 * Returns hash digest of the given data, using the given algorithm when provided. Defaults to using
 * SHA-256.
 */
 function toHash(
  data: Uint8Array | string,
  algorithm: COSEALG = -7,
): Promise<Uint8Array> {
  if (typeof data === 'string') {
    data = fromUTF8String(data);
  }

  const hash = digest(data, algorithm);

  return hash;
}

 async function matchExpectedRPID(
  rpIDHash: Uint8Array,
  expectedRPIDs: string[],
): Promise<string> {
  try {
    const matchedRPID = await Promise.any<string>(
      expectedRPIDs.map((expected) => {
        return new Promise((resolve, reject) => {
          toHash(fromASCIIString(expected)).then(
            (expectedRPIDHash) => {
              if (areEqual(rpIDHash, expectedRPIDHash)) {
                resolve(expected);
              } else {
                reject();
              }
            },
          );
        });
      }),
    );

    return matchedRPID;
  } catch (err) {
    const _err = err as Error;

    // This means no matches were found
    if (_err.name === 'AggregateError') {
      throw new UnexpectedRPIDHash();
    }

    // An unexpected error occurred
    throw err;
  }
}

class UnexpectedRPIDHash extends Error {
  constructor() {
    const message = 'Unexpected RP ID hash';
    super(message);
    this.name = 'UnexpectedRPIDHash';
  }
}

/**
 * CBOR-encoded extensions can be deeply-nested Maps, which are too deep for a simple
 * `Object.entries()`. This method will recursively make sure that all Maps are converted into
 * basic objects.
 */
function convertMapToObjectDeep(
  input: Map<string, unknown>,
): { [key: string]: unknown } {
  const mapped: { [key: string]: unknown } = {};

  for (const [key, value] of input) {
    if (value instanceof Map) {
      mapped[key] = convertMapToObjectDeep(value);
    } else {
      mapped[key] = value;
    }
  }

  return mapped;
}

/**
 * Convert authenticator extension data buffer to a proper object
 *
 * @param extensionData Authenticator Extension Data buffer
 */
 function decodeAuthenticatorExtensions(
  extensionData: Uint8Array,
): AuthenticationExtensionsAuthenticatorOutputs | undefined {
  let toCBOR: Map<string, unknown>;
  try {
    toCBOR = decodeFirst(extensionData);
  } catch (err) {
    const _err = err as Error;
    throw new Error(`Error decoding authenticator extensions: ${_err.message}`);
  }

  return convertMapToObjectDeep(toCBOR);
}

/**
 * Decode an authenticator's base64url-encoded clientDataJSON to JSON
 */
 function decodeClientDataJSON(data: Base64URLString): ClientDataJSON {
  const toString = toUTF8String(data);
  const clientData: ClientDataJSON = JSON.parse(toString);

  return clientData;
}

/**
 * Make sense of the authData buffer contained in an Attestation
 */
 function parseAuthenticatorData(
  authData: Uint8Array,
): ParsedAuthenticatorData {
  if (authData.byteLength < 37) {
    throw new Error(
      `Authenticator data was ${authData.byteLength} bytes, expected at least 37 bytes`,
    );
  }

  let pointer = 0;
  const dataView = toDataView(authData);

  const rpIdHash = authData.slice(pointer, pointer += 32);

  const flagsBuf = authData.slice(pointer, pointer += 1);
  const flagsInt = flagsBuf[0];

  // Bit positions can be referenced here:
  // https://www.w3.org/TR/webauthn-2/#flags
  const flags = {
    up: !!(flagsInt & (1 << 0)), // User Presence
    uv: !!(flagsInt & (1 << 2)), // User Verified
    be: !!(flagsInt & (1 << 3)), // Backup Eligibility
    bs: !!(flagsInt & (1 << 4)), // Backup State
    at: !!(flagsInt & (1 << 6)), // Attested Credential Data Present
    ed: !!(flagsInt & (1 << 7)), // Extension Data Present
    flagsInt,
  };

  const counterBuf = authData.slice(pointer, pointer + 4);
  const counter = dataView.getUint32(pointer, false);
  pointer += 4;

  let aaguid: Uint8Array | undefined = undefined;
  let credentialID: Uint8Array | undefined = undefined;
  let credentialPublicKey: Uint8Array | undefined = undefined;

  if (flags.at) {
    aaguid = authData.slice(pointer, pointer += 16);

    const credIDLen = dataView.getUint16(pointer);
    pointer += 2;

    credentialID = authData.slice(pointer, pointer += credIDLen);

    /**
     * Firefox 117 incorrectly CBOR-encodes authData when EdDSA (-8) is used for the public key.
     * A CBOR "Map of 3 items" (0xa3) should be "Map of 4 items" (0xa4), and if we manually adjust
     * the single byte there's a good chance the authData can be correctly parsed.
     *
     * This browser release also incorrectly uses the string labels "OKP" and "Ed25519" instead of
     * their integer representations for kty and crv respectively. That's why the COSE public key
     * in the hex below looks so odd.
     */
    // Bytes decode to `{ 1: "OKP", 3: -8, -1: "Ed25519" }` (it's missing key -2 a.k.a. COSEKEYS.x)
    const badEdDSACBOR = fromHex('a301634f4b500327206745643235353139');
    const bytesAtCurrentPosition = authData.slice(pointer, pointer + badEdDSACBOR.byteLength);
    let foundBadCBOR = false;
    if (areEqual(badEdDSACBOR, bytesAtCurrentPosition)) {
      // Change the bad CBOR 0xa3 to 0xa4 so that the credential public key can be recognized
      foundBadCBOR = true;
      authData[pointer] = 0xa4;
    }

    // Decode the next CBOR item in the buffer, then re-encode it back to a Buffer
    const firstDecoded = decodeFirst<COSEPublicKey>(
      authData.slice(pointer),
    );
    const firstEncoded = Uint8Array.from(
      /**
       * Casting to `Map` via `as unknown` here because TS doesn't make it possible to define Maps
       * with discrete keys and properties with known types per pair, and CBOR libs typically parse
       * CBOR Major Type 5 to `Map` because you can have numbers for keys. A `COSEPublicKey` can be
       * generalized as "a Map with numbers for keys and either numbers or bytes for values" though.
       * If this presumption falls apart then other parts of verification later on will fail so we
       * should be safe doing this here.
       */
      encode(firstDecoded as unknown as Map<number, number | Uint8Array>),
    );

    if (foundBadCBOR) {
      // Restore the bit we changed so that `authData` is the same as it came in and won't break
      // signature verification.
      authData[pointer] = 0xa3;
    }

    credentialPublicKey = firstEncoded;
    pointer += firstEncoded.byteLength;
  }

  let extensionsData: AuthenticationExtensionsAuthenticatorOutputs | undefined = undefined;
  let extensionsDataBuffer: Uint8Array | undefined = undefined;

  if (flags.ed) {
    /**
     * Typing here feels a little sloppy but we're immediately CBOR-encoding this back to bytes to
     * more diligently parse via `decodeAuthenticatorExtensions()` so :shrug:
     */
    type AuthenticatorExtensionData = Map<string, Uint8Array>;
    const firstDecoded = decodeFirst<AuthenticatorExtensionData>(authData.slice(pointer));
    extensionsDataBuffer = Uint8Array.from(encode(firstDecoded));
    extensionsData = decodeAuthenticatorExtensions(extensionsDataBuffer);
    pointer += extensionsDataBuffer.byteLength;
  }

  // Pointer should be at the end of the authenticator data, otherwise too much data was sent
  if (authData.byteLength > pointer) {
    throw new Error('Leftover bytes detected while parsing authenticator data');
  }

  return {
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
    aaguid,
    credentialID,
    credentialPublicKey,
    extensionsData,
    extensionsDataBuffer,
  };
}

 function decodeCredentialPublicKey(
  publicKey: Uint8Array,
): COSEPublicKey {
  return decodeFirst<COSEPublicKey>(publicKey);
}

/**
 * Map X.509 signature algorithm OIDs to COSE algorithm IDs
 *
 * - EC2 OIDs: https://oidref.com/1.2.840.10045.4.3
 * - RSA OIDs: https://oidref.com/1.2.840.113549.1.1
 */
 function mapX509SignatureAlgToCOSEAlg(
  signatureAlgorithm: string,
): COSEALG {
  let alg: COSEALG;

  if (signatureAlgorithm === '1.2.840.10045.4.3.2') {
    alg = COSEALG.ES256;
  } else if (signatureAlgorithm === '1.2.840.10045.4.3.3') {
    alg = COSEALG.ES384;
  } else if (signatureAlgorithm === '1.2.840.10045.4.3.4') {
    alg = COSEALG.ES512;
  } else if (signatureAlgorithm === '1.2.840.113549.1.1.11') {
    alg = COSEALG.RS256;
  } else if (signatureAlgorithm === '1.2.840.113549.1.1.12') {
    alg = COSEALG.RS384;
  } else if (signatureAlgorithm === '1.2.840.113549.1.1.13') {
    alg = COSEALG.RS512;
  } else if (signatureAlgorithm === '1.2.840.113549.1.1.5') {
    alg = COSEALG.RS1;
  } else {
    throw new Error(
      `Unable to map X.509 signature algorithm ${signatureAlgorithm} to a COSE algorithm`,
    );
  }

  return alg;
}

function convertX509PublicKeyToCOSE(
  x509Certificate: Uint8Array,
): COSEPublicKey {
  let cosePublicKey: COSEPublicKey = new Map();

  /**
   * Time to extract the public key from an X.509 certificate
   */
  const x509 = AsnParser.parse(x509Certificate, Certificate);

  const { tbsCertificate } = x509;
  const { subjectPublicKeyInfo, signature: _tbsSignature } = tbsCertificate;

  const signatureAlgorithm = _tbsSignature.algorithm;
  const publicKeyAlgorithmID = subjectPublicKeyInfo.algorithm.algorithm;

  if (publicKeyAlgorithmID === id_ecPublicKey) {
    /**
     * EC2 Public Key
     */
    if (!subjectPublicKeyInfo.algorithm.parameters) {
      throw new Error('Certificate public key was missing parameters (EC2)');
    }

    const ecParameters = AsnParser.parse(
      new Uint8Array(subjectPublicKeyInfo.algorithm.parameters),
      ECParameters,
    );

    let crv = -999;
    const { namedCurve } = ecParameters;

    if (namedCurve === id_secp256r1) {
      crv = COSECRV.P256;
    } else if (namedCurve === id_secp384r1) {
      crv = COSECRV.P384;
    } else {
      throw new Error(
        `Certificate public key contained unexpected namedCurve ${namedCurve} (EC2)`,
      );
    }

    const subjectPublicKey = new Uint8Array(
      subjectPublicKeyInfo.subjectPublicKey,
    );

    let x: Uint8Array;
    let y: Uint8Array;
    if (subjectPublicKey[0] === 0x04) {
      // Public key is in "uncompressed form", so we can split the remaining bytes in half
      let pointer = 1;
      const halfLength = (subjectPublicKey.length - 1) / 2;
      x = subjectPublicKey.slice(pointer, pointer += halfLength);
      y = subjectPublicKey.slice(pointer);
    } else {
      throw new Error(
        'TODO: Figure out how to handle public keys in "compressed form"',
      );
    }

    const coseEC2PubKey: COSEPublicKeyEC2 = new Map();
    coseEC2PubKey.set(COSEKEYS.kty, COSEKTY.EC2);
    coseEC2PubKey.set(
      COSEKEYS.alg,
      mapX509SignatureAlgToCOSEAlg(signatureAlgorithm),
    );
    coseEC2PubKey.set(COSEKEYS.crv, crv);
    coseEC2PubKey.set(COSEKEYS.x, x);
    coseEC2PubKey.set(COSEKEYS.y, y);

    cosePublicKey = coseEC2PubKey;
  } else if (publicKeyAlgorithmID === '1.2.840.113549.1.1.1') {
    /**
     * RSA public key
     */
    const rsaPublicKey = AsnParser.parse(
      subjectPublicKeyInfo.subjectPublicKey,
      RSAPublicKey,
    );

    const coseRSAPubKey: COSEPublicKeyRSA = new Map();
    coseRSAPubKey.set(COSEKEYS.kty, COSEKTY.RSA);
    coseRSAPubKey.set(
      COSEKEYS.alg,
      mapX509SignatureAlgToCOSEAlg(signatureAlgorithm),
    );
    coseRSAPubKey.set(COSEKEYS.n, new Uint8Array(rsaPublicKey.modulus));
    coseRSAPubKey.set(COSEKEYS.e, new Uint8Array(rsaPublicKey.publicExponent));

    cosePublicKey = coseRSAPubKey;
  } else {
    throw new Error(
      `Certificate public key contained unexpected algorithm ID ${publicKeyAlgorithmID}`,
    );
  }

  return cosePublicKey;
}

/**
 * Verify an authenticator's signature
 */
 function verifySignature(opts: {
  signature: Uint8Array;
  data: Uint8Array;
  credentialPublicKey?: Uint8Array;
  x509Certificate?: Uint8Array;
  hashAlgorithm?: COSEALG;
}): Promise<boolean> {
  const {
    signature,
    data,
    credentialPublicKey,
    x509Certificate,
    hashAlgorithm,
  } = opts;

  if (!x509Certificate && !credentialPublicKey) {
    throw new Error('Must declare either "leafCert" or "credentialPublicKey"');
  }

  if (x509Certificate && credentialPublicKey) {
    throw new Error(
      'Must not declare both "leafCert" and "credentialPublicKey"',
    );
  }

  let cosePublicKey: COSEPublicKey = new Map();

  if (credentialPublicKey) {
    cosePublicKey = decodeCredentialPublicKey(credentialPublicKey);
  } else if (x509Certificate) {
    cosePublicKey = convertX509PublicKeyToCOSE(x509Certificate);
  }

  return verify({
    cosePublicKey,
    signature,
    data,
    shaHashOverride: hashAlgorithm,
  });
}

/**
 * Verify that the user has legitimately completed the authentication process
 *
 * **Options:**
 *
 * @param response - Response returned by **@simplewebauthn/browser**'s `startAssertion()`
 * @param expectedChallenge - The base64url-encoded `options.challenge` returned by `generateAuthenticationOptions()`
 * @param expectedOrigin - Website URL (or array of URLs) that the registration should have occurred on
 * @param expectedRPID - RP ID (or array of IDs) that was specified in the registration options
 * @param authenticator - An internal {@link AuthenticatorDevice} matching the credential's ID
 * @param expectedType **(Optional)** - The response type expected ('webauthn.get')
 * @param requireUserVerification **(Optional)** - Enforce user verification by the authenticator (via PIN, fingerprint, etc...) Defaults to `true`
 * @param advancedFIDOConfig **(Optional)** - Options for satisfying more stringent FIDO RP feature requirements
 * @param advancedFIDOConfig.userVerification **(Optional)** - Enable alternative rules for evaluating the User Presence and User Verified flags in authenticator data: UV (and UP) flags are optional unless this value is `"required"`
 */
export async function verifyAuthenticationResponse(
  options: VerifyAuthenticationResponseOpts,
): Promise<VerifiedAuthenticationResponse> {
  const {
    response,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    expectedType,
    authenticator,
    requireUserVerification = true,
    advancedFIDOConfig,
  } = options;
  const { id, rawId, type: credentialType, response: assertionResponse } = response;

  // Ensure credential specified an ID
  if (!id) {
    throw new Error('Missing credential ID');
  }

  // Ensure ID is base64url-encoded
  if (id !== rawId) {
    throw new Error('Credential ID was not base64url-encoded');
  }

  // Make sure credential type is public-key
  if (credentialType !== 'public-key') {
    throw new Error(
      `Unexpected credential type ${credentialType}, expected "public-key"`,
    );
  }

  if (!response) {
    throw new Error('Credential missing response');
  }

  if (typeof assertionResponse?.clientDataJSON !== 'string') {
    throw new Error('Credential response clientDataJSON was not a string');
  }

  const clientDataJSON = decodeClientDataJSON(assertionResponse.clientDataJSON);

  const { type, origin, challenge, tokenBinding } = clientDataJSON;

  // Make sure we're handling an authentication
  if (Array.isArray(expectedType)) {
    if (!expectedType.includes(type)) {
      const joinedExpectedType = expectedType.join(', ');
      throw new Error(
        `Unexpected authentication response type "${type}", expected one of: ${joinedExpectedType}`,
      );
    }
  } else if (expectedType) {
    if (type !== expectedType) {
      throw new Error(
        `Unexpected authentication response type "${type}", expected "${expectedType}"`,
      );
    }
  } else if (type !== 'webauthn.get') {
    throw new Error(`Unexpected authentication response type: ${type}`);
  }

  // Ensure the device provided the challenge we gave it
  if (typeof expectedChallenge === 'function') {
    if (!(await expectedChallenge(challenge))) {
      throw new Error(
        `Custom challenge verifier returned false for registration response challenge "${challenge}"`,
      );
    }
  } else if (challenge !== expectedChallenge) {
    throw new Error(
      `Unexpected authentication response challenge "${challenge}", expected "${expectedChallenge}"`,
    );
  }

  // Check that the origin is our site
  if (Array.isArray(expectedOrigin)) {
    if (!expectedOrigin.includes(origin)) {
      const joinedExpectedOrigin = expectedOrigin.join(', ');
      throw new Error(
        `Unexpected authentication response origin "${origin}", expected one of: ${joinedExpectedOrigin}`,
      );
    }
  } else {
    if (origin !== expectedOrigin) {
      throw new Error(
        `Unexpected authentication response origin "${origin}", expected "${expectedOrigin}"`,
      );
    }
  }

  if (!isBase64URL(assertionResponse.authenticatorData)) {
    throw new Error(
      'Credential response authenticatorData was not a base64url string',
    );
  }

  if (!isBase64URL(assertionResponse.signature)) {
    throw new Error('Credential response signature was not a base64url string');
  }

  if (
    assertionResponse.userHandle &&
    typeof assertionResponse.userHandle !== 'string'
  ) {
    throw new Error('Credential response userHandle was not a string');
  }

  if (tokenBinding) {
    if (typeof tokenBinding !== 'object') {
      throw new Error('ClientDataJSON tokenBinding was not an object');
    }

    if (
      ['present', 'supported', 'notSupported'].indexOf(tokenBinding.status) < 0
    ) {
      throw new Error(`Unexpected tokenBinding status ${tokenBinding.status}`);
    }
  }

  const authDataBuffer = toBuffer(
    assertionResponse.authenticatorData,
  );
  const parsedAuthData = parseAuthenticatorData(authDataBuffer);
  const { rpIdHash, flags, counter, extensionsData } = parsedAuthData;

  // Make sure the response's RP ID is ours
  let expectedRPIDs: string[] = [];
  if (typeof expectedRPID === 'string') {
    expectedRPIDs = [expectedRPID];
  } else {
    expectedRPIDs = expectedRPID;
  }

  const matchedRPID = await matchExpectedRPID(rpIdHash, expectedRPIDs);

  if (advancedFIDOConfig !== undefined) {
    const { userVerification: fidoUserVerification } = advancedFIDOConfig;

    /**
     * Use FIDO Conformance-defined rules for verifying UP and UV flags
     */
    if (fidoUserVerification === 'required') {
      // Require `flags.uv` be true (implies `flags.up` is true)
      if (!flags.uv) {
        throw new Error(
          'User verification required, but user could not be verified',
        );
      }
    } else if (
      fidoUserVerification === 'preferred' ||
      fidoUserVerification === 'discouraged'
    ) {
      // Ignore `flags.uv`
    }
  } else {
    /**
     * Use WebAuthn spec-defined rules for verifying UP and UV flags
     */
    // WebAuthn only requires the user presence flag be true
    if (!flags.up) {
      throw new Error('User not present during authentication');
    }

    // Enforce user verification if required
    if (requireUserVerification && !flags.uv) {
      throw new Error(
        'User verification required, but user could not be verified',
      );
    }
  }

  const clientDataHash = await toHash(
    toBuffer(assertionResponse.clientDataJSON),
  );
  const signatureBase = concat([authDataBuffer, clientDataHash]);

  const signature = toBuffer(assertionResponse.signature);

  if (
    (counter > 0 || authenticator.counter > 0) &&
    counter <= authenticator.counter
  ) {
    // Error out when the counter in the DB is greater than or equal to the counter in the
    // dataStruct. It's related to how the authenticator maintains the number of times its been
    // used for this client. If this happens, then someone's somehow increased the counter
    // on the device without going through this site
    throw new Error(
      `Response counter value ${counter} was lower than expected ${authenticator.counter}`,
    );
  }

  const { credentialDeviceType, credentialBackedUp } = parseBackupFlags(flags);

  const toReturn: VerifiedAuthenticationResponse = {
    verified: await verifySignature({
      signature,
      data: signatureBase,
      credentialPublicKey: authenticator.credentialPublicKey,
    }),
    authenticationInfo: {
      newCounter: counter,
      credentialID: authenticator.credentialID,
      userVerified: flags.uv,
      credentialDeviceType,
      credentialBackedUp,
      authenticatorExtensionResults: extensionsData,
      origin: clientDataJSON.origin,
      rpID: matchedRPID,
    },
  };

  return toReturn;
}
