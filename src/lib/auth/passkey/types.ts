import { Certificate } from "@/lib/asn";

/**
 * Available only in secure contexts.
 *
 * [MDN Reference](https://developer.mozilla.org/docs/Web/API/AuthenticatorAssertionResponse)
 */
export interface AuthenticatorAssertionResponse extends AuthenticatorResponse {
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/AuthenticatorAssertionResponse/authenticatorData) */
  readonly authenticatorData: ArrayBuffer;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/AuthenticatorAssertionResponse/signature) */
  readonly signature: ArrayBuffer;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/AuthenticatorAssertionResponse/userHandle) */
  readonly userHandle: ArrayBuffer | null;
}

/**
 * Available only in secure contexts.
 *
 * [MDN Reference](https://developer.mozilla.org/docs/Web/API/AuthenticatorAttestationResponse)
 */
export interface AuthenticatorAttestationResponse
  extends AuthenticatorResponse {
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/AuthenticatorAttestationResponse/attestationObject) */
  readonly attestationObject: ArrayBuffer;
  getAuthenticatorData(): ArrayBuffer;
  getPublicKey(): ArrayBuffer | null;
  getPublicKeyAlgorithm(): COSEAlgorithmIdentifier;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/AuthenticatorAttestationResponse/getTransports) */
  getTransports(): string[];
}

export interface AuthenticationExtensionsClientInputs {
  appid?: string;
  credProps?: boolean;
  hmacCreateSecret?: boolean;
}

export interface AuthenticationExtensionsClientOutputs {
  appid?: boolean;
  credProps?: CredentialPropertiesOutput;
  hmacCreateSecret?: boolean;
}

export interface AuthenticatorSelectionCriteria {
  authenticatorAttachment?: AuthenticatorAttachment;
  requireResidentKey?: boolean;
  residentKey?: ResidentKeyRequirement;
  userVerification?: UserVerificationRequirement;
}

/**
 * Basic cryptography features available in the current context. It allows access to a cryptographically strong random number generator and to cryptographic primitives.
 *
 * [MDN Reference](https://developer.mozilla.org/docs/Web/API/Crypto)
 */
export interface Crypto {
  /**
   * Available only in secure contexts.
   *
   * [MDN Reference](https://developer.mozilla.org/docs/Web/API/Crypto/subtle)
   */
  readonly subtle: SubtleCrypto;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/Crypto/getRandomValues) */
  getRandomValues<T extends ArrayBufferView | null>(array: T): T;
  /**
   * Available only in secure contexts.
   *
   * [MDN Reference](https://developer.mozilla.org/docs/Web/API/Crypto/randomUUID)
   */
  randomUUID(): `${string}-${string}-${string}-${string}-${string}`;
}

/**
 * Available only in secure contexts.
 *
 * [MDN Reference](https://developer.mozilla.org/docs/Web/API/PublicKeyCredential)
 */
export interface PublicKeyCredential extends Credential {
  readonly authenticatorAttachment: string | null;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/PublicKeyCredential/rawId) */
  readonly rawId: ArrayBuffer;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/PublicKeyCredential/response) */
  readonly response: AuthenticatorResponse;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/PublicKeyCredential/getClientExtensionResults) */
  getClientExtensionResults(): AuthenticationExtensionsClientOutputs;
}

export interface PublicKeyCredentialCreationOptions {
  attestation?: AttestationConveyancePreference;
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  challenge: BufferSource;
  excludeCredentials?: PublicKeyCredentialDescriptor[];
  extensions?: AuthenticationExtensionsClientInputs;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  rp: PublicKeyCredentialRpEntity;
  timeout?: number;
  user: PublicKeyCredentialUserEntity;
}

export interface PublicKeyCredentialDescriptor {
  id: BufferSource;
  transports?: AuthenticatorTransport[];
  type: PublicKeyCredentialType;
}

export interface PublicKeyCredentialParameters {
  alg: COSEAlgorithmIdentifier;
  type: PublicKeyCredentialType;
}

export interface PublicKeyCredentialRequestOptions {
  allowCredentials?: PublicKeyCredentialDescriptor[];
  challenge: BufferSource;
  extensions?: AuthenticationExtensionsClientInputs;
  rpId?: string;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
}

export interface PublicKeyCredentialUserEntity
  extends PublicKeyCredentialEntity {
  displayName: string;
  id: BufferSource;
}

/**
 * Available only in secure contexts.
 *
 * [MDN Reference](https://developer.mozilla.org/docs/Web/API/AuthenticatorResponse)
 */
export interface AuthenticatorResponse {
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/AuthenticatorResponse/clientDataJSON) */
  readonly clientDataJSON: ArrayBuffer;
}

export interface CredentialPropertiesOutput {
  rk?: boolean;
}

/**
 * This Web Crypto API interface provides a number of low-level cryptographic functions. It is accessed via the Crypto.subtle properties available in a window context (via Window.crypto).
 * Available only in secure contexts.
 *
 * [MDN Reference](https://developer.mozilla.org/docs/Web/API/SubtleCrypto)
 */
export interface SubtleCrypto {
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/decrypt) */
  decrypt(
    algorithm:
      | AlgorithmIdentifier
      | RsaOaepParams
      | AesCtrParams
      | AesCbcParams
      | AesGcmParams,
    key: CryptoKey,
    data: BufferSource,
  ): Promise<ArrayBuffer>;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/deriveBits) */
  deriveBits(
    algorithm:
      | AlgorithmIdentifier
      | EcdhKeyDeriveParams
      | HkdfParams
      | Pbkdf2Params,
    baseKey: CryptoKey,
    length: number,
  ): Promise<ArrayBuffer>;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/deriveKey) */
  deriveKey(
    algorithm:
      | AlgorithmIdentifier
      | EcdhKeyDeriveParams
      | HkdfParams
      | Pbkdf2Params,
    baseKey: CryptoKey,
    derivedKeyType:
      | AlgorithmIdentifier
      | AesDerivedKeyParams
      | HmacImportParams
      | HkdfParams
      | Pbkdf2Params,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey>;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/digest) */
  digest(
    algorithm: AlgorithmIdentifier,
    data: BufferSource,
  ): Promise<ArrayBuffer>;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/encrypt) */
  encrypt(
    algorithm:
      | AlgorithmIdentifier
      | RsaOaepParams
      | AesCtrParams
      | AesCbcParams
      | AesGcmParams,
    key: CryptoKey,
    data: BufferSource,
  ): Promise<ArrayBuffer>;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/exportKey) */
  exportKey(format: 'jwk', key: CryptoKey): Promise<JsonWebKey>;
  exportKey(
    format: Exclude<KeyFormat, 'jwk'>,
    key: CryptoKey,
  ): Promise<ArrayBuffer>;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/generateKey) */
  generateKey(
    algorithm: RsaHashedKeyGenParams | EcKeyGenParams,
    extractable: boolean,
    keyUsages: ReadonlyArray<KeyUsage>,
  ): Promise<CryptoKeyPair>;
  generateKey(
    algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params,
    extractable: boolean,
    keyUsages: ReadonlyArray<KeyUsage>,
  ): Promise<CryptoKey>;
  generateKey(
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKeyPair | CryptoKey>;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/importKey) */
  importKey(
    format: 'jwk',
    keyData: JsonWebKey,
    algorithm:
      | AlgorithmIdentifier
      | RsaHashedImportParams
      | EcKeyImportParams
      | HmacImportParams
      | AesKeyAlgorithm,
    extractable: boolean,
    keyUsages: ReadonlyArray<KeyUsage>,
  ): Promise<CryptoKey>;
  importKey(
    format: Exclude<KeyFormat, 'jwk'>,
    keyData: BufferSource,
    algorithm:
      | AlgorithmIdentifier
      | RsaHashedImportParams
      | EcKeyImportParams
      | HmacImportParams
      | AesKeyAlgorithm,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey>;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/sign) */
  sign(
    algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams,
    key: CryptoKey,
    data: BufferSource,
  ): Promise<ArrayBuffer>;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/unwrapKey) */
  unwrapKey(
    format: KeyFormat,
    wrappedKey: BufferSource,
    unwrappingKey: CryptoKey,
    unwrapAlgorithm:
      | AlgorithmIdentifier
      | RsaOaepParams
      | AesCtrParams
      | AesCbcParams
      | AesGcmParams,
    unwrappedKeyAlgorithm:
      | AlgorithmIdentifier
      | RsaHashedImportParams
      | EcKeyImportParams
      | HmacImportParams
      | AesKeyAlgorithm,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey>;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/verify) */
  verify(
    algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams,
    key: CryptoKey,
    signature: BufferSource,
    data: BufferSource,
  ): Promise<boolean>;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/wrapKey) */
  wrapKey(
    format: KeyFormat,
    key: CryptoKey,
    wrappingKey: CryptoKey,
    wrapAlgorithm:
      | AlgorithmIdentifier
      | RsaOaepParams
      | AesCtrParams
      | AesCbcParams
      | AesGcmParams,
  ): Promise<ArrayBuffer>;
}

/**
 * Available only in secure contexts.
 *
 * [MDN Reference](https://developer.mozilla.org/docs/Web/API/Credential)
 */
export interface Credential {
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/Credential/id) */
  readonly id: string;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/Credential/type) */
  readonly type: string;
}

export interface PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {
  id?: string;
}

export interface PublicKeyCredentialEntity {
  name: string;
}

export interface RsaOaepParams extends Algorithm {
  label?: BufferSource;
}

export interface AesCtrParams extends Algorithm {
  counter: BufferSource;
  length: number;
}

export interface AesCbcParams extends Algorithm {
  iv: BufferSource;
}

export interface AesGcmParams extends Algorithm {
  additionalData?: BufferSource;
  iv: BufferSource;
  tagLength?: number;
}

/**
 * The CryptoKey dictionary of the Web Crypto API represents a cryptographic key.
 * Available only in secure contexts.
 *
 * [MDN Reference](https://developer.mozilla.org/docs/Web/API/CryptoKey)
 */
export interface CryptoKey {
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/CryptoKey/algorithm) */
  readonly algorithm: KeyAlgorithm;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/CryptoKey/extractable) */
  readonly extractable: boolean;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/CryptoKey/type) */
  readonly type: KeyType;
  /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/CryptoKey/usages) */
  readonly usages: KeyUsage[];
}

export interface EcdhKeyDeriveParams extends Algorithm {
  public: CryptoKey;
}

export interface HkdfParams extends Algorithm {
  hash: HashAlgorithmIdentifier;
  info: BufferSource;
  salt: BufferSource;
}

export interface Pbkdf2Params extends Algorithm {
  hash: HashAlgorithmIdentifier;
  iterations: number;
  salt: BufferSource;
}

export interface AesDerivedKeyParams extends Algorithm {
  length: number;
}

export interface HmacImportParams extends Algorithm {
  hash: HashAlgorithmIdentifier;
  length?: number;
}

export interface JsonWebKey {
  alg?: string;
  crv?: string;
  d?: string;
  dp?: string;
  dq?: string;
  e?: string;
  ext?: boolean;
  k?: string;
  key_ops?: string[];
  kty?: string;
  n?: string;
  oth?: RsaOtherPrimesInfo[];
  p?: string;
  q?: string;
  qi?: string;
  use?: string;
  x?: string;
  y?: string;
}

export interface RsaHashedKeyGenParams extends RsaKeyGenParams {
  hash: HashAlgorithmIdentifier;
}

export interface EcKeyGenParams extends Algorithm {
  namedCurve: NamedCurve;
}

export interface CryptoKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

export interface AesKeyGenParams extends Algorithm {
  length: number;
}

export interface HmacKeyGenParams extends Algorithm {
  hash: HashAlgorithmIdentifier;
  length?: number;
}

export interface RsaHashedImportParams extends Algorithm {
  hash: HashAlgorithmIdentifier;
}

export interface EcKeyImportParams extends Algorithm {
  namedCurve: NamedCurve;
}

export interface AesKeyAlgorithm extends KeyAlgorithm {
  length: number;
}

export interface RsaPssParams extends Algorithm {
  saltLength: number;
}

export interface EcdsaParams extends Algorithm {
  hash: HashAlgorithmIdentifier;
}

export interface Algorithm {
  name: string;
}

export interface KeyAlgorithm {
  name: string;
}

export interface RsaOtherPrimesInfo {
  d?: string;
  r?: string;
  t?: string;
}

export interface RsaKeyGenParams extends Algorithm {
  modulusLength: number;
  publicExponent: BigInteger;
}

export type AttestationConveyancePreference =
  | 'direct'
  | 'enterprise'
  | 'indirect'
  | 'none';
export type AuthenticatorTransport =
  | 'ble'
  | 'hybrid'
  | 'internal'
  | 'nfc'
  | 'usb';
export type COSEAlgorithmIdentifier = number;
export type UserVerificationRequirement =
  | 'discouraged'
  | 'preferred'
  | 'required';
export type AuthenticatorAttachment = 'cross-platform' | 'platform';
export type ResidentKeyRequirement = 'discouraged' | 'preferred' | 'required';
export type BufferSource = ArrayBufferView | ArrayBuffer;
export type PublicKeyCredentialType = 'public-key';
export type AlgorithmIdentifier = Algorithm | string;
export type KeyUsage =
  | 'decrypt'
  | 'deriveBits'
  | 'deriveKey'
  | 'encrypt'
  | 'sign'
  | 'unwrapKey'
  | 'verify'
  | 'wrapKey';
export type KeyFormat = 'jwk' | 'pkcs8' | 'raw' | 'spki';
export type KeyType = 'private' | 'public' | 'secret';
export type HashAlgorithmIdentifier = AlgorithmIdentifier;
export type NamedCurve = string;
export type BigInteger = Uint8Array;

export interface PublicKeyCredentialCreationOptionsJSON {
  rp: PublicKeyCredentialRpEntity;
  user: PublicKeyCredentialUserEntityJSON;
  challenge: Base64URLString;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: PublicKeyCredentialDescriptorJSON[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
  extensions?: AuthenticationExtensionsClientInputs;
}

/**
 * A variant of PublicKeyCredentialRequestOptions suitable for JSON transmission to the browser to
 * (eventually) get passed into navigator.credentials.get(...) in the browser.
 */
export interface PublicKeyCredentialRequestOptionsJSON {
  challenge: Base64URLString;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PublicKeyCredentialDescriptorJSON[];
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
}

/**
 * https://w3c.github.io/webauthn/#dictdef-publickeycredentialdescriptorjson
 */
export interface PublicKeyCredentialDescriptorJSON {
  id: Base64URLString;
  type: PublicKeyCredentialType;
  transports?: AuthenticatorTransportFuture[];
}

/**
 * https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentityjson
 */
export interface PublicKeyCredentialUserEntityJSON {
  id: string;
  name: string;
  displayName: string;
}

/**
 * The value returned from navigator.credentials.create()
 */
export interface RegistrationCredential extends PublicKeyCredentialFuture {
  response: AuthenticatorAttestationResponseFuture;
}

/**
 * A slightly-modified RegistrationCredential to simplify working with ArrayBuffers that
 * are Base64URL-encoded in the browser so that they can be sent as JSON to the server.
 *
 * https://w3c.github.io/webauthn/#dictdef-registrationresponsejson
 */
export interface RegistrationResponseJSON {
  id: Base64URLString;
  rawId: Base64URLString;
  response: AuthenticatorAttestationResponseJSON;
  authenticatorAttachment?: AuthenticatorAttachment;
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
  type: PublicKeyCredentialType;
}

/**
 * The value returned from navigator.credentials.get()
 */
export interface AuthenticationCredential extends PublicKeyCredentialFuture {
  response: AuthenticatorAssertionResponse;
}

/**
 * A slightly-modified AuthenticationCredential to simplify working with ArrayBuffers that
 * are Base64URL-encoded in the browser so that they can be sent as JSON to the server.
 *
 * https://w3c.github.io/webauthn/#dictdef-authenticationresponsejson
 */
export interface AuthenticationResponseJSON {
  id: Base64URLString;
  rawId: Base64URLString;
  response: AuthenticatorAssertionResponseJSON;
  authenticatorAttachment?: AuthenticatorAttachment;
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
  type: PublicKeyCredentialType;
}

/**
 * A slightly-modified AuthenticatorAttestationResponse to simplify working with ArrayBuffers that
 * are Base64URL-encoded in the browser so that they can be sent as JSON to the server.
 *
 * https://w3c.github.io/webauthn/#dictdef-authenticatorattestationresponsejson
 */
export interface AuthenticatorAttestationResponseJSON {
  clientDataJSON: Base64URLString;
  attestationObject: Base64URLString;
  // Optional in L2, but becomes required in L3. Play it safe until L3 becomes Recommendation
  authenticatorData?: Base64URLString;
  // Optional in L2, but becomes required in L3. Play it safe until L3 becomes Recommendation
  transports?: AuthenticatorTransportFuture[];
  // Optional in L2, but becomes required in L3. Play it safe until L3 becomes Recommendation
  publicKeyAlgorithm?: COSEAlgorithmIdentifier;
  publicKey?: Base64URLString;
}

/**
 * A slightly-modified AuthenticatorAssertionResponse to simplify working with ArrayBuffers that
 * are Base64URL-encoded in the browser so that they can be sent as JSON to the server.
 *
 * https://w3c.github.io/webauthn/#dictdef-authenticatorassertionresponsejson
 */
export interface AuthenticatorAssertionResponseJSON {
  clientDataJSON: Base64URLString;
  authenticatorData: Base64URLString;
  signature: Base64URLString;
  userHandle?: Base64URLString;
}

/**
 * A WebAuthn-compatible device and the information needed to verify assertions by it
 */
export type AuthenticatorDevice = {
  credentialID: Base64URLString;
  credentialPublicKey: Uint8Array;
  // Number of times this authenticator is expected to have been used
  counter: number;
  // From browser's `startRegistration()` -> RegistrationCredentialJSON.transports (API L2 and up)
  transports?: AuthenticatorTransportFuture[];
};

/**
 * An attempt to communicate that this isn't just any string, but a Base64URL-encoded string
 */
export type Base64URLString = string;

/**
 * AuthenticatorAttestationResponse in TypeScript's DOM lib is outdated (up through v3.9.7).
 * Maintain an augmented version here so we can implement additional properties as the WebAuthn
 * spec evolves.
 *
 * See https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse
 *
 * Properties marked optional are not supported in all browsers.
 */
export interface AuthenticatorAttestationResponseFuture
  extends AuthenticatorAttestationResponse {
  getTransports(): AuthenticatorTransportFuture[];
}

/**
 * A super class of TypeScript's `AuthenticatorTransport` that includes support for the latest
 * transports. Should eventually be replaced by TypeScript's when TypeScript gets updated to
 * know about it (sometime after 4.6.3)
 */
export type AuthenticatorTransportFuture =
  | 'ble'
  | 'cable'
  | 'hybrid'
  | 'internal'
  | 'nfc'
  | 'smart-card'
  | 'usb';

/**
 * A super class of TypeScript's `PublicKeyCredentialDescriptor` that knows about the latest
 * transports. Should eventually be replaced by TypeScript's when TypeScript gets updated to
 * know about it (sometime after 4.6.3)
 */
export interface PublicKeyCredentialDescriptorFuture
  extends Omit<PublicKeyCredentialDescriptor, 'transports'> {
  transports?: AuthenticatorTransportFuture[];
}

/** */
export type PublicKeyCredentialJSON =
  | RegistrationResponseJSON
  | AuthenticationResponseJSON;

/**
 * A super class of TypeScript's `PublicKeyCredential` that knows about upcoming WebAuthn features
 */
export interface PublicKeyCredentialFuture extends PublicKeyCredential {
  type: PublicKeyCredentialType;
  // See https://github.com/w3c/webauthn/issues/1745
  isConditionalMediationAvailable?(): Promise<boolean>;
  // See https://w3c.github.io/webauthn/#sctn-parseCreationOptionsFromJSON
  parseCreationOptionsFromJSON?(
    options: PublicKeyCredentialCreationOptionsJSON,
  ): PublicKeyCredentialCreationOptions;
  // See https://w3c.github.io/webauthn/#sctn-parseRequestOptionsFromJSON
  parseRequestOptionsFromJSON?(
    options: PublicKeyCredentialRequestOptionsJSON,
  ): PublicKeyCredentialRequestOptions;
  // See https://w3c.github.io/webauthn/#dom-publickeycredential-tojson
  toJSON?(): PublicKeyCredentialJSON;
}

/**
 * The two types of credentials as defined by bit 3 ("Backup Eligibility") in authenticator data:
 * - `"singleDevice"` credentials will never be backed up
 * - `"multiDevice"` credentials can be backed up
 */
export type CredentialDeviceType = 'singleDevice' | 'multiDevice';

export interface RegistrationCredentialWithResponse
  extends RegistrationCredential {
  transports?: AuthenticatorTransportFuture[];
  responsePublicKeyAlgorithm?: number;
  responsePublicKey?: string;
  responseAuthenticatorData?: string;
}

export type GenerateAuthenticationOptionsOpts = {
  rpID: string;
  allowCredentials?: {
    id: Base64URLString;
    transports?: AuthenticatorTransportFuture[];
  }[];
  challenge?: string | Uint8Array;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
};

export type VerifyAuthenticationResponseOpts = {
  response: AuthenticationResponseJSON;
  expectedChallenge: string | ((challenge: string) => boolean | Promise<boolean>);
  expectedOrigin: string | string[];
  expectedRPID: string | string[];
  authenticator: AuthenticatorDevice;
  expectedType?: string | string[];
  requireUserVerification?: boolean;
  advancedFIDOConfig?: {
    userVerification?: UserVerificationRequirement;
  };
};

export type DevicePublicKeyAuthenticatorOutput = {
  dpk?: Uint8Array;
  sig?: string;
  nonce?: Uint8Array;
  scope?: Uint8Array;
  aaguid?: Uint8Array;
};
export type UVMAuthenticatorOutput = {
  uvm?: Uint8Array[];
};

export type AuthenticationExtensionsAuthenticatorOutputs = {
  devicePubKey?: DevicePublicKeyAuthenticatorOutput;
  uvm?: UVMAuthenticatorOutput;
};

/**
 * Result of authentication verification
 *
 * @param verified If the authentication response could be verified
 * @param authenticationInfo.credentialID The ID of the authenticator used during authentication.
 * Should be used to identify which DB authenticator entry needs its `counter` updated to the value
 * below
 * @param authenticationInfo.newCounter The number of times the authenticator identified above
 * reported it has been used. **Should be kept in a DB for later reference to help prevent replay
 * attacks!**
 * @param authenticationInfo.credentialDeviceType Whether this is a single-device or multi-device
 * credential. **Should be kept in a DB for later reference!**
 * @param authenticationInfo.credentialBackedUp Whether or not the multi-device credential has been
 * backed up. Always `false` for single-device credentials. **Should be kept in a DB for later
 * reference!**
 * @param authenticationInfo.origin The origin of the website that the authentication occurred on
 * @param authenticationInfo.rpID The RP ID that the authentication occurred on
 * @param authenticationInfo?.authenticatorExtensionResults The authenticator extensions returned
 * by the browser
 */
export type VerifiedAuthenticationResponse = {
  verified: boolean;
  authenticationInfo: {
    credentialID: Base64URLString;
    newCounter: number;
    userVerified: boolean;
    credentialDeviceType: CredentialDeviceType;
    credentialBackedUp: boolean;
    origin: string;
    rpID: string;
    authenticatorExtensionResults?: AuthenticationExtensionsAuthenticatorOutputs;
  };
};

export type ClientDataJSON = {
  type: string;
  challenge: string;
  origin: string;
  crossOrigin?: boolean;
  tokenBinding?: {
    id?: string;
    status: 'present' | 'supported' | 'not-supported';
  };
};

export type ParsedAuthenticatorData = {
  rpIdHash: Uint8Array;
  flagsBuf: Uint8Array;
  flags: {
    up: boolean;
    uv: boolean;
    be: boolean;
    bs: boolean;
    at: boolean;
    ed: boolean;
    flagsInt: number;
  };
  counter: number;
  counterBuf: Uint8Array;
  aaguid?: Uint8Array;
  credentialID?: Uint8Array;
  credentialPublicKey?: Uint8Array;
  extensionsData?: AuthenticationExtensionsAuthenticatorOutputs;
  extensionsDataBuffer?: Uint8Array;
};

/**
 * Fundamental values that are needed to discern the more specific COSE public key types below.
 *
 * The use of `Maps` here is due to CBOR encoding being used with public keys, and the CBOR "Map"
 * type is being decoded to JavaScript's `Map` type instead of, say, a basic Object as us JS
 * developers might prefer.
 *
 * These types are an unorthodox way of saying "these Maps should involve these discrete lists of
 * keys", but it works.
 */
/**
 * COSE Keys
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
 * https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
 */
export enum COSEKTY {
  OKP = 1,
  EC2 = 2,
  RSA = 3
}

export enum COSEKEYS {
  kty = 1,
  alg = 3,
  crv = -1,
  x = -2,
  y = -3,
  n = -1,
  e = -2
}

/**
 * COSE Algorithms
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
export enum COSEALG {
  ES256 = -7,
  EdDSA = -8,
  ES384 = -35,
  ES512 = -36,
  PS256 = -37,
  PS384 = -38,
  PS512 = -39,
  ES256K = -47,
  RS256 = -257,
  RS384 = -258,
  RS512 = -259,
  RS1 = -65535
}

export type COSEPublicKey = {
  get(key: COSEKEYS.kty): COSEKTY | undefined;
  get(key: COSEKEYS.alg): COSEALG | undefined;
  set(key: COSEKEYS.kty, value: COSEKTY): void;
  set(key: COSEKEYS.alg, value: COSEALG): void;
};

/**
 * COSE Curves
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
 */
export enum COSECRV {
  P256 = 1,
  P384 = 2,
  P521 = 3,
  ED25519 = 6,
  SECP256K1 = 8,
}

export type COSEPublicKeyOKP = COSEPublicKey & {
  // Getters
  get(key: COSEKEYS.crv): number | undefined;
  get(key: COSEKEYS.x): Uint8Array | undefined;
  // Setters
  set(key: COSEKEYS.crv, value: number): void;
  set(key: COSEKEYS.x, value: Uint8Array): void;
};

export type COSEPublicKeyEC2 = COSEPublicKey & {
  // Getters
  get(key: COSEKEYS.crv): number | undefined;
  get(key: COSEKEYS.x): Uint8Array | undefined;
  get(key: COSEKEYS.y): Uint8Array | undefined;
  // Setters
  set(key: COSEKEYS.crv, value: number): void;
  set(key: COSEKEYS.x, value: Uint8Array): void;
  set(key: COSEKEYS.y, value: Uint8Array): void;
};

export type COSEPublicKeyRSA = COSEPublicKey & {
  // Getters
  get(key: COSEKEYS.n): Uint8Array | undefined;
  get(key: COSEKEYS.e): Uint8Array | undefined;
  // Setters
  set(key: COSEKEYS.n, value: Uint8Array): void;
  set(key: COSEKEYS.e, value: Uint8Array): void;
};

export type SubtleCryptoAlg = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';
export type SubtleCryptoCrv = 'P-256' | 'P-384' | 'P-521' | 'Ed25519';
export type SubtleCryptoKeyAlgName =
  | 'ECDSA'
  | 'Ed25519'
  | 'RSASSA-PKCS1-v1_5'
  | 'RSA-PSS';

export type GenerateRegistrationOptionsOpts = {
  rpName: string;
  rpID: string;
  userName: string;
  userID?: Uint8Array;
  challenge?: string | Uint8Array;
  userDisplayName?: string;
  timeout?: number;
  attestationType?: AttestationConveyancePreference;
  excludeCredentials?: {
    id: Base64URLString;
    transports?: AuthenticatorTransportFuture[];
  }[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  extensions?: AuthenticationExtensionsClientInputs;
  supportedAlgorithmIDs?: COSEAlgorithmIdentifier[];
};

export type VerifyRegistrationResponseOpts = {
  response: RegistrationResponseJSON;
  expectedChallenge: string | ((challenge: string) => boolean | Promise<boolean>);
  expectedOrigin: string | string[];
  expectedRPID?: string | string[];
  expectedType?: string | string[];
  requireUserVerification?: boolean;
  supportedAlgorithmIDs?: COSEAlgorithmIdentifier[];
};

export type AttestationFormat = 'fido-u2f' | 'packed' | 'android-safetynet' | 'android-key' | 'tpm' | 'apple' | 'none';

/**
 * Result of registration verification
 *
 * @param verified If the assertion response could be verified
 * @param registrationInfo.fmt Type of attestation
 * @param registrationInfo.counter The number of times the authenticator reported it has been used.
 * **Should be kept in a DB for later reference to help prevent replay attacks!**
 * @param registrationInfo.aaguid Authenticator's Attestation GUID indicating the type of the
 * authenticator
 * @param registrationInfo.credentialPublicKey The credential's public key
 * @param registrationInfo.credentialID The credential's credential ID for the public key above
 * @param registrationInfo.credentialType The type of the credential returned by the browser
 * @param registrationInfo.userVerified Whether the user was uniquely identified during attestation
 * @param registrationInfo.attestationObject The raw `response.attestationObject` Buffer returned by
 * the authenticator
 * @param registrationInfo.credentialDeviceType Whether this is a single-device or multi-device
 * credential. **Should be kept in a DB for later reference!**
 * @param registrationInfo.credentialBackedUp Whether or not the multi-device credential has been
 * backed up. Always `false` for single-device credentials. **Should be kept in a DB for later
 * reference!**
 * @param registrationInfo.origin The origin of the website that the registration occurred on
 * @param registrationInfo?.rpID The RP ID that the registration occurred on, if one or more were
 * specified in the registration options
 * @param registrationInfo?.authenticatorExtensionResults The authenticator extensions returned
 * by the browser
 */
export type VerifiedRegistrationResponse = {
  verified: boolean;
  registrationInfo?: {
    fmt: AttestationFormat;
    counter: number;
    aaguid: string;
    credentialID: Base64URLString;
    credentialPublicKey: Uint8Array;
    credentialType: 'public-key';
    attestationObject: Uint8Array;
    userVerified: boolean;
    credentialDeviceType: CredentialDeviceType;
    credentialBackedUp: boolean;
    origin: string;
    rpID?: string;
    authenticatorExtensionResults?: AuthenticationExtensionsAuthenticatorOutputs;
  };
};

/**
 * `AttestationStatement` will be an instance of `Map`, but these keys help make finite the list of
 * possible values within it.
 */
export type AttestationStatement = {
  get(key: 'sig'): Uint8Array | undefined;
  get(key: 'x5c'): Uint8Array[] | undefined;
  get(key: 'response'): Uint8Array | undefined;
  get(key: 'alg'): number | undefined;
  get(key: 'ver'): string | undefined;
  get(key: 'certInfo'): Uint8Array | undefined;
  get(key: 'pubArea'): Uint8Array | undefined;
  readonly size: number;
};

/**
 * Values passed to all attestation format verifiers, from which they are free to use as they please
 */
export type AttestationFormatVerifierOpts = {
  aaguid: Uint8Array;
  attStmt: AttestationStatement;
  authData: Uint8Array;
  clientDataHash: Uint8Array;
  credentialID: Uint8Array;
  credentialPublicKey: Uint8Array;
  rootCertificates: string[];
  rpIdHash: Uint8Array;
  verifyTimestampMS?: boolean;
};

export type AttestationObject = {
  get(key: 'fmt'): AttestationFormat;
  get(key: 'attStmt'): AttestationStatement;
  get(key: 'authData'): Uint8Array;
};

export type CertificateInfo = {
  issuer: Issuer;
  subject: Subject;
  version: number;
  basicConstraintsCA: boolean;
  notBefore: Date;
  notAfter: Date;
  parsedCertificate: Certificate;
};

export type Issuer = {
  C?: string;
  O?: string;
  OU?: string;
  CN?: string;
  combined: string;
};

export type Subject = {
  C?: string;
  O?: string;
  OU?: string;
  CN?: string;
  combined: string;
};

/**
 * A cache of revoked cert serial numbers by Authority Key ID
 */
export type CAAuthorityInfo = {
  // A list of certificates serial numbers in hex format
  revokedCerts: string[];
  // An optional date by which an update should be published
  nextUpdate?: Date;
};

/**
 * Metadata Service structures
 * https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
 */
export type MDSJWTHeader = {
  alg: string;
  typ: string;
  x5c: Base64URLString[];
};
export type MDSJWTPayload = {
  legalHeader: string;
  no: number;
  nextUpdate: string;
  entries: MetadataBLOBPayloadEntry[];
};
export type MetadataBLOBPayloadEntry = {
  aaid?: string;
  aaguid?: string;
  attestationCertificateKeyIdentifiers?: string[];
  metadataStatement?: MetadataStatement;
  biometricStatusReports?: BiometricStatusReport[];
  statusReports: StatusReport[];
  timeOfLastStatusChange: string;
  rogueListURL?: string;
  rogueListHash?: string;
};
export type BiometricStatusReport = {
  certLevel: number;
  modality: UserVerify;
  effectiveDate?: string;
  certificationDescriptor?: string;
  certificateNumber?: string;
  certificationPolicyVersion?: string;
  certificationRequirementsVersion?: string;
};
export type StatusReport = {
  status: AuthenticatorStatus;
  effectiveDate?: string;
  authenticatorVersion?: number;
  certificate?: string;
  url?: string;
  certificationDescriptor?: string;
  certificateNumber?: string;
  certificationPolicyVersion?: string;
  certificationRequirementsVersion?: string;
};
export type AuthenticatorStatus = 'NOT_FIDO_CERTIFIED' | 'FIDO_CERTIFIED' | 'USER_VERIFICATION_BYPASS' | 'ATTESTATION_KEY_COMPROMISE' | 'USER_KEY_REMOTE_COMPROMISE' | 'USER_KEY_PHYSICAL_COMPROMISE' | 'UPDATE_AVAILABLE' | 'REVOKED' | 'SELF_ASSERTION_SUBMITTED' | 'FIDO_CERTIFIED_L1' | 'FIDO_CERTIFIED_L1plus' | 'FIDO_CERTIFIED_L2' | 'FIDO_CERTIFIED_L2plus' | 'FIDO_CERTIFIED_L3' | 'FIDO_CERTIFIED_L3plus';
/**
* Types defined in the FIDO Metadata Statement spec
*
* See https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html
*/
export type CodeAccuracyDescriptor = {
  base: number;
  minLength: number;
  maxRetries?: number;
  blockSlowdown?: number;
};
export type BiometricAccuracyDescriptor = {
  selfAttestedFRR?: number;
  selfAttestedFAR?: number;
  maxTemplates?: number;
  maxRetries?: number;
  blockSlowdown?: number;
};
export type PatternAccuracyDescriptor = {
  minComplexity: number;
  maxRetries?: number;
  blockSlowdown?: number;
};
export type VerificationMethodDescriptor = {
  userVerificationMethod: UserVerify;
  caDesc?: CodeAccuracyDescriptor;
  baDesc?: BiometricAccuracyDescriptor;
  paDesc?: PatternAccuracyDescriptor;
};
export type VerificationMethodANDCombinations = VerificationMethodDescriptor[];
export type rgbPaletteEntry = {
  r: number;
  g: number;
  b: number;
};
export type DisplayPNGCharacteristicsDescriptor = {
  width: number;
  height: number;
  bitDepth: number;
  colorType: number;
  compression: number;
  filter: number;
  interlace: number;
  plte?: rgbPaletteEntry[];
};
export type EcdaaTrustAnchor = {
  X: string;
  Y: string;
  c: string;
  sx: string;
  sy: string;
  G1Curve: string;
};
export type ExtensionDescriptor = {
  id: string;
  tag?: number;
  data?: string;
  fail_if_unknown: boolean;
};
export type AlternativeDescriptions = {
  [langCode: string]: string;
};
export type MetadataStatement = {
  legalHeader?: string;
  aaid?: string;
  aaguid?: string;
  attestationCertificateKeyIdentifiers?: string[];
  description: string;
  alternativeDescriptions?: AlternativeDescriptions;
  authenticatorVersion: number;
  protocolFamily: string;
  schema: number;
  upv: Version[];
  authenticationAlgorithms: AlgSign[];
  publicKeyAlgAndEncodings: AlgKey[];
  attestationTypes: Attestation[];
  userVerificationDetails: VerificationMethodANDCombinations[];
  keyProtection: KeyProtection[];
  isKeyRestricted?: boolean;
  isFreshUserVerificationRequired?: boolean;
  matcherProtection: MatcherProtection[];
  cryptoStrength?: number;
  attachmentHint?: AttachmentHint[];
  tcDisplay: TransactionConfirmationDisplay[];
  tcDisplayContentType?: string;
  tcDisplayPNGCharacteristics?: DisplayPNGCharacteristicsDescriptor[];
  attestationRootCertificates: string[];
  ecdaaTrustAnchors?: EcdaaTrustAnchor[];
  icon?: string;
  supportedExtensions?: ExtensionDescriptor[];
  authenticatorGetInfo?: AuthenticatorGetInfo;
};
/**
* Types declared in other specs
*/
/**
* USER_VERIFY
* https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#user-verification-methods
*/
export type UserVerify = 'presence_internal' | 'fingerprint_internal' | 'passcode_internal' | 'voiceprint_internal' | 'faceprint_internal' | 'location_internal' | 'eyeprint_internal' | 'pattern_internal' | 'handprint_internal' | 'passcode_external' | 'pattern_external' | 'none' | 'all';
/**
* ALG_SIGN
* https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authentication-algorithms
*
* Using this helpful TS pattern here so that we can strongly enforce the existence of COSE info
* mappings in `algSignToCOSEInfoMap` in verifyAttestationWithMetadata.ts
*/
export type AlgSign = typeof AlgSign[number];
declare const AlgSign: readonly ["secp256r1_ecdsa_sha256_raw", "secp256r1_ecdsa_sha256_der", "rsassa_pss_sha256_raw", "rsassa_pss_sha256_der", "secp256k1_ecdsa_sha256_raw", "secp256k1_ecdsa_sha256_der", "rsassa_pss_sha384_raw", "rsassa_pkcsv15_sha256_raw", "rsassa_pkcsv15_sha384_raw", "rsassa_pkcsv15_sha512_raw", "rsassa_pkcsv15_sha1_raw", "secp384r1_ecdsa_sha384_raw", "secp512r1_ecdsa_sha256_raw", "ed25519_eddsa_sha512_raw"];
/**
* ALG_KEY
* https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#public-key-representation-formats
*/
export type AlgKey = 'ecc_x962_raw' | 'ecc_x962_der' | 'rsa_2048_raw' | 'rsa_2048_der' | 'cose';
/**
* ATTESTATION
* https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authenticator-attestation-types
*/
export type Attestation = 'basic_full' | 'basic_surrogate' | 'ecdaa' | 'attca' | 'anonca' | 'none';
/**
* KEY_PROTECTION
* https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#key-protection-types
*/
export type KeyProtection = 'software' | 'hardware' | 'tee' | 'secure_element' | 'remote_handle';
/**
* MATCHER_PROTECTION
* https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#matcher-protection-types
*/
export type MatcherProtection = 'software' | 'tee' | 'on_chip';
/**
* ATTACHMENT_HINT
* https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authenticator-attachment-hints
*/
export type AttachmentHint = 'internal' | 'external' | 'wired' | 'wireless' | 'nfc' | 'bluetooth' | 'network' | 'ready' | 'wifi_direct';
/**
* TRANSACTION_CONFIRMATION_DISPLAY
* https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#transaction-confirmation-display-types
*/
export type TransactionConfirmationDisplay = 'any' | 'privileged_software' | 'tee' | 'hardware' | 'remote';
/**
* https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#version-interface
*/
export type Version = {
  major: number;
  minor: number;
};
/**
* https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfoz
*/
export type AuthenticatorGetInfo = {
  versions: ('FIDO_2_0' | 'U2F_V2')[];
  extensions?: string[];
  aaguid: string;
  options?: {
      plat?: boolean;
      rk?: boolean;
      clientPin?: boolean;
      up?: boolean;
      uv?: boolean;
  };
  maxMsgSize?: number;
  pinProtocols?: number[];
  algorithms?: {
      type: 'public-key';
      alg: number;
  }[];
};

export type SafetyNetJWTHeader = {
  alg: string;
  x5c: string[];
};

export type SafetyNetJWTPayload = {
  nonce: string;
  timestampMs: number;
  apkPackageName: string;
  apkDigestSha256: string;
  ctsProfileMatch: boolean;
  apkCertificateDigestSha256: string[];
  basicIntegrity: boolean;
};

export type SafetyNetJWTSignature = string;

export type ParsedPubArea = {
  type: 'TPM_ALG_RSA' | 'TPM_ALG_ECC';
  nameAlg: string;
  objectAttributes: {
    fixedTPM: boolean;
    stClear: boolean;
    fixedParent: boolean;
    sensitiveDataOrigin: boolean;
    userWithAuth: boolean;
    adminWithPolicy: boolean;
    noDA: boolean;
    encryptedDuplication: boolean;
    restricted: boolean;
    decrypt: boolean;
    signOrEncrypt: boolean;
  };
  authPolicy: Uint8Array;
  parameters: {
    rsa?: RSAParameters;
    ecc?: ECCParameters;
  };
  unique: Uint8Array;
};

export type RSAParameters = {
  symmetric: string;
  scheme: string;
  keyBits: number;
  exponent: number;
};

export type ECCParameters = {
  symmetric: string;
  scheme: string;
  curveID: string;
  kdf: string;
};

export type ManufacturerInfo = {
  name: string;
  id: string;
};

export type ParsedCertInfo = {
  magic: number;
  type: string;
  qualifiedSigner: Uint8Array;
  extraData: Uint8Array;
  clockInfo: {
    clock: Uint8Array;
    resetCount: number;
    restartCount: number;
    safe: boolean;
  };
  firmwareVersion: Uint8Array;
  attested: {
    nameAlg: string;
    nameAlgBuffer: Uint8Array;
    name: Uint8Array;
    qualifiedName: Uint8Array;
  };
};

export type RootCertIdentifier = AttestationFormat | 'mds';

// Cached MDS APIs from which BLOBs are downloaded
export type CachedMDS = {
  url: string;
  no: number;
  nextUpdate: Date;
};

export type CachedBLOBEntry = {
  entry: MetadataBLOBPayloadEntry;
  url: string;
};

export enum SERVICE_STATE {
  DISABLED,
  REFRESHING,
  READY,
}

// Allow MetadataService to accommodate unregistered AAGUIDs ("permissive"), or only allow
// registered AAGUIDs ("strict"). Currently primarily impacts how `getStatement()` operates
export type VerificationMode = 'permissive' | 'strict';
