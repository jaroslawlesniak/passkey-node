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