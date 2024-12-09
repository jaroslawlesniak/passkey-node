import { isBase64URL, toBuffer, toUTF8String } from "@/lib/base64";

import {
  AuthenticationResponseJSON,
  AuthenticatorAssertionResponseJSON,
  Base64URLString,
  ClientDataJSON,
  ParsedAuthenticatorData,
  VerifiedAuthenticationResponse,
  VerifyAuthenticationResponseOpts,
} from "../../types";
import { concat } from "../../uint";
import {
  matchExpectedRPID,
  parseAuthenticatorData,
  parseBackupFlags,
  toHash,
  verifySignature,
} from "../../utils";

const isIdValid = ({ id, rawId }: AuthenticationResponseJSON) => {
  if (!id) {
    throw new Error("Credential ID not provided");
  }

  if (id !== rawId) {
    throw new Error("Credential ID is in incorrect format");
  }
};

const isPublicKeyAuthentication = ({ type }: AuthenticationResponseJSON) => {
  if (type !== "public-key") {
    throw new Error(`Incorrect type, expected public-key, given ${type}"`);
  }
};

const isResponseContentExists = ({ response }: AuthenticationResponseJSON) => {
  if (!response) {
    throw new Error("Lack of response");
  }
};

const ensuresResponseIsAString = ({ response }: AuthenticationResponseJSON) => {
  if (typeof response?.clientDataJSON !== "string") {
    throw new Error("Incorrect response type");
  }
};

const validateResponse = ({ response }: VerifyAuthenticationResponseOpts) =>
  [
    isIdValid,
    isPublicKeyAuthentication,
    isResponseContentExists,
    ensuresResponseIsAString,
  ].forEach((validator) => validator(response));

const toClientData = (data: Base64URLString): ClientDataJSON =>
  JSON.parse(toUTF8String(data));

const toTypeErrorMessage = (type: string) =>
  `Unexpected response type, found ${type}`;

const isArrayOfExpectedTypesValid = (
  { type }: ClientDataJSON,
  { expectedType }: VerifyAuthenticationResponseOpts,
) => {
  if (Array.isArray(expectedType) && !expectedType.includes(type)) {
    throw new Error(toTypeErrorMessage(expectedType.join(", ")));
  }
};

const isStringifyExpectedTypeValid = (
  { type }: ClientDataJSON,
  { expectedType }: VerifyAuthenticationResponseOpts,
) => {
  if (expectedType && type !== expectedType) {
    throw new Error(toTypeErrorMessage(expectedType.toString()));
  }
};

const isValidWebAuthenticationType = ({ type }: ClientDataJSON) => {
  if (type !== "webauthn.get") {
    throw new Error(toTypeErrorMessage(type));
  }
};

const validateAuthentication = (
  response: ClientDataJSON,
  options: VerifyAuthenticationResponseOpts,
) =>
  [
    isArrayOfExpectedTypesValid,
    isStringifyExpectedTypeValid,
    isValidWebAuthenticationType,
  ].forEach((validator) => validator(response, options));

const toDeviceChallengeErrorMessage = (challenge: string) =>
  `Invalid challenge, expected ${challenge}`;

const isFunctionDeviceChallengeValid = async (
  { challenge }: ClientDataJSON,
  { expectedChallenge }: VerifyAuthenticationResponseOpts,
) => {
  if (
    typeof expectedChallenge === "function" &&
    !(await expectedChallenge(challenge))
  ) {
    throw new Error(toDeviceChallengeErrorMessage(challenge));
  }
};

const isStringDeviceChallengeValid = async (
  { challenge }: ClientDataJSON,
  { expectedChallenge }: VerifyAuthenticationResponseOpts,
) => {
  if (challenge !== expectedChallenge) {
    throw new Error(toDeviceChallengeErrorMessage(expectedChallenge as string));
  }
};

const validateDeviceChallenge = (
  response: ClientDataJSON,
  options: VerifyAuthenticationResponseOpts,
) =>
  [isFunctionDeviceChallengeValid, isStringDeviceChallengeValid].forEach(
    async (validator) => await validator(response, options),
  );

const toOriginErrorMessage = (challenge: string) =>
  `Invalid origin, expected ${challenge}`;

const isOriginInArray = (
  { origin }: ClientDataJSON,
  { expectedOrigin }: VerifyAuthenticationResponseOpts,
) => {
  if (Array.isArray(expectedOrigin) && !expectedOrigin.includes(origin)) {
    throw new Error(toOriginErrorMessage(expectedOrigin.join(", ")));
  }
};

const isSingleOriginValid = (
  { origin }: ClientDataJSON,
  { expectedOrigin }: VerifyAuthenticationResponseOpts,
) => {
  if (origin !== expectedOrigin) {
    throw new Error(toOriginErrorMessage(expectedOrigin as string));
  }
};

const validateOrigin = (
  response: ClientDataJSON,
  options: VerifyAuthenticationResponseOpts,
) =>
  [isOriginInArray, isSingleOriginValid].forEach((validator) =>
    validator(response, options),
  );

const isPartInBase64 = (payload: string) => () => {
  if (!isBase64URL(payload)) {
    throw new Error("Content is not in base64Url format");
  }
};

const isUserHandleValid = ({
  userHandle,
}: AuthenticatorAssertionResponseJSON) => {
  if (userHandle && typeof userHandle !== "string") {
    throw new Error("userHandle is not a string");
  }
};

const validateAssertionResponse = (
  response: AuthenticatorAssertionResponseJSON,
) =>
  [
    isPartInBase64(response.authenticatorData),
    isPartInBase64(response.signature),
    isUserHandleValid,
  ].forEach((validator) => validator(response));

const isTokenBindingAnObject = ({ tokenBinding }: ClientDataJSON) => {
  if (tokenBinding && typeof tokenBinding !== "object") {
    throw new Error("Token is not an object");
  }
};

const isTokenBindingInCorrectState = ({ tokenBinding }: ClientDataJSON) => {
  if (
    tokenBinding &&
    ["notSupported", "supported", "present"].indexOf(tokenBinding.status) < 0
  ) {
    throw new Error(`Unexpected status: ${tokenBinding.status}`);
  }
};

const validateTokenBinding = (response: ClientDataJSON) =>
  [isTokenBindingAnObject, isTokenBindingInCorrectState].forEach((validator) =>
    validator(response),
  );

const toExpectedRPIDs = ({
  expectedRPID,
}: VerifyAuthenticationResponseOpts) => {
  if (typeof expectedRPID === "string") {
    return [expectedRPID];
  } else {
    return expectedRPID;
  }
};

const isFidoUserVerification = (
  { advancedFIDOConfig }: VerifyAuthenticationResponseOpts,
  { flags }: ParsedAuthenticatorData,
) => {
  if (advancedFIDOConfig !== undefined) {
    const { userVerification } = advancedFIDOConfig;

    if (userVerification === "required") {
      if (!flags.uv) {
        throw new Error("Flag (UV) not valid");
      }
    }
  }
};

const checkUserVerification = (
  { requireUserVerification = true }: VerifyAuthenticationResponseOpts,
  { flags }: ParsedAuthenticatorData,
) => {
  if (!flags.up) {
    throw new Error("Flag (UP) not valid");
  }

  if (requireUserVerification && !flags.uv) {
    throw new Error("User verification required");
  }
};

const validateUserVerification = (
  response: VerifyAuthenticationResponseOpts,
  authenticator: ParsedAuthenticatorData,
) =>
  [isFidoUserVerification, checkUserVerification].forEach((validator) =>
    validator(response, authenticator),
  );

const isCounterBiggerThanExpected = (
  { authenticator }: VerifyAuthenticationResponseOpts,
  { counter }: ParsedAuthenticatorData,
) => {
  if (
    (counter > 0 || authenticator.counter > 0) &&
    counter <= authenticator.counter
  ) {
    throw new Error(`Response counter is not valid, given ${counter}`);
  }
};

const validateCounter = (
  response: VerifyAuthenticationResponseOpts,
  authenticator: ParsedAuthenticatorData,
) =>
  [isCounterBiggerThanExpected].forEach((validator) =>
    validator(response, authenticator),
  );

const toSignature = (
  { clientDataJSON, signature }: AuthenticatorAssertionResponseJSON,
  buffer: Uint8Array,
) =>
  toHash(toBuffer(clientDataJSON)).then((hash) => [
    concat([buffer, hash]),
    toBuffer(signature),
  ]);

/**
 * Verify that the user has legitimately completed the authentication process
 *
 * **Options:**
 *
 * @param response - Response returned by `startAssertion()`
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
  const { response, authenticator } = options;

  const assertionResponse = response.response;

  validateResponse(options);

  const clientData = toClientData(assertionResponse.clientDataJSON);

  validateAuthentication(clientData, options);
  validateDeviceChallenge(clientData, options);
  validateOrigin(clientData, options);
  validateAssertionResponse(assertionResponse);
  validateTokenBinding(clientData);

  const authDataBuffer = toBuffer(assertionResponse.authenticatorData);
  const parsedAuthData = parseAuthenticatorData(authDataBuffer);

  validateUserVerification(options, parsedAuthData);
  validateCounter(options, parsedAuthData);

  const { rpIdHash, flags, counter, extensionsData } = parsedAuthData;

  const matchedRPID = await matchExpectedRPID(
    rpIdHash,
    toExpectedRPIDs(options),
  );

  const verified = await toSignature(assertionResponse, authDataBuffer).then(
    ([data, signature]) =>
      verifySignature({
        signature,
        data,
        credentialPublicKey: authenticator.credentialPublicKey,
      }),
  );

  const authenticationInfo = {
    ...parseBackupFlags(flags),
    newCounter: counter,
    credentialID: authenticator.credentialID,
    userVerified: flags.uv,
    authenticatorExtensionResults: extensionsData,
    origin: clientData.origin,
    rpID: matchedRPID,
  };

  const payload: VerifiedAuthenticationResponse = {
    verified,
    authenticationInfo,
  };

  return payload;
}
