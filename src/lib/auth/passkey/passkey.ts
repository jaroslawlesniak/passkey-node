import {
  GenerateRegistrationOptionsOpts,
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
  VerifyRegistrationResponseOpts,
  generateRegistrationOptions,
  verifyRegistrationResponse
} from "@simplewebauthn/server"
import {
  AuthenticationResponseJSON,
  AuthenticatorDevice,
  AuthenticatorTransportFuture,
  RegistrationResponseJSON
} from "@simplewebauthn/server/script/deps";

import { Credential } from "@prisma/client";

import { ES256, RS256, origin, rpID, rpName } from "./config";
import { generateAuthenticationOptions, verifyAuthenticationResponse } from "./authentication";
import { VerifyAuthenticationResponseOpts } from "./types";
import { toBuffer } from "@/lib/base64";

const withStartRegistrationDefaults = (userId: number, email: string): GenerateRegistrationOptionsOpts => ({
  rpName,
  rpID,
  userID: toBuffer(userId.toString(10), 'base64'),
  userName: email,
  timeout: 60000,
  attestationType: 'direct',
  excludeCredentials: [],
  authenticatorSelection: {
    residentKey: 'preferred',
  },
  supportedAlgorithmIDs: [ES256, RS256],
})

export const startRegistration = (userId: number, email: string) =>
  generateRegistrationOptions(withStartRegistrationDefaults(userId, email));

const withVerifyRegistrationDefaults = (response: RegistrationResponseJSON, challenge: string): VerifyRegistrationResponseOpts => ({
  response,
  expectedChallenge: challenge,
  expectedOrigin: origin,
  expectedRPID: rpID,
  requireUserVerification: true,
})

const isRegistrationVerified = ({ verified, registrationInfo }: VerifiedRegistrationResponse) => {
  if (verified && registrationInfo) {
    return registrationInfo;
  }

  throw new Error('Failed to verify');
}

export const verifyRegistration = (body: RegistrationResponseJSON, challenge: string) =>
  verifyRegistrationResponse(withVerifyRegistrationDefaults(body, challenge)).then(isRegistrationVerified);

export const startLogin = () =>
  generateAuthenticationOptions();

const toAuthenticatorDevice = ({
  counter,
  credentialId,
  publicKey,
  transports
}: Credential): AuthenticatorDevice => ({
  counter,
  credentialID: credentialId,
  credentialPublicKey: toBuffer(publicKey, 'base64'),
  transports: transports as AuthenticatorTransportFuture[]
});

const withVerifyLoginDefaults = (
  response: AuthenticationResponseJSON,
  expectedChallenge: string,
  credential: Credential
): VerifyAuthenticationResponseOpts => ({
  response,
  expectedChallenge,
  expectedOrigin: origin,
  expectedRPID: rpID,
  authenticator: toAuthenticatorDevice(credential),
});

export const fromRawId = (rawId: string) => rawId

const isLoginVerified = ({ verified, authenticationInfo }: VerifiedAuthenticationResponse) => {
  if (verified) {
    return { authenticationInfo };
  }

  throw new Error('Verification failed');
}

export const verifyLogin = (response: AuthenticationResponseJSON, expectedChallenge: string, credential: Credential) =>
  verifyAuthenticationResponse(withVerifyLoginDefaults(response, expectedChallenge, credential)).then(isLoginVerified);
