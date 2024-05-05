import { GenerateAuthenticationOptionsOpts, GenerateRegistrationOptionsOpts, VerifiedAuthenticationResponse, VerifiedRegistrationResponse, VerifyAuthenticationResponseOpts, VerifyRegistrationResponseOpts, generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server"
import { base64ToUint8Array, numberToUint8 } from "../buffer";
import { AuthenticationResponseJSON, AuthenticatorDevice, AuthenticatorTransportFuture, RegistrationResponseJSON } from "@simplewebauthn/server/script/deps";
import { Credential } from "@prisma/client";
import { isoBase64URL } from "@simplewebauthn/server/helpers";

const ES256 = -7;
const RS256 = -257;

const rpName: string = 'Passkeys Tutorial';
const rpID: string = 'localhost';
const origin: string = `http://${rpID}:5173`;

const withStartRegistrationDefaults = (userId: number, email: string): GenerateRegistrationOptionsOpts => ({
  rpName,
  rpID,
  userID: numberToUint8(userId),
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

const liftRegistrationOrThrow = ({ verified, registrationInfo }: VerifiedRegistrationResponse) => {
  if (verified && registrationInfo) {
    return registrationInfo;
  }

  throw new Error('Failed to verify');
}

export const verifyRegistration = (body: RegistrationResponseJSON, challenge: string) =>
  verifyRegistrationResponse(withVerifyRegistrationDefaults(body, challenge)).then(liftRegistrationOrThrow);

const withStartLoginDefaults = (): GenerateAuthenticationOptionsOpts => ({
  timeout: 60000,
  allowCredentials: [],
  userVerification: 'required',
  rpID,
})

export const startLogin = () => 
  generateAuthenticationOptions(withStartLoginDefaults());

const toAuthenticatorDevice = ({ counter, credentialId, publicKey, transports }: Credential): AuthenticatorDevice => ({
  counter,
  credentialID: credentialId,
  credentialPublicKey: base64ToUint8Array(publicKey),
  transports: transports as AuthenticatorTransportFuture[]
})

const withVerifyLoginDefaults = (response: AuthenticationResponseJSON, expectedChallenge: string, credential: Credential): VerifyAuthenticationResponseOpts => ({
    response,
    expectedChallenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    authenticator: toAuthenticatorDevice(credential),
})

export const fromRawId = (rawId: string) => 
  isoBase64URL.toBase64(rawId).replace(/=+$/, '').replace(/\+/g, '-'); // what about this?

export const liftCredentialOrThrow = (credential?: Credential) => {
  if (credential) {
    return credential;
  }

  throw new Error('Credential not found');
}

const liftVerifyLoginOrThrow = ({ verified, authenticationInfo }: VerifiedAuthenticationResponse) => {
  if (verified) {
    return { authenticationInfo };
  }

  throw new Error('Verification failed');
}

export const verifyLogin = (response: AuthenticationResponseJSON, expectedChallenge: string, credential: Credential) =>
  verifyAuthenticationResponse(withVerifyLoginDefaults(response, expectedChallenge, credential)).then(liftVerifyLoginOrThrow);
