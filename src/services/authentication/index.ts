import { numberToUint8, uint8ArrayToBase64, base64ToUint8Array } from "@/lib/buffer";
import { credentialRepository, userRepository } from "@/repositories";
import { VerifyAuthenticationResponseOpts, generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import { AuthenticationResponseJSON, AuthenticatorDevice, AuthenticatorTransportFuture, RegistrationResponseJSON } from "@simplewebauthn/server/script/deps";
import { isoBase64URL } from '@simplewebauthn/server/helpers'
import { Credential } from "@prisma/client";

const ES256 = -7;
const RS256 = -257;

const rpName: string = 'Passkeys Tutorial';
const rpID: string = 'localhost';
const origin: string = `http://${rpID}:5173`;

export const startUserRegistration = async (userName: string) =>
  userRepository.create(userName).then(user => 
    generateRegistrationOptions({
      rpName,
      rpID,
      userID: numberToUint8(user.id),
      userName: user.userName,
      timeout: 60000,
      attestationType: 'direct',
      excludeCredentials: [],
      authenticatorSelection: {
        residentKey: 'preferred',
      },
      supportedAlgorithmIDs: [ES256, RS256],
    }).then(options => ({ user, options }))
  );

export const finishUserRegistration = (userToken: string, body: RegistrationResponseJSON, challenge: string) =>
  verifyRegistrationResponse({
    response: body,
    expectedChallenge: challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    requireUserVerification: true,
  }).then(async ({ verified, registrationInfo }) => {
    if (verified && registrationInfo) {
      const { credentialPublicKey, credentialID, counter } = registrationInfo;

      const user = await userRepository.getByToken(userToken);

      return credentialRepository.create({
        counter,
        credentialId: credentialID,
        publicKey: uint8ArrayToBase64(credentialPublicKey),
        transports: body.response.transports || [],
        userId: user.id,
      });
    } else {
      throw new Error('Not verified');
    }
  });

export const startUserLogging = (userName: string) => 
  userRepository.getByUserName(userName).then(user => 
    generateAuthenticationOptions({
      timeout: 60000,
      allowCredentials: [],
      userVerification: 'required',
      rpID,
  }).then(options => ({ user, options })));

const toAuthenticatorDevice = ({ counter, credentialId, publicKey, transports }: Credential): AuthenticatorDevice => ({
  counter,
  credentialID: credentialId,
  credentialPublicKey: base64ToUint8Array(publicKey),
  transports: transports as AuthenticatorTransportFuture[]
})

export const finishUserLogging = async (body: AuthenticationResponseJSON, challenge: string) => {
  const credentialId = isoBase64URL.toBase64(body.rawId).replace(/=+$/, ''); // what about this?
  // const bodyCredIdBuffer = isoBase64URL.toBuffer(body.rawId);
  const credential = await credentialRepository.getByCredentialId(credentialId)

  if (!credential) {
    throw new Error('DB credential not found');
  }

  const dbCredential: AuthenticatorDevice = toAuthenticatorDevice(credential);

  const opts: VerifyAuthenticationResponseOpts = {
    response: body,
    expectedChallenge: challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    authenticator: dbCredential,
  };

  const verification = await verifyAuthenticationResponse(opts);

  const { verified, authenticationInfo } = verification;

  if (verified) {
    await credentialRepository.update(
      credential.id,
      {
        counter: authenticationInfo.newCounter
      }
    );

    return Promise.resolve();
  } else {
    throw new Error('Not verified');
  }
}
