import { numberToUint8, uint8ArrayToBase64 } from "@/lib/buffer";
import { credentialRepository, userRepository } from "@/repositories";
import { generateRegistrationOptions, verifyRegistrationResponse } from "@simplewebauthn/server";
import { RegistrationResponseJSON } from "@simplewebauthn/server/script/deps";

const ES256 = -7;
const RS256 = -257;

const rpName: string = 'Passkeys Tutorial';
const rpID: string = 'localhost';
const origin: string = `http://${rpID}:8080`;

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
      console.log(registrationInfo)

      const user = await userRepository.getByToken(userToken);

      return credentialRepository.create({
        counter,
        credentialId: credentialID,
        publicKey: uint8ArrayToBase64(credentialPublicKey),
        transports: body.response.transports?.[0] || '',
        userId: user.id,
      });
    } else {
      throw new Error('Not verified');
    }
  });

export const startUserLogging = () => {
  console.log('startUserLogging');
}

export const finishUserLogging = () => {
  console.log('finishUserLogging');
}
