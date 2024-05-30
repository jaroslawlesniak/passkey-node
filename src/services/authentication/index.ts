import { uint8ArrayToBase64 } from "@/lib/buffer";
import { credentialRepository, userRepository } from "@/repositories";
import { AuthenticationResponseJSON, RegistrationResponseJSON, fromRawId, startLogin, startRegistration, verifyLogin, verifyRegistration } from "@/lib/auth";

export const startUserRegistration = async (email: string) =>
  userRepository.create(email).then(user =>
    startRegistration(user.id, email).then(options => ({ user, options }))
  );

export const finishUserRegistration = (userToken: string, body: RegistrationResponseJSON, challenge: string) =>
  verifyRegistration(body, challenge)
    .then(({ credentialPublicKey, credentialID, counter }) =>
      userRepository.getByToken(userToken)
        .then(user => credentialRepository.create({
          counter,
          credentialId: credentialID,
          publicKey: uint8ArrayToBase64(credentialPublicKey),
          transports: body.response.transports || [],
          userId: user.id,
        })));

export const startUserLogging = (email: string) =>
  userRepository.getByEmail(email).then(user =>
    startLogin().then(options => ({ user, options })));

export const finishUserLogging = async (body: AuthenticationResponseJSON, challenge: string) =>
  credentialRepository.getByCredentialId(fromRawId(body.rawId))
    .then(credential => verifyLogin(body, challenge, credential)
      .then(({ authenticationInfo }) => credentialRepository.update(credential.id, { counter: authenticationInfo.newCounter }))
    )

export const getUser = (token: string) =>
  userRepository.getByToken(token);
