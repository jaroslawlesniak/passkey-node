import { fromBuffer } from "@/lib/base64";

import { rpID } from "../../config";
import { generateChallenge } from "../../native";
import { PublicKeyCredentialRequestOptionsJSON } from "../../types";

const defaults: Partial<PublicKeyCredentialRequestOptionsJSON> = {
  rpId: rpID,
  timeout: 60000,
  allowCredentials: [], // not yet supported
  userVerification: "required",
  extensions: {},
};

const toPublicKeyCredentialRequest = (
  challenge: Uint8Array,
): PublicKeyCredentialRequestOptionsJSON => ({
  ...defaults,
  challenge: fromBuffer(challenge, "base64url"),
});

/**
 * Prepare a value to pass into navigator.credentials.get(...) for authenticator authentication
 *
 * **Options:**
 *
 * @param rpID - Valid domain name (after `https://`)
 * @param allowCredentials **(Optional)** - Authenticators previously registered by the user, if any. If undefined the client will ask the user which credential they want to use
 * @param challenge **(Optional)** - Random value the authenticator needs to sign and pass back user for authentication. Defaults to generating a random value
 * @param timeout **(Optional)** - How long (in ms) the user can take to complete authentication. Defaults to `60000`
 * @param userVerification **(Optional)** - Set to `'discouraged'` when asserting as part of a 2FA flow, otherwise set to `'preferred'` or `'required'` as desired. Defaults to `"preferred"`
 * @param extensions **(Optional)** - Additional plugins the authenticator or browser should use during authentication
 */
export const generateAuthenticationOptions =
  (): Promise<PublicKeyCredentialRequestOptionsJSON> =>
    generateChallenge().then(toPublicKeyCredentialRequest);
