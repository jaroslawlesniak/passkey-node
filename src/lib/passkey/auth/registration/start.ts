import { fromBuffer, isBase64URL, trimPadding } from "@/lib/base64";

import { getRandomValues } from "../../crypto";
import { generateChallenge } from "../../native";
import {
  GenerateRegistrationOptionsOpts,
  PublicKeyCredentialCreationOptionsJSON,
} from "../../types";
import { fromUTF8String } from "../../uint";

/**
 * Set up some default authenticator selection options as per the latest spec:
 * https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria
 *
 * Helps with some older platforms (e.g. Android 7.0 Nougat) that may not be aware of these
 * defaults.
 */
const defaultAuthenticatorSelection: AuthenticatorSelectionCriteria = {
  residentKey: "preferred",
  userVerification: "preferred",
};

/**
 * Use the most commonly-supported algorithms
 * See the following:
 *   - https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 *   - https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-pubkeycredparams
 */
const defaultSupportedAlgorithmIDs: COSEAlgorithmIdentifier[] = [-8, -7, -257];

/**
 * Generate a suitably random value to be used as user ID
 */
export async function generateUserID(): Promise<Uint8Array> {
  /**
   * WebAuthn spec says user.id has a max length of 64 bytes. I prefer how 32 random bytes look
   * after they're base64url-encoded so I'm choosing to go with that here.
   */
  const newUserID = new Uint8Array(32);

  await getRandomValues(newUserID);

  return newUserID;
}

/**
 * Prepare a value to pass into navigator.credentials.create(...) for authenticator registration
 *
 * **Options:**
 *
 * @param rpName - User-visible, "friendly" website/service name
 * @param rpID - Valid domain name (after `https://`)
 * @param userName - User's website-specific username (email, etc...)
 * @param userID **(Optional)** - User's website-specific unique ID. Defaults to generating a random identifier
 * @param challenge **(Optional)** - Random value the authenticator needs to sign and pass back. Defaults to generating a random value
 * @param userDisplayName **(Optional)** - User's actual name. Defaults to `""`
 * @param timeout **(Optional)** - How long (in ms) the user can take to complete attestation. Defaults to `60000`
 * @param attestationType **(Optional)** - Specific attestation statement. Defaults to `"none"`
 * @param excludeCredentials **(Optional)** - Authenticators registered by the user so the user can't register the same credential multiple times. Defaults to `[]`
 * @param authenticatorSelection **(Optional)** - Advanced criteria for restricting the types of authenticators that may be used. Defaults to `{ residentKey: 'preferred', userVerification: 'preferred' }`
 * @param extensions **(Optional)** - Additional plugins the authenticator or browser should use during attestation
 * @param supportedAlgorithmIDs **(Optional)** - Array of numeric COSE algorithm identifiers supported for attestation by this RP. See https://www.iana.org/assignments/cose/cose.xhtml#algorithms. Defaults to `[-8, -7, -257]`
 */
export async function generateRegistrationOptions(
  options: GenerateRegistrationOptionsOpts,
): Promise<PublicKeyCredentialCreationOptionsJSON> {
  const {
    rpName,
    rpID,
    userName,
    userID,
    challenge = await generateChallenge(),
    userDisplayName = "",
    timeout = 60000,
    attestationType = "none",
    excludeCredentials = [],
    authenticatorSelection = defaultAuthenticatorSelection,
    extensions,
    supportedAlgorithmIDs = defaultSupportedAlgorithmIDs,
  } = options;

  /**
   * Prepare pubKeyCredParams from the array of algorithm ID's
   */
  const pubKeyCredParams: PublicKeyCredentialParameters[] =
    supportedAlgorithmIDs.map((id) => ({
      alg: id,
      type: "public-key",
    }));

  /**
   * Capture some of the nuances of how `residentKey` and `requireResidentKey` how either is set
   * depending on when either is defined in the options
   */
  if (authenticatorSelection.residentKey === undefined) {
    /**
     * `residentKey`: "If no value is given then the effective value is `required` if
     * requireResidentKey is true or `discouraged` if it is false or absent."
     *
     * See https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey
     */
    if (authenticatorSelection.requireResidentKey) {
      authenticatorSelection.residentKey = "required";
    } else {
      /**
       * FIDO Conformance v1.7.2 fails the first test if we do this, even though this is
       * technically compatible with the WebAuthn L2 spec...
       */
      // authenticatorSelection.residentKey = 'discouraged';
    }
  } else {
    /**
     * `requireResidentKey`: "Relying Parties SHOULD set it to true if, and only if, residentKey is
     * set to "required""
     *
     * Spec says this property defaults to `false` so we should still be okay to assign `false` too
     *
     * See https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey
     */
    authenticatorSelection.requireResidentKey =
      authenticatorSelection.residentKey === "required";
  }

  /**
   * Preserve ability to specify `string` values for challenges
   */
  let _challenge = challenge;
  if (typeof _challenge === "string") {
    _challenge = fromUTF8String(_challenge);
  }

  /**
   * Explicitly disallow use of strings for userID anymore because `isoBase64URL.fromBuffer()` below
   * will return an empty string if one gets through!
   */
  if (typeof userID === "string") {
    throw new Error(
      `String values for \`userID\` are no longer supported. See https://simplewebauthn.dev/docs/advanced/server/custom-user-ids`,
    );
  }

  /**
   * Generate a user ID if one is not provided
   */
  let _userID = userID;
  if (!_userID) {
    _userID = await generateUserID();
  }

  return {
    challenge: fromBuffer(_challenge),
    rp: {
      name: rpName,
      id: rpID,
    },
    user: {
      id: fromBuffer(_userID),
      name: userName,
      displayName: userDisplayName,
    },
    pubKeyCredParams,
    timeout,
    attestation: attestationType,
    excludeCredentials: excludeCredentials.map((cred) => {
      if (!isBase64URL(cred.id)) {
        throw new Error(
          `excludeCredential id "${cred.id}" is not a valid base64url string`,
        );
      }

      return {
        ...cred,
        id: trimPadding(cred.id),
        type: "public-key",
      };
    }),
    authenticatorSelection,
    extensions: {
      ...extensions,
      credProps: true,
    },
  };
}
