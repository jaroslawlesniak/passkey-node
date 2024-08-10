import { getRandomValues } from "crypto";

export const generateChallenge = (): Promise<Uint8Array> =>
  Promise.resolve(getRandomValues(new Uint8Array(32)));
