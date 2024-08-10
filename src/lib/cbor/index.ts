import { CBORType, decodePartialCBOR, encodeCBOR } from "@levischuck/tiny-cbor";

export const decodeFirst = <T>(input: Uint8Array): T =>
  (decodePartialCBOR(new Uint8Array(input), 0) as [T, number])[0];

export const encode = (input: CBORType): Uint8Array => encodeCBOR(input);
