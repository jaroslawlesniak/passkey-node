export const areEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length != right.length) {
    return false;
  }

  return left.every((value, i) => value === right[i]);
};

export const toHex = (array: Uint8Array): string =>
  Array.from(array, (i) => i.toString(16).padStart(2, "0")).join("");

const HEX_STRING_REGEX = /[^a-fA-F0-9]/u;
const EMPTY_ARRAY = [] as const;

export const fromHex = (hex?: string): Uint8Array => {
  if (!hex) {
    return Uint8Array.from(EMPTY_ARRAY);
  }

  const valid =
    hex.length !== 0 && hex.length % 2 === 0 && !HEX_STRING_REGEX.test(hex);

  if (!valid) {
    throw new Error("Invalid hex string");
  }

  const bytes = hex.match(/.{1,2}/g) ?? EMPTY_ARRAY;

  return Uint8Array.from(bytes.map((byte) => parseInt(byte, 16)));
};

const getArraysLengths = (arrays: Uint8Array[]) =>
  arrays.reduce((prev, curr) => prev + curr.length, 0);

export function concat(arrays: Uint8Array[]): Uint8Array {
  const array = new Uint8Array(getArraysLengths(arrays));

  let pointer = 0;

  arrays.forEach((arr) => {
    array.set(arr, pointer);

    pointer += arr.length;
  });

  return array;
}

export const toUTF8String = (input: Uint8Array): string => {
  const decoder = new TextDecoder("utf-8");

  return decoder.decode(input);
};

export const fromUTF8String = (input: string): Uint8Array => {
  const encoder = new TextEncoder();

  return encoder.encode(input);
};

export const fromASCIIString = (input: string): Uint8Array =>
  Uint8Array.from(input.split("").map((x) => x.charCodeAt(0)));

export const toDataView = (array: Uint8Array): DataView =>
  new DataView(array.buffer, array.byteOffset, array.length);
