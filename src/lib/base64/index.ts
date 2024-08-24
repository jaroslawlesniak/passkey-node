import base64 from "@hexagon/base64";

import type { Base64URLString } from "@/lib/passkey";

import type { Algorithm, Utf8String } from "./types";

const isUrlMode = (origin: Algorithm) => origin === "base64url";

export const toBuffer = (
  payload: string,
  from: Algorithm = "base64url",
): Uint8Array => new Uint8Array(base64.toArrayBuffer(payload, isUrlMode(from)));

export const fromBuffer = (
  buffer: Uint8Array,
  to: Algorithm = "base64url",
): string => base64.fromArrayBuffer(buffer, isUrlMode(to));

export const toBase64 = (payload: Base64URLString): Promise<string> =>
  Promise.resolve()
    .then(() => base64.toArrayBuffer(payload, isUrlMode("base64url")))
    .then((buffer) => base64.fromArrayBuffer(buffer, isUrlMode("base64")));

export const fromUTF8String = (payload: Utf8String): string =>
  base64.fromString(payload, isUrlMode("base64url"));

export const toUTF8String = (payload: Base64URLString): string =>
  base64.toString(payload, isUrlMode("base64url"));

export const isBase64 = (payload: string): boolean =>
  base64.validate(payload, isUrlMode("base64"));

export const isBase64URL = (payload: string): boolean =>
  base64.validate(trimPadding(payload), isUrlMode("base64url"));

export const trimPadding = (payload: Base64URLString): Base64URLString =>
  payload.replace(/=/g, "");
