import { Request } from "express";
import jwt from "jsonwebtoken";

import { Token, TokenPayload } from "./types";

const SECRET = "some secret value"; // should be stored somewhere in a secured way
const TOKEN_EXPIRES_IN = "1d";

export const sign = <T extends object>(userToken: string, payload: T): Token =>
  jwt.sign({ ...payload, userToken }, SECRET, { expiresIn: TOKEN_EXPIRES_IN });

export const validate = (token: Token) => jwt.verify(token, SECRET);

export const extract = (req: Request) => {
  const token = req.body.token;

  if (token) {
    return validate(token) as TokenPayload;
  }

  throw new Error("Token is null");
};
