import { Request } from "express";
import jwt from "jsonwebtoken";

import { Token, TokenPayload } from "./types";

const secret = "some secret value";
const expiresIn = "1d";

export const sign = <T extends object>(userToken: string, payload: T): Token =>
  jwt.sign({ ...payload, userToken }, secret, { expiresIn });

export const validate = (token: Token) => jwt.verify(token, secret);

export const extract = (req: Request) => {
  const token = req.body.token;

  if (token) {
    return validate(token) as TokenPayload;
  }

  throw new Error("Token is null");
};
