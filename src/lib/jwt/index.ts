import { Request } from 'express'

import { Token } from "./types";
import jwt from 'jsonwebtoken';

const secret = 'some secret value';
const expiresIn = '1d';

export const sign = (userToken: string, challenge: string): Token => 
  jwt.sign(
    { userToken, challenge },
    secret,
    { expiresIn }
  );

export const validate = (token: Token) => 
  jwt.verify(token, secret)

export const extract = (req: Request) => {
  const token = req.body.token;

  if (token) {
    return validate(token) as any;
  }

  throw new Error('Token is null');
  // const token = req.cookies['token'];

  // if (token) {
  //   return validate(token) as any;
  // }

  // throw new Error('Token is null');
}
