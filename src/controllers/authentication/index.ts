import { authentication } from "@/services";

import type { Controller } from "../types";
import { extract, sign } from "@/lib/jwt";

export const index: Controller = (_, res) => {
  return res.status(200).send('Hello World!');
};

export const passkeyRegistrationStart: Controller = (req, res) => {
  const { userName } = req.body;

  authentication.startUserRegistration(userName).then(({ options, user }) => {
    const token = sign(user.token, options.challenge);

    res.cookie('token', token, { maxAge: 900000, httpOnly: true })

    return res.status(200).send(options);
  });
};

export const passkeyRegistrationFinish: Controller = (req, res) => {
  const { userToken, challenge } = extract(req);
  console.log(userToken, challenge)
  authentication.finishUserRegistration(userToken, req.body, challenge).then(user => {
    console.log(user);

    return res.status(200).send('passkeyRegistrationFinish');
  });
};

export const passkeyLoginStart: Controller = (_, res) => {
  authentication.startUserLogging();

  return res.status(200).send('passkeyLoginStart');
};

export const passkeyLoginFinish: Controller = (_, res) => {
  authentication.finishUserLogging();

  return res.status(200).send('passkeyLoginFinish');
};
