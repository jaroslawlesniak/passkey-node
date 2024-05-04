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

    return res.status(200).json({ options, token });
  })
  // .catch(() => res.status(500).send())
};

export const passkeyRegistrationFinish: Controller = (req, res) => {
  const { userToken, challenge } = extract(req);

  authentication.finishUserRegistration(userToken, req.body, challenge).then(() => {
    return res.status(200).send('passkeyRegistrationFinish');
  })
  // .catch(() => res.status(500).send())
};

export const passkeyLoginStart: Controller = (req, res) => {
  const { userName } = req.body;

  authentication.startUserLogging(userName).then(({ options, user }) => {
    const token = sign(user.token, options.challenge);

    return res.status(200).json({ options, token });
  })
  // .catch(() => res.status(500).send())
};

export const passkeyLoginFinish: Controller = (req, res) => {
  const { challenge } = extract(req);

  authentication.finishUserLogging(req.body, challenge)
    .then(() => res.status(200).send('passkeyLoginFinish'))
    // .catch(() => res.status(500).send())
};
