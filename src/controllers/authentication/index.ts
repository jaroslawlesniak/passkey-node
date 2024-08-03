import { authentication } from "@/services";

import type { Controller } from "../types";
import { extract, sign } from "@/lib/jwt";
import { log } from "@/lib/logger";
import { fromRawId } from "@/lib/auth";

export const index: Controller = (_, res) => {
  return res.status(200).send('Hello World!');
};

export const passkeyRegistrationStart: Controller = (req, res) => {
  const { email } = req.body;

  authentication.startUserRegistration(email).then(({ options, user }) => {
    const token = sign(user.token, { challenge: options.challenge });

    return res.status(200).json({ options, token });
  })
  .catch(log(() => res.status(500).send()))
};

export const passkeyRegistrationFinish: Controller = (req, res) => {
  const { userToken, challenge } = extract(req);

  authentication
    .finishUserRegistration(userToken, req.body, challenge)
    .then(() => authentication.getUser(userToken))
    .then(({ email }) => {
      const token = sign(userToken, {});

      return res.status(200).json({ token, email });
    })
    .catch(log(() => res.status(500).send()))
};

export const passkeyLoginStart: Controller = (req, res) => {
  const { email } = req.body;

  authentication.startUserLogging(email).then(({ options, user }) => {
    const token = sign(user.token, { challenge: options.challenge });

    return res.status(200).json({ options, token });
  })
  .catch(log(() => res.status(500).send()))
};

export const passkeyLoginFinish: Controller = (req, res) => {
  const { userToken, challenge } = extract(req);

  authentication
    .finishUserLogging(req.body, fromRawId(challenge))
    .then(() => authentication.getUser(userToken))
    .then(({ email }) => {
      const token = sign(userToken, {});

      res.status(200).json({ token, email })}
    )
    .catch(log(() => res.status(500).send()))
};
