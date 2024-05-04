import { finishUserLogging, finishUserRegistration, startUserLogging, startUserRegistration } from "@/services/authentication";
import type { Controller } from "../types";

export const index: Controller = (_, res) => {
  return res.status(200).send('Hello World!');
};

export const passkeyRegistrationStart: Controller = (_, res) => {
  startUserRegistration();

  return res.status(200).send('passkeyRegistrationStart');
};

export const passkeyRegistrationFinish: Controller = (_, res) => {
  finishUserRegistration();

  return res.status(200).send('passkeyRegistrationFinish');
};

export const passkeyLoginStart: Controller = (_, res) => {
  startUserLogging();

  return res.status(200).send('passkeyLoginStart');
};

export const passkeyLoginFinish: Controller = (_, res) => {
  finishUserLogging();

  return res.status(200).send('passkeyLoginFinish');
};
