import type { Controller } from "../types";

export const index: Controller = (req, res, next) => {
  return res.status(200).send('ok');
}
