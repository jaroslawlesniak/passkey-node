import type { Controller } from "../types";

export const index: Controller = (req, res) => {
  return res.status(200).send(req.query);
}
