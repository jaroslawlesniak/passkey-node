import express, { Router } from "express";

export const withRouter = (config: (router: Router) => void) => {
  const router = express.Router();

  config(router);

  return router;
};
