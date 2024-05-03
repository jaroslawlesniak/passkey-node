import { Request, Response, NextFunction } from 'express';

export type Controller = <T>(req: Request, res: Response, next: NextFunction) => Response<T> | void;
