
import { Request, Response, NextFunction } from 'express';

// This higher-order function takes your controller and wraps it
export const catchAsync = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, next).catch(next);
  };
};