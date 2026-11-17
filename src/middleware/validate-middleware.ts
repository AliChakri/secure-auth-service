import { NextFunction, Request, Response } from "express"
import { AppError } from "../utils/AppError.js";
import { ZodError, type ZodTypeAny } from "zod";
// import { AnyZodObject } from "zod/v3";

export const validate = (schema: ZodTypeAny) => {
    return async(req: Request, res: Response, next: NextFunction) => {
        try {

            await schema.parseAsync({
                body: req.body,
                query: req.query,
                params: req.params,
            });
            next();
        } catch (error) {
            if (error instanceof ZodError) {
                const message = error.issues.map(e => e.message).join(", ");
                return next(new AppError(message, 400));
            }
            next(error);
        }
    };
};