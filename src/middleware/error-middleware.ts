
import { Request, Response, NextFunction } from 'express';
import { AppError } from '../utils/AppError.js';

export const globalErrorHandler = (
    err: Error | AppError,
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const statusCode = err instanceof AppError ? err.statusCode : 500;

    res.status(statusCode).json({
        status: 'error',
        message: err.message || 'Internal Server Error',
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    });
};