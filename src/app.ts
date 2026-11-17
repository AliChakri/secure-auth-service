
import express, { Application, Request, Response } from "express"
import helmet from "helmet";
import { globalErrorHandler } from "./middleware/error-middleware.js";
import authRouter from "./routes/auth-routes.js";
import cookieParser from "cookie-parser";
import cors from 'cors'

const app:Application = express();


const allowedOrigins = [
  process.env.CLIENT_URL,
  'http://127.0.0.1:5173'
];

app.use(helmet());
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Blocked by CORS: Origin not allowed'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    credentials: true,
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser());
app.use('/api/auth', authRouter);

app.get('/health', (req: Request, res: Response) => {
    res.status(200).json({ status: 'UP' });
});

// Error Handling must be the Last Middleware
app.use(globalErrorHandler);

export default app

