import express, { Express } from 'express'
import { authentication } from '@/routes';
import cookieParser from 'cookie-parser';

const app: Express = express();

app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(cookieParser());

// routes
app.use(authentication());

export default app;
