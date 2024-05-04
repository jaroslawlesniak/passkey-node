import express, { Express } from 'express'
import { authentication } from '@/routes';
import cookieParser from 'cookie-parser';
import cors from 'cors';

const app: Express = express();

app.use(cors({
  origin: "*"
}))
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(cookieParser());

// routes
app.use(authentication());

export default app;
