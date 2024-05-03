import express, { Express } from 'express'
import { authentication } from './routes';

const app: Express = express();

app.use(express.json());
app.use(express.urlencoded({extended: true}));

// routes
app.use(authentication);

export default app;
