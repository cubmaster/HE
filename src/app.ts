import express from "express";
import * as http from "http";
import path from "path";

import cors from "cors";
import {config} from "./config/config";
import {IndexRouter} from './routes/index'
import {APIRouter} from './routes/api';
import {HE} from './routes/he'
import {
    Mongoose
}  from './config/mongoose';

const app = express();
const server = new http.Server(app);
const env = process.env.NODE_ENV = process.env.NODE_ENV || 'development';



if (env == 'development'){
    app.use(cors({
        allowedHeaders:'*',
        credentials: true,
        origin:'*',
        methods:'*'
    }));


}

const mongoose = new Mongoose(app, config[env]);
//app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({extended: false}));



app.use(express.static(path.join(__dirname, 'public')));


app.use('/he', new HE().router);
app.use('/api', new APIRouter().router);
app.use('/', new IndexRouter().router);


server.listen(process.env.PORT || 3000, () => {
    console.log(`Application listening on port ${process.env.PORT || 3000}!`);
});

