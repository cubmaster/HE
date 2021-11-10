


import {dataInit} from "./dataInit";
import {initModules} from "./models";
import  mongoose  from 'mongoose';

export class Mongoose
{
    constructor(app,config) {
        console.info("Connected to database:" + config.db);

        mongoose.connect(config.db, {
            promiseLibrary: require('bluebird'),
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useCreateIndex: true
        }).then(() => console.log('db connection successful'))
            .catch((err) => console.error(err));


        const mods = new initModules();
        const data = new dataInit();
    }

}
