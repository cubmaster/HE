
import {encryption} from './encryption'
import { user} from '../models/user'
import * as mongoose from "mongoose";

export class UserFunctions{

    static UserCount():number{
        const u = new user();
        return 1
    }

    static MakeNewUser(UserName: string, email: any, pwd: any, lastName: any, firstName: any, _Roles: never[], cb: (arg0: any) => void){


        "use strict";
        let Roles = _Roles || [];

        let salty = encryption.createSalt();
        let u = new user();
        let newUser:any = {};

             newUser.email= email;
             newUser.password= encryption.hashPwd(salty, pwd);
             newUser.username= UserName.toLowerCase();
             newUser.salt= salty;
             newUser.lastName= lastName;
             newUser.firstName=firstName;
             newUser.roles=Roles;
            //auth:config.Auth

        newUser.save();


    }


}


