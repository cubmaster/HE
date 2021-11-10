import jwt  from  'jwt-simple';
import * as config from  '../config/config';




export class Jwt{
    static env:string =process.env.NODE_ENV = process.env.NODE_ENV || 'development';





    static setTokenAndSent (user, res) {


        res.status(200).send(this.setToken(user));
    }

    static setToken(user){
        "use strict";
        let payload = {
            sub: user
        }

        let token = jwt.encode(payload, config[this.env].privateKey);


        user.password=null;
        user.salt=null;
        user.Auth = config[this.env].Auth;
        return {

            user: user,
            token: token,
            message: "Success"
        }
    }


    static getPayloadFromToken (token,res)
    {
        let user = jwt.decode(token,config[this.env].privateKey);
        user.sub.password=null;
        user.sub.salt=null;
        user.sub.authenticated = true;
        res.status(200).send(user.sub);

    }

     static currentUser (req){
        let token;
        let user;

        token = req.header("Authorization").replace("Bearer ","");
        user =  jwt.decode(token,config[this.env].privateKey);

        return user.sub;
    }



}
