import crypto from "crypto";

export class encryption {
    static createSalt() {
        return crypto.randomBytes(128).toString('base64');
    }

    static  hashPwd(salt:string, pwd:string) {
        let hmac = crypto.createHmac('sha256', salt);
        return hmac.update(pwd).digest('hex');
    }


}

