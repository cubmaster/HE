

import * as  encrypt  from '../utilities/encryption';
import mongoose, {  Schema, Model, Document } from 'mongoose';
export interface IUser extends Document {
    email: string
    firstName: string,
    lastName: string,
    username: string,
    salt: string,
    password:string,
    roles: [string],
    auth: any,
    profileImage: {
        fieldName: string,
        originalName: string,
        encoding: string,
        mimetype: string,
        buffer: string,
        size: number
    }
}
 export const UserSchema: Schema = new Schema({
            email: {type: String},
            firstName: {type: String},
            lastName: {type: String},
            username: {
                type: String,
                required: '{PATH} is required!',
                unique: true
            },
            salt: {type: String},
            password: {type: String},
            roles: [{type: String}],
            auth: {type: mongoose.Schema.Types.Mixed},
            profileImage: {
                fieldName: String,
                originalName: String,
                encoding: String,
                mimetype: String,
                buffer: String,
                size: Number
            }
        });

       // this.userSchema.methods = {
       //     authenticate: function (passwordToMatch,cb) {
//
//
       //         return cb(null,encrypt.encryption.hashPwd(this.salt, passwordToMatch) === this.password);
       //     },
       //     hasRole: function (role) {
       //         return this.roles.indexOf(role) > -1;
       //
       //
       //     }
//
       // };

export default () =>  mongoose.model<IUser>('user', UserSchema);
