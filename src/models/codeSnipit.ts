import  { Schema, Document } from 'mongoose';
import * as mongoose from "mongoose";



export interface ICodeSnipit extends Document {
    name:string,
    inputs:[],
    outputs:[],
    code:string;
    classname: string;

}




const SnipitSchema = new Schema({
    name:  { type: String, required: true },
    inputs:[],
    outputs:[],
    code: String,
    classname: {type:String,default:'snipit'}
});


export default () => { mongoose.model<ICodeSnipit>('codesnipit', SnipitSchema);}
