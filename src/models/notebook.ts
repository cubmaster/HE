import  { Schema, Document } from 'mongoose';
import * as mongoose from "mongoose";



export interface INotebook extends Document {
    name:string,
    nodes:[],
    links:[],
    classname:string
}




const NotebookSchema = new Schema({
    name:  { type: String, required: true },
    nodes:[],
    links:[],
    classname: {type:String,default: "notebook"}
    });


export default () => { mongoose.model<INotebook>('notebook', NotebookSchema);}
