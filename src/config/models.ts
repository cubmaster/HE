import fs from 'fs'
import path from 'path'
import notebook from "../models/notebook";
import role from "../models/role";
import user from "../models/user";
import codeSnipit from "../models/codeSnipit";



export function initModules(){
    notebook();
    user();
    role();
    codeSnipit();

}
