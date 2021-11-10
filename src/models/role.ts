

import mongoose, { model, Schema, Document } from 'mongoose';

export interface IRole extends Document {
    Name: string;
    Right: string;

}

const RoleSchema: Schema = new Schema({
    Name: { type: String, required: true },
    Right: {type: String, enum: ['Read.', 'Write', 'Edit', 'Submit']}
});

export default () =>  mongoose.model<IRole>('role', RoleSchema);
