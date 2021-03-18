import mongoose from "mongoose";
const { Schema } = mongoose;

// Create Schema
const UserSchema = new Schema({
  name: {
    type: String,
    required: true,
  },
  last_name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: false,
    lowercase: true
  },
  telephone: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true
  },
  created_at: {
    type: Date,
    default: Date.now
  },
  role: {
    type: Schema.Types.ObjectId,
    ref: 'Roles',
    required: true
  }
});

const Users = mongoose.model('users', UserSchema);

export default Users;
