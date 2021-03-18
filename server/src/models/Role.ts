import mongoose from "mongoose";
const { Schema } = mongoose;

// schema
const RoleSchema = new Schema({
  name: {
    type: String,
    required: true
  },
}, {
  collection: 'Roles'
});

const Roles = mongoose.model('Roles', RoleSchema);

export default Roles;
