"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const mongoose_1 = __importDefault(require("mongoose"));
const Schema = mongoose_1.default.Schema;
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
const Users = mongoose_1.default.model('users', UserSchema);
exports.default = Users;
