"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.transformUserToPayload = void 0;
const transformUserToPayload = (user) => {
    const obj = Object.create(null);
    Object.keys(user).forEach(key => {
        obj[key] = user[key];
    });
    return obj;
};
exports.transformUserToPayload = transformUserToPayload;
