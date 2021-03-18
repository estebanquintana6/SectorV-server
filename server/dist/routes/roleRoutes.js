"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
// Schema
const Role_1 = __importDefault(require("../models/Role"));
const config_1 = require("../config/config");
const router = express_1.Router();
/**
 * @route GET api/roles/
 * @desc Fetches all the available roles
 * @params token: JWT token
 * @access Authenticated users
 */
router.get("/", (req, res) => {
    const headers = req.headers;
    const token = headers.authorization.split(' ')[1];
    jsonwebtoken_1.default.verify(token, config_1.secretKey, function (err, decoded) {
        if (err)
            res.status(401).json(err);
        const role = decoded.role.name;
        const allowedRoles = ['ADMIN', 'SUPERADMIN'];
        if (allowedRoles.includes(role)) {
            Role_1.default.find().then((roles) => {
                res.status(200).json(roles);
            });
        }
        else {
            return res.status(401).json({ message: 'Forbidden' });
        }
    });
});
exports.default = router;
