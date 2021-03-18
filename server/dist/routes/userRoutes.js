"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const config_1 = require("../config/config");
// Load input validation
const register_1 = __importDefault(require("../validation/register"));
const login_1 = __importDefault(require("../validation/login"));
// for the future
// const validateChangePassword = require("../validation/changePassword");
const router = express_1.Router();
// Load User model
const User_1 = __importDefault(require("../models/User"));
const Role_1 = __importDefault(require("../models/Role"));
// Load utils
const userToJWTPayload_1 = require("../utils/userToJWTPayload");
/**
 * @route POST api/users/register
 * @desc Registers user
 * @params name, last_name, email, telephone, password, code (Campus Code), role (Role name)
 * @access Public
 */
router.post("/register", (req, res) => {
    // Form validation
    const { errors, isValid } = register_1.default(req.body);
    // Check validation
    if (!isValid) {
        return res.status(400).json(errors);
    }
    const { name, last_name, email, telephone, password, } = req.body;
    let { role } = req.body;
    if (!role)
        role = 'USUARIO';
    Role_1.default.findOne({ name: role }).then(role => {
        User_1.default.findOne({ $or: [{ email }, { telephone }] }).populate('role').then(user => {
            if (user) {
                return res.status(400).json({ email: "Ya existe un usuario con ese email o teléfono" });
            }
            else {
                const newUser = new User_1.default({
                    name,
                    last_name,
                    email,
                    password,
                    role: role._id,
                    telephone,
                });
                // Hash password before saving in database
                bcryptjs_1.default.genSalt(10, (err, salt) => {
                    bcryptjs_1.default.hash(newUser.get('password'), salt, (err, hash) => {
                        if (err)
                            throw err;
                        newUser.set('password', hash);
                        User_1.default.create(newUser)
                            .then(user => {
                            return res.json(user);
                        })
                            .catch(err => {
                            console.log('ERR', err);
                            res.status(500);
                        });
                    });
                });
            }
        });
    });
});
/**
 * @route POST api/users/login
 * @desc Retrieves user JWT, so we can store user data by decrypting the JWT in the frontend
 * @params email, password
 * @access Public
 */
router.post("/login", (req, res) => {
    // Form validation
    const { errors, isValid } = login_1.default(req.body);
    // Check validation
    if (!isValid) {
        return res.status(400).json(errors);
    }
    const { email, password, telephone } = req.body;
    // Find user by email
    User_1.default.findOne({ $or: [{ email }, { telephone }] }).populate('role').then((user) => {
        // Check if user exists
        if (!user) {
            return res.status(404).json({ emailnotfound: "El email no existe" });
        }
        // Check password
        bcryptjs_1.default.compare(password, user.password).then((isMatch) => {
            if (isMatch) {
                // User matched
                // Create JWT Payload
                const payload = userToJWTPayload_1.transformUserToPayload(user._doc);
                // Sign token
                jsonwebtoken_1.default.sign(payload, config_1.secretKey, {
                    expiresIn: 86400 // 1 year in seconds
                }, (err, token) => {
                    res.json({
                        success: true,
                        token
                    });
                });
            }
            else {
                return res
                    .status(400)
                    .json({ passwordincorrect: "Contraseña incorrecta" });
            }
        });
    });
});
/**
 * @route GET api/users/list
 * @desc Retrieves user JWT, so we can store user data by decrypting the JWT in the frontend
 * @params JWT token
 * @access Only authenticated users
 */
router.get("/list", (req, res) => {
    const headers = req.headers;
    const token = headers.authorization.split(' ')[1];
    if (!token)
        return res.status(404).json();
    jsonwebtoken_1.default.verify(token, config_1.secretKey, function (err, decoded) {
        if (err)
            res.status(401).json(err);
        const role = decoded.role.name;
    });
});
/**
 * @route POST api/users/changeRole
 * @desc Searches for the desired role and if
 * exists and the user requesting the action is
 * an admin, the new role is assigned to that user.
 * @params
 * token: JWT token,
 * id: userId of the user to change,
 * role: new role name to assign
 * @access Only admin users
 */
router.post("/changeRole", (req, res) => {
    const body = req.body;
    const headers = req.headers;
    const token = headers.authorization.split(' ')[1];
    const userId = body.id;
    const newRole = body.role;
    Role_1.default.findOne({ name: newRole }).then((fetchedRole) => {
        if (!fetchedRole) {
            return res.status(404).json({ error: "Role not found" });
        }
        jsonwebtoken_1.default.verify(token, config_1.secretKey, function (err, decoded) {
            if (err)
                res.status(401);
            const role = decoded.role.name;
            const allowedRoles = ['SUPERADMIN', 'ADMIN'];
            // only admins and superadmins can change role
            if (allowedRoles.includes(role)) {
                User_1.default.findOneAndUpdate({ _id: userId }, { role: fetchedRole }).then((err) => {
                    if (err)
                        res.status(304).json({ message: "El rol no se modifico" });
                    res.status(200).json({ message: "Rol modificado" });
                });
            }
            else {
                res.status(401).json({ message: 'Forbidden' });
            }
        });
    });
});
exports.default = router;
