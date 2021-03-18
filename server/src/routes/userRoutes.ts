import { Router, Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import { secretKey } from '../config/config';

// Load input validation
import validateRegisterInput from "../validation/register";
import validateLoginInput from "../validation/login";
// for the future
// const validateChangePassword = require("../validation/changePassword");

const router = Router();

// Load User model
import User from "../models/User";
import Role from "../models/Role";

// Load utils
import { transformUserToPayload } from '../utils/userToJWTPayload';


/**
 * @route POST api/users/register
 * @desc Registers user
 * @params name, last_name, email, telephone, password, code (Campus Code), role (Role name)
 * @access Public
 */
router.post("/register", (req: Request, res: Response) => {
    // Form validation
    const { errors, isValid } = validateRegisterInput(req.body);
    // Check validation
    if (!isValid) {
        return res.status(400).json(errors);
    }

    const {
        name,
        last_name,
        email,
        telephone,
        password,
    } = req.body;

    let {
        role
    } = req.body;

    if (!role) role = 'USUARIO';

    Role.findOne({ name: role }).then(role => {
        User.findOne({ $or: [{ email }, { telephone }] }).populate('role').then(user => {
            if (user) {
                return res.status(400).json({ email: "Ya existe un usuario con ese email o teléfono" });
            } else {

                const newUser = new User({
                    name,
                    last_name,
                    email,
                    password,
                    role: role._id,
                    telephone,
                });

                // Hash password before saving in database
                bcrypt.genSalt(10, (err, salt) => {
                    bcrypt.hash(newUser.get('password'), salt, (err, hash) => {
                        if (err) throw err;
                        newUser.set('password', hash);
                        User.create(newUser)
                            .then(user => {
                                return res.json(user)
                            })
                            .catch(err => {
                                console.log('ERR', err);
                                res.status(500)
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
router.post("/login", (req: Request, res: Response) => {
    // Form validation
    const { errors, isValid } = validateLoginInput(req.body);

    // Check validation
    if (!isValid) {
        return res.status(400).json(errors);
    }

    const { email, password, telephone } = req.body

    // Find user by email
    User.findOne({ $or: [{ email }, { telephone }] }).populate('role').then((user: any) => {
        // Check if user exists
        if (!user) {
            return res.status(404).json({ emailnotfound: "El email no existe" });
        }
        // Check password
        bcrypt.compare(password, user.password).then((isMatch: boolean) => {
            if (isMatch) {
                // User matched

                // Create JWT Payload
                const payload = transformUserToPayload(user._doc)

                // Sign token
                jwt.sign(payload, secretKey,
                    {
                        expiresIn: 86400 // 1 year in seconds
                    },
                    (err: Error, token: String) => {
                        res.json({
                            success: true,
                            token
                        });
                    }
                );
            } else {
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
router.get("/list", (req: Request, res: Response) => {
    const headers = req.headers
    const token = headers.authorization.split(' ')[1];
    if (!token) return res.status(404).json()
    jwt.verify(token, secretKey, function (err: any, decoded: any) {
        if (err) res.status(401).json(err);
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
router.post("/changeRole", (req: Request, res: Response) => {
    const body = req.body;
    const headers = req.headers
    const token = headers.authorization.split(' ')[1];
    const userId = body.id;
    const newRole = body.role;

    Role.findOne({ name: newRole }).then((fetchedRole: any) => {
        if (!fetchedRole) {
            return res.status(404).json({ error: "Role not found" });
        }
        jwt.verify(token, secretKey, function (err: Error, decoded: any) {
            if (err) res.status(401);
            const role = decoded.role.name;
            const allowedRoles = ['SUPERADMIN', 'ADMIN']
            // only admins and superadmins can change role
            if (allowedRoles.includes(role)) {
                User.findOneAndUpdate({ _id: userId }, { role: fetchedRole }).then((err) => {
                    if (err) res.status(304).json({ message: "El rol no se modifico" })
                    res.status(200).json({ message: "Rol modificado" });
                });
            } else {
                res.status(401).json({ message: 'Forbidden' })
            }
        });
    })
});

export default router;
