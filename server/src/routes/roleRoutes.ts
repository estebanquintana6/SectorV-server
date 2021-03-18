import { Router, Request, Response } from "express";
import jwt from "jsonwebtoken";

// Schema
import Roles from '../models/Role';

import { secretKey } from '../config/config';

const router = Router();

/**
 * @route GET api/roles/
 * @desc Fetches all the available roles
 * @params token: JWT token
 * @access Authenticated users
 */
router.get("/", (req: Request, res: Response) => {
    const headers = req.headers
    const token = headers.authorization.split(' ')[1];

    jwt.verify(token, secretKey, function (err: Error, decoded: any) {
        if (err) res.status(401).json(err);
        const role = decoded.role.name;
        const allowedRoles = ['ADMIN', 'SUPERADMIN']
        if (allowedRoles.includes(role)) {
            Roles.find().then((roles: any) => {
                res.status(200).json(roles);
            });

        } else {
            return res.status(401).json({ message: 'Forbidden' });
        }
    });
});


export default router;
