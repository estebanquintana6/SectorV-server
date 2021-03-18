"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const Validator = require("validator");
const isEmpty = (obj) => Object.keys(obj).length == 0;
function validateRegisterInput(data) {
    const errors = Object.create(null);
    // Convert empty fields to an empty string so we can use validator functions
    data.role = data.role ? data.role : "";
    data.name = data.name ? data.name : "";
    data.email = data.email ? data.email : "";
    data.last_name = data.last_name ? data.last_name : "";
    data.password = data.password ? data.password : "";
    data.passwordConfirmation = data.passwordConfirmation ? data.passwordConfirmation : "";
    // Name checks
    if (Validator.isEmpty(data.name)) {
        errors.name = "Se requiere un nombre.";
    }
    if (Validator.isEmpty(data.last_name)) {
        errors.last_name = "Se require el campo de apellido.";
    }
    // Email checks
    if (Validator.isEmpty(data.email)) {
        errors.email = "Email es requerido.";
    }
    else if (!Validator.isEmail(data.email)) {
        errors.email = "El email no es valido.";
    }
    // Password checks
    if (Validator.isEmpty(data.password)) {
        errors.password = "El campo de contraseña es requerido.";
    }
    if (!Validator.isLength(data.password, { min: 6, max: 30 })) {
        errors.password = "La contraseña debe tener al menos 6 caracteres";
    }
    if (!Validator.equals(data.password, data.passwordConfirmation)) {
        errors.passwordConfirmation = "Las contraseñas deben coincidir";
    }
    console.log(isEmpty(errors));
    return {
        errors,
        isValid: isEmpty(errors)
    };
}
exports.default = validateRegisterInput;
;
