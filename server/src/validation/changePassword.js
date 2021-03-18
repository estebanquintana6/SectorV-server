const Validator = require("validator");
const isEmpty = require("is-empty");

module.exports = function validateChangePassword(data) {
  let errors = {};
  // Convert empty fields to an empty string so we can use validator functions

  data.password = !isEmpty(data.password) ? data.password : "";
  data.confirmPassword = !isEmpty(data.confirmPassword) ? data.confirmPassword : "";

  // Password checks
  if (Validator.isEmpty(data.password)) {
    errors.password = "Se requiere una contraseña";
  }

  if (Validator.isEmpty(data.confirmPassword)) {
    errors.password = "Se requiere confirmar la contraseña";
  }

  if (!Validator.isLength(data.password, { min: 6, max: 30 })) {
    errors.password = "La contraseña debe tener al menos 6 caracteres";
  }

  if (!Validator.equals(data.password, data.confirmPassword)) {
    errors.password = "Las contraseñas deben coincidir";
  }

  return {
    errors,
    isValid: isEmpty(errors)
  };
};