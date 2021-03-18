const Validator = require("validator");

const isEmpty = (obj: any) : boolean => Object.keys(obj).length == 0;

export default function validateLoginInput(data: any) {
  const errors = Object.create(null);

  // Convert empty fields to an empty string so we can use validator functions
  data.email = data.email ? data.email : "";
  data.telephone = data.telephone ? data.telephone : "";
  data.password = data.password ? data.password : "";

  // Email checks
  if (Validator.isEmpty(data.email) && Validator.isEmpty(data.telephone) ) {
    errors.email = "Se requiere el email o telefono";
  } else if (!Validator.isEmpty(data.email) && !Validator.isEmail(data.email)) {
    errors.email = "El email no es válido";
  }
  // Password checks
  if (Validator.isEmpty(data.password)) {
    errors.password = "Se requiere una contraseña";
  }

  return {
    errors,
    isValid: isEmpty(errors)
  };
};