export const transformUserToPayload = (user: any) : Object => {
  const obj = Object.create(null);
  Object.keys(user).forEach(key => {
    obj[key] = user[key]
  })
  return obj
}