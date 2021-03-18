import Role from "../models/Role";


const createRole = async (name: string) => {
  return Role.findOne({ name }).then(async (exist) => {
    if (exist) return exist;

    const role = new Role({ name });
    const roleResponse = await role.save();
    if(roleResponse.id != null) console.log("ROLE CREATED:", roleResponse.get('name'))
    return roleResponse
  })
}

export const initializeDb = async () => {
  await createRole('SUPERADMIN');
  await createRole('ADMIN')
  await createRole('USUARIO')

  console.log("hello");
}