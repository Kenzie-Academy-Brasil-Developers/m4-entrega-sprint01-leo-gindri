import express, { json, request, response } from "express";
import users from "./database.js";
import { v4 as uuidv4 } from "uuid";
import { hash, compare } from "bcryptjs";
import jwt from "jsonwebtoken";
import "dotenv/config";

const app = express();
app.use(express.json());

const ensureAuthMiddleware = (request, response, next) => {
  let authorization = request.headers.authorization;

  if (!authorization) {
    return response.status(401).json({
      message: "Invalid Token",
    });
  }

  const data = request.body;

  authorization = authorization.split(" ")[1];

  return jwt.verify(authorization, process.env.SECRET_KEY, (error, decoded) => {
    if (error) {
      return response.status(401).json({
        message: "Invalid token.",
      });
    }

    request.user = {
      id: decoded.sub,
    };

    return next();
  });
};

const admAuthMiddleware = (request, response, next) => {
  const id = request.user.id;
  const userIsAdm = users.find((el) => el.uuid === id);
  console.log(userIsAdm);
  if (!userIsAdm.isAdm) {
    return response.status(403).json({
      message: "You do not have administrator permissions.",
    });
  }

  return next();
};

const editAuthenticationMiddleware = (request, response, next) => {
  const userId = request.user.id;

  const id = request.params.id;
  const user = users.find((el) => el.uuid === userId);

  if (user.uuid === id || user.isAdm === true) {
    return next();
  }

  return response.status(403).json({
    message: "Missing admin permissions",
  });
};

const deleteAuthenticaitonMiddleware = (request, response, next) => {
  const userId = request.user.id;
  const user = users.find((el) => el.uuid === userId);

  if (userId === request.params.id || user.isAdm === true) {
    return next();
  }

  return response.status(403).json({
    message: "Missing authorization headers",
  });
};

// .
// .
// .
// .
// .
// ..
// .
// .

const createSessionService = async ({ email, password }) => {
  const user = users.find((el) => el.email === email);

  if (!user) {
    return [
      401,
      {
        message: "Wrong e-mail or password",
      },
    ];
  }

  const passwordMatch = await compare(password, user.password);

  if (!passwordMatch) {
    return [
      401,
      {
        message: "Wrong email/password",
      },
    ];
  }

  const token = jwt.sign({}, process.env.SECRET_KEY, {
    expiresIn: "24h",
    subject: user.uuid,
  });

  return [200, { token }];
};

const createUserService = async (userData) => {
  const userAlreadyExist = users.find((el) => el.email === userData.email);

  if (userAlreadyExist) {
    return [
      409,
      {
        message: "E-mail Already registered",
      },
    ];
  }

  const newUser = {
    uuid: uuidv4(),
    ...userData,
    createdOn: new Date(),
    updatedOn: new Date(),
    password: await hash(userData.password, 10),
  };

  users.push(newUser);

  return [201, { ...newUser, password: undefined }];
};

const listUsersService = (data) => {
  return [200, users];
};

const listProfileUserService = (data) => {
  const id = data.user.id;
  const userProfile = users.find((el) => el.uuid === id);

  const user = {
    uuid: userProfile.uuid,
    createdOn: userProfile.createdOn,
    updatedOn: userProfile.updatedOn,
    name: userProfile.name,
    email: userProfile.email,
    password: undefined,
    isAdm: userProfile.isAdm,
  };

  return [200, user];
};

const editUsersService = async (data, req) => {
  const userId = req.user.id;
  const user = users.find((el) => el.uuid === userId);

  const updatedData = {
    ...user,
    updatedOn: `${new Date()}`,
    password:
      data.password == undefined
        ? user.password
        : await hash(data.password, 10),
    name: data.name == undefined ? user.name : data.name,
    email: data.email == undefined ? user.email : data.email,
  };

  return [200, { ...updatedData, password: undefined }];
};

const deleteUsersService = (req) => {
  users.splice(req.params.id, 1);

  return [204, {}];
};
// .
// .
// .
// .
// .
// .
// .
// .
// .
// .
const createSessionController = async (request, response) => {
  const data = request.body;
  const [status, loginData] = await createSessionService(data);
  return response.status(status).json(loginData);
};

const createUserController = async (request, response) => {
  const userData = request.body;
  const [status, user] = await createUserService(userData);
  return response.status(status).json(user);
};

const listUsersController = (request, response) => {
  const fullData = request;
  const [status, list] = listUsersService(fullData);
  return response.status(status).json(list);
};

const listProfileUserController = (request, response) => {
  const fullData = request;
  const [status, user] = listProfileUserService(fullData);
  return response.status(status).json(user);
};

const editUsersController = async (request, response) => {
  const data = request.body;
  const fullData = request;
  const [status, newData] = await editUsersService(data, fullData);
  return response.status(status).json(newData);
};

const deleteUsersCotroller = (request, response) => {
  const fullData = request;
  const [status, data] = deleteUsersService(fullData);
  return response.status(status).json(data);
};

app.post("/users", createUserController);
app.get("/users", ensureAuthMiddleware, admAuthMiddleware, listUsersController);
app.post("/login", createSessionController);
app.get(`/users/profile`, ensureAuthMiddleware, listProfileUserController);
app.patch(
  "/users/:id",
  ensureAuthMiddleware,
  editAuthenticationMiddleware,
  editUsersController
);
app.delete(
  "/users/:id",
  ensureAuthMiddleware,
  deleteAuthenticaitonMiddleware,
  deleteUsersCotroller
);

app.listen(process.env.PORT);

export default app;
