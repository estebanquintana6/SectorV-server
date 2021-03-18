// requiring libraries
import express from "express";
import mongoose from "mongoose";
import bodyParser from "body-parser";
import passport from "passport";
import cors from "cors";

const {
    MONGO_USER,
    MONGO_PSWD,
    MONGO_URI,
    MONGO_PORT,
    MONGO_DB,
    MONGO_AUTH_DB
} = process.env;

// Setting up modules and dependencies
const app = express();
// we need to make ${MONGO_DB} change when running tests
const mongoUri = `mongodb://${MONGO_USER}:${MONGO_PSWD}@${MONGO_URI}:${MONGO_PORT}/${MONGO_DB}?authSource=${MONGO_AUTH_DB}`;
import { initializeDb } from "./utils/seeds";
// Import other routes for entities
import users from './routes/userRoutes';
import roles from './routes/roleRoutes';

// Cors
app.use(cors());

// Bodyparser middleware
app.use(
    bodyParser.urlencoded({
        extended: false
    })
);
app.use(bodyParser.json());

// DB Config
const options = {
    useNewUrlParser: true
};

// Function to connect to the database
const conn = () => {
    mongoose.connect(mongoUri, options);
};
// Call it to connect
conn();

// Handle the database connection and retry as needed
const db = mongoose.connection;
db.on("error", (err: Error) => {
    console.log("There was a problem connecting to mongo: ", err);
    console.log("Trying again");
    setTimeout(() => conn(), 5000);
});
db.once("open", async () => {
    if (process.env.NODE_ENV === 'development') {
        await initializeDb();
    }
    console.log("Successfully connected to mongo");
});

// Passport middleware
app.use(passport.initialize());

// Routes

// app.get("/", express.static("public"));
app.get("/", (req: any, res: any) => {
    res.send({ hey: 'que tengas buen día' })
});
app.use('/api/users', users);
app.use('/api/roles', roles);

const port = process.env.PORT || 4000;

app.listen(port, () => console.log(`Server up and running on port ${port} in env ${process.env.NODE_ENV} !`));

module.exports = app; // For testing