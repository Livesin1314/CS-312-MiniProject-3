/*Having the enviroment varaibles from the .env files*/
require("dotenv").config();
//import the pool from the pg package to use postgresql
const { Pool } = require("pg");
//create the connectiono pool to manage the database
const pool = new Pool({
   //get the username from .env
   user: process.env.DB_USER, 
   //get the database from the .env
   host: process.env.DB_HOTS, 
   //get the name of the database from .env
   database: process.env.DB_NAME,
   //get the password from the database from .env
   password: process.env.DB_PASSWORD,
   //get the databse prot from the .env file and get a number
   port: Number(process.env.DB_PORT)
});
//export the connection pool so it can be used
module.exports = pool;