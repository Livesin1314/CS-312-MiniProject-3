// Importing the framework and required packages to the file
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const pool = require("./db");
// Creating the application and port number
const app = express();
const PORT = 3000;
// Set the view engine
app.set("view engine", "ejs");
// Setting the middleware for reading form data and serving CSS
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
// Set up sessions so the application remembers signed-in users
app.use(
    session({
        //A secret from the .env file to sign the seesion cookie
        secret: process.env.SESSION_SECRET,
        //making sure it doesn't save the session if nothing changed
        resave: false,
        saveUninitialized: false,
        cookie: {
            //preventing the javascript in the browser from reading the cookies
            httpOnly: true,
            //using the false for local develpment over http
            secure: false, 
            //protecting against corss site request
            sameSite: "lax",
            //setting the sessiono cookies to the last 2 hours
            maxAge: 1000 * 60 * 60 * 2 
        }
    })
);
// Making the signed-in user available to every EJS page
app.use((req, res, next) => {
    //checking if the singed in user is available or setting it to null if not
    res.locals.currentUser = req.session.user || null;
    //continue to the next
    next();
});
// Checking whether a user is signed in before allowing certain actions
function requireLogin(req, res, next) {
    //check if the session contains a signed in user
    if (!req.session.user) {
        //if true, send teh user to the sign in page
        return res.redirect("/signin");
    }
    //go to the next
    next();
}
// Display all blog posts from the database
app.get("/", async (req, res) => {
    try {
        //get the blog post from teh postgresql
        const result = await pool.query(`
            SELECT
                blog_id AS id,
                creator_name AS creator,
                creator_user_id,
                title,
                body AS content,
                date_created AS date
            FROM blogs
            ORDER BY date_created DESC
        `);
        //have the blog show and make sure the blog appears in newest to oldest
        res.render("index", {
            posts: result.rows,
            error: null
        });
        //check for error
    } catch (error) {
        //if an error, print the databse error
        console.error("Error loading blog posts:", error.message);
        //send the error response 
        res.status(500).send("Unable to load blog posts.");
    }
});
// Display the signup page
app.get("/signup", (req, res) => {
    //render the signup.ejs adn print error message
    res.render("signup", { error: null });
});
// Register a new user
app.post("/signup", async (req, res) => {
    //get the information for name, user, and password
    const { user_id, name, password } = req.body;

    // Check if that all required fields were provided
    if (!user_id || !name || !password) {
        //return the signup page with an error if an error occurs
        return res.status(400).render("signup", {
            error: "Please fill in every field."
        });
    }
    //make sure the password is up to 72 bytes adn reject logner passwords
    if (Buffer.byteLength(password, "utf8") > 72) {
        //if true, print error message of too long password
        return res.status(400).render("signup", {
            error: "Your password must be no longer than 72 bytes."
        });
    }
    try {
        // Check whether the username is already registered
        const existingUser = await pool.query(
            "SELECT user_id FROM users WHERE user_id = $1",
            [user_id]
        );
        //check if the username alreay exists and pritn error message
        if (existingUser.rows.length > 0) {
            return res.status(409).render("signup", {
                error: "That username is already taken."
            });
        }
        // Hash the password before saving it to the database
        const hashedPassword = await bcrypt.hash(password, 10);
        //Put the new user into PostgreSQL
        await pool.query(
            `INSERT INTO users (user_id, password, name)
             VALUES ($1, $2, $3)`,
            [user_id, hashedPassword, name]
        );
        // Take the user to the signin page after signingup
        res.redirect("/signin?registered=1");
        //checking for erorrs and printing message
    } catch (error) {
        console.error("Signup error:", error.message);
        // Handle a duplicate username error if another request registered it
        if (error.code === "23505") {
            return res.status(409).render("signup", {
                error: "That username is already taken."
            });
        }
        //show the general error if failure of creationo
        res.status(500).render("signup", {
            error: "Unable to create your account. Please try again."
        });
    }
});
// Display the signin page
app.get("/signin", (req, res) => {
    //show the sigin page adn checking if the user is registered
    res.render("signin", {
        error: null,
        registered: req.query.registered === "1"
    });
});
// Sign in an existing user
app.post("/signin", async (req, res) => {
    //get the usernaem and passowrd through the signin page
    const { user_id, password } = req.body;
    //check if the fields have been fileld
    if (!user_id || !password) {
        //if true, produce error message
        return res.status(400).render("signin", {
            error: "Enter your username and password.",
            registered: false
        });
    }
    try {
        // Find the user by username and sotre the password and username
        const result = await pool.query(
            "SELECT user_id, password, name FROM users WHERE user_id = $1",
            [user_id]
        );
        //get the matchign user from teh query
        const user = result.rows[0];
        // Reject an unknown username if it doens't exist
        if (!user) {
            return res.status(401).render("signin", {
                error: "Invalid username or password.",
                registered: false
            });
        }
        // Compare the entered password with the stored hash
        const passwordMatches = await bcrypt.compare(
            password,
            user.password
        );
        //checking if the password matches 
        if (!passwordMatches) {
            //if true, pritn error message
            return res.status(401).render("signin", {
                error: "Invalid username or password.",
                registered: false
            });
        }

        // Creating a fresh session after successful authentication
        req.session.regenerate((error) => {
            //check if an error occurs
            if (error) {
                console.error("Session error:", error.message);
                return res.status(500).send("Unable to sign in.");
            }
            // Store only the user's public account details in the session
            req.session.user = {
                user_id: user.user_id,
                name: user.name
            };
            //send the signed in user to the homepage after signing in
            res.redirect("/");
        });
        //check for erros
    } catch (error) {
        console.error("Signin error:", error.message);
        res.status(500).render("signin", {
            error: "Unable to sign in. Please try again.",
            registered: false
        });
    }
});
// Sign out the current user
app.post("/logout", (req, res) => {
    //get rid of teh session so the user is signed out
    req.session.destroy((error) => {
        if (error) {
            console.error("Logout error:", error.message);
            return res.status(500).send("Unable to sign out.");
        }
        //remove the cookies
        res.clearCookie("connect.sid");
        //send the user tot eh home page after signing out
        res.redirect("/");
    });
});
// Create a blog post
//checking if the user is signed in
app.post("/posts", requireLogin, async (req, res) => {
    //getting the post title adn content
    const { title, content } = req.body;
    //checking if the content exists and not empty
    if (!title || !title.trim() || !content || !content.trim()) {
        return res.status(400).send("A title and post content are required.");
    }
    
    try {
        // Get the signed-in user's account instead of trusting form input
        const user = req.session.user;
        //put the new blogs into the table
        await pool.query(
            `INSERT INTO blogs
                (creator_name, creator_user_id, title, body)
             VALUES ($1, $2, $3, $4)`,
            [user.name, user.user_id, title.trim(), content.trim()]
        );
        //send the user to the hopme page 
        res.redirect("/");
        //check for error
    } catch (error) {
        console.error("Create post error:", error.message);
        res.status(500).send("Unable to create the post.");
    }
});

// Display the edit page only if the signed-in user owns the post
app.get("/posts/:id/edit", requireLogin, async (req, res) => {
    try {
        //find the post by the id and make sure they match
        const result = await pool.query(
            `SELECT
                blog_id AS id,
                creator_name AS creator,
                creator_user_id,
                title,
                body AS content,
                date_created AS date
             FROM blogs
             WHERE blog_id = $1 AND creator_user_id = $2`,
            [req.params.id, req.session.user.user_id]
        );
        //get the matching post from teh query
        const post = result.rows[0];
        //check if the post exist or the user owns it
        if (!post) {
            return res.status(404).send("Post not found or you do not own it.");
        }
        //show edit.ejs
        res.render("edit", { post: post });
        //check for error
    } catch (error) {
        console.error("Load edit page error:", error.message);
        res.status(500).send("Unable to load the edit page.");
    }
});
// Update a post only if the signed-in user owns it
app.post("/posts/:id/edit", requireLogin, async (req, res) => {
    //get the content of the blog from edit
    const { title, content } = req.body;
    //checking if teh updated content is not empty
    if (!title || !title.trim() || !content || !content.trim()) {
        return res.status(400).send("A title and post content are required.");
    }
    try {
        //have the updated content match the user id
        const result = await pool.query(
            `UPDATE blogs
             SET title = $1, body = $2
             WHERE blog_id = $3 AND creator_user_id = $4
             RETURNING blog_id`,
            [
                //save the title
                title.trim(),
                //save teh content
                content.trim(),
                //get the id
                req.params.id,
                //get teh signed in user's account id
                req.session.user.user_id
            ]
        );
        //check if no row was updated or the post wans't found
        if (result.rows.length === 0) {
            return res.status(404).send("Post not found or you do not own it.");
        }
        //return to the homepage
        res.redirect("/");
        //check for errors
    } catch (error) {
        console.error("Update post error:", error.message);
        res.status(500).send("Unable to update the post.");
    }
});

// Delete a post only if the signed-in user owns it
app.post("/posts/:id/delete", requireLogin, async (req, res) => {
    try {
        //have the delted post when the ids match
        const result = await pool.query(
            `DELETE FROM blogs
             WHERE blog_id = $1 AND creator_user_id = $2
             RETURNING blog_id`,
            [req.params.id, req.session.user.user_id]
        );
        //check if no rows were deleted or not found
        if (result.rows.length === 0) {
            return res.status(404).send("Post not found or you do not own it.");
        }
        //send back to the homepage
        res.redirect("/");
        //check for errors
    } catch (error) {
        console.error("Delete post error:", error.message);
        res.status(500).send("Unable to delete the post.");
    }
});
// Start server and listen for port 3000
app.listen(PORT, () => {
    //have the server display messge if success
    console.log(`Server running at http://localhost:${PORT}`);
});