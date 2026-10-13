/*
This application manages a blog using Express, EJS, and PostgreSQL.
Users can sign up, sign in, create posts, and manage their own posts.
*/

// Importing the framework and required packages
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
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: false, // Use false for local development over HTTP
            sameSite: "lax",
            maxAge: 1000 * 60 * 60 * 2 // Session lasts up to two hours
        }
    })
);

// Make the signed-in user available to every EJS page
app.use((req, res, next) => {
    res.locals.currentUser = req.session.user || null;
    next();
});

// Check whether a user is signed in before allowing certain actions
function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.redirect("/signin");
    }

    next();
}

// Display all blog posts from the database
app.get("/", async (req, res) => {
    try {
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

        res.render("index", {
            posts: result.rows,
            error: null
        });
    } catch (error) {
        console.error("Error loading blog posts:", error.message);
        res.status(500).send("Unable to load blog posts.");
    }
});

// Display the signup page
app.get("/signup", (req, res) => {
    res.render("signup", { error: null });
});

// Register a new user
app.post("/signup", async (req, res) => {
    const { user_id, name, password } = req.body;

    // Check that all required fields were provided
    if (!user_id || !name || !password) {
        return res.status(400).render("signup", {
            error: "Please fill in every field."
        });
    }

    // bcrypt supports passwords up to 72 bytes
    if (Buffer.byteLength(password, "utf8") > 72) {
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

        if (existingUser.rows.length > 0) {
            return res.status(409).render("signup", {
                error: "That username is already taken."
            });
        }

        // Hash the password before saving it
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the new user into PostgreSQL
        await pool.query(
            `INSERT INTO users (user_id, password, name)
             VALUES ($1, $2, $3)`,
            [user_id, hashedPassword, name]
        );

        // Send the new user to the signin page
        res.redirect("/signin?registered=1");
    } catch (error) {
        console.error("Signup error:", error.message);

        // Handle a duplicate username if another request registered it
        if (error.code === "23505") {
            return res.status(409).render("signup", {
                error: "That username is already taken."
            });
        }

        res.status(500).render("signup", {
            error: "Unable to create your account. Please try again."
        });
    }
});

// Display the signin page
app.get("/signin", (req, res) => {
    res.render("signin", {
        error: null,
        registered: req.query.registered === "1"
    });
});

// Sign in an existing user
app.post("/signin", async (req, res) => {
    const { user_id, password } = req.body;

    if (!user_id || !password) {
        return res.status(400).render("signin", {
            error: "Enter your username and password.",
            registered: false
        });
    }

    try {
        // Find the user by username
        const result = await pool.query(
            "SELECT user_id, password, name FROM users WHERE user_id = $1",
            [user_id]
        );

        const user = result.rows[0];

        // Reject an unknown username
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

        if (!passwordMatches) {
            return res.status(401).render("signin", {
                error: "Invalid username or password.",
                registered: false
            });
        }

        // Create a fresh session after successful authentication
        req.session.regenerate((error) => {
            if (error) {
                console.error("Session error:", error.message);
                return res.status(500).send("Unable to sign in.");
            }

            // Store only the user's public account details in the session
            req.session.user = {
                user_id: user.user_id,
                name: user.name
            };

            res.redirect("/");
        });
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
    req.session.destroy((error) => {
        if (error) {
            console.error("Logout error:", error.message);
            return res.status(500).send("Unable to sign out.");
        }

        res.clearCookie("connect.sid");
        res.redirect("/");
    });
});

// Create a blog post
app.post("/posts", requireLogin, async (req, res) => {
    const { title, content } = req.body;

    if (!title || !title.trim() || !content || !content.trim()) {
        return res.status(400).send("A title and post content are required.");
    }

    try {
        // Use the signed-in user's account instead of trusting form input
        const user = req.session.user;

        await pool.query(
            `INSERT INTO blogs
                (creator_name, creator_user_id, title, body)
             VALUES ($1, $2, $3, $4)`,
            [user.name, user.user_id, title.trim(), content.trim()]
        );

        res.redirect("/");
    } catch (error) {
        console.error("Create post error:", error.message);
        res.status(500).send("Unable to create the post.");
    }
});

// Display the edit page only if the signed-in user owns the post
app.get("/posts/:id/edit", requireLogin, async (req, res) => {
    try {
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

        const post = result.rows[0];

        if (!post) {
            return res.status(404).send("Post not found or you do not own it.");
        }

        res.render("edit", { post: post });
    } catch (error) {
        console.error("Load edit page error:", error.message);
        res.status(500).send("Unable to load the edit page.");
    }
});

// Update a post only if the signed-in user owns it
app.post("/posts/:id/edit", requireLogin, async (req, res) => {
    const { title, content } = req.body;

    if (!title || !title.trim() || !content || !content.trim()) {
        return res.status(400).send("A title and post content are required.");
    }

    try {
        const result = await pool.query(
            `UPDATE blogs
             SET title = $1, body = $2
             WHERE blog_id = $3 AND creator_user_id = $4
             RETURNING blog_id`,
            [
                title.trim(),
                content.trim(),
                req.params.id,
                req.session.user.user_id
            ]
        );

        if (result.rows.length === 0) {
            return res.status(404).send("Post not found or you do not own it.");
        }

        res.redirect("/");
    } catch (error) {
        console.error("Update post error:", error.message);
        res.status(500).send("Unable to update the post.");
    }
});

// Delete a post only if the signed-in user owns it
app.post("/posts/:id/delete", requireLogin, async (req, res) => {
    try {
        const result = await pool.query(
            `DELETE FROM blogs
             WHERE blog_id = $1 AND creator_user_id = $2
             RETURNING blog_id`,
            [req.params.id, req.session.user.user_id]
        );

        if (result.rows.length === 0) {
            return res.status(404).send("Post not found or you do not own it.");
        }

        res.redirect("/");
    } catch (error) {
        console.error("Delete post error:", error.message);
        res.status(500).send("Unable to delete the post.");
    }
});

// Start server and listen for port 3000
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});