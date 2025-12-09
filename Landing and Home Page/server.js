import express from "express";
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import path from "path";
import fs from "fs";
import bcrypt from "bcrypt";

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const port = 4000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "css")));
app.use(express.static(path.join(__dirname, "images")));

// Initialize DB
const file = join(__dirname, '../shared-db/db.json');
const adapter = new JSONFile(file);
const defaultData = { activeUser: null, users: [], lastActivity: null };

const db = new Low(adapter, defaultData);
await db.read();
db.data ||= defaultData;
await db.write();

// Max idle time (5 min)
const maxIdleTime = 5 * 60 * 1000;

// -------------------------------------------------
// ⭐ FIXED checkAuth middleware for port 3030
// -------------------------------------------------
async function checkAuth(req, res, next) {
    const username = req.cookies.user4000; // FIXED cookie name

    if (!username) return res.redirect("/login.html");

    await db.read();

    if (db.data.activeUser === username) {
        const lastActivity = db.data.lastActivity || 0;

        // Idle timeout check
        if (Date.now() - lastActivity > maxIdleTime) {
            db.data.activeUser = null;
            db.data.lastActivity = null;
            await db.write();

            res.clearCookie("user3030");
            res.clearCookie("lastActivity");

            return res.redirect("/login.html?loggedOut=idle");
        }

        // Update activity
        db.data.lastActivity = Date.now();
        await db.write();
        res.cookie("lastActivity", Date.now().toString());

        return next();
    }

    return res.redirect("/login.html");
}

// -------------------------------------------------
// Serve login page
// -------------------------------------------------
app.get("/", (req, res) => res.redirect("/login.html"));

app.get("/login.html", async (req, res) => {
    const username = req.cookies.user4000; // FIXED
    await db.read();

    if (username && db.data.activeUser === username) {
        return res.redirect("/index.html");
    }

    res.sendFile(join(__dirname, "pages/login.html"));
});

// -------------------------------------------------
// LOGIN (fixed cookie name)
// -------------------------------------------------
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    await db.read();

    // If someone else is active
    if (db.data.activeUser && db.data.activeUser !== username) {
        const idleTime = Date.now() - (db.data.lastActivity || 0);

        if (idleTime <= maxIdleTime) {
            let page = fs.readFileSync(join(__dirname, "pages/login.html"), "utf-8");
            page = page.replace('{{message}}', `System is currently used by ${db.data.activeUser}. Actions disabled.`);
            page = page.replace('style="display: none;"', 'style="display: block;"');
            return res.send(page);
        } else {
            // Auto clear idle user
            db.data.activeUser = null;
            db.data.lastActivity = null;
            await db.write();
        }
    }

    const user = db.data.users.find(u => u.username === username);

    if (user && await bcrypt.compare(password, user.password)) {
        db.data.activeUser = username;
        db.data.lastActivity = Date.now();
        await db.write();

        // FIXED cookie name
        res.cookie("user4000", username);
        res.cookie("lastActivity", Date.now().toString());

        return res.redirect("/index.html");
    }

    // Invalid login
    let page = fs.readFileSync(join(__dirname, "pages/login.html"), "utf-8");
    page = page.replace('{{message}}', 'Invalid username or password.');
    page = page.replace('style="display: none;"', 'style="display: block;"');
    return res.send(page);
});

// -------------------------------------------------
// Protected page
// -------------------------------------------------
app.get("/index.html", checkAuth, (req, res) => {
    res.sendFile(join(__dirname, "pages/index.html"));
});

// -------------------------------------------------
// LOGOUT (fixed cookie name)
// -------------------------------------------------
app.get("/logout", async (req, res) => {
    const username = req.cookies.user4000;

    await db.read();

    if (db.data.activeUser === username) {
        db.data.activeUser = null;
        db.data.lastActivity = null;
        await db.write();
    }

    res.clearCookie("user4000"); // FIXED
    res.clearCookie("lastActivity");

    const type = req.query.type || "manual";
    return res.redirect(`/login.html?loggedOut=${type}`);
});

// -------------------------------------------------
// Lecturer required endpoints
// -------------------------------------------------
app.get("/current-user", async (req, res) => {
    await db.read();
    res.json({
        activeUser: db.data.activeUser,
        lastActivity: db.data.lastActivity
    });
});

app.post("/request-logout", async (req, res) => {
    await db.read();

    db.data.activeUser = null;
    db.data.lastActivity = null;

    await db.write();

    res.json({ success: true, message: "Active user has been logged off." });
});

// -------------------------------------------------
// View status
// -------------------------------------------------
app.get("/status", async (req, res) => {
    await db.read();

    const currentUser = req.cookies.user4000 || null;
    const userObj = db.data.users.find(u => u.username === currentUser);
    const role = userObj ? userObj.role : null;

    res.json({
        activeUser: db.data.activeUser,
        currentUser,
        role,
        allUsers: db.data.users.map(u => ({
            username: u.username,
            role: u.role
        }))
    });
});

// -------------------------------------------------
// Admin: Create User
// -------------------------------------------------
app.post("/create-user", async (req, res) => {
    try {
        const currentUser = req.cookies.user4000;
        await db.read();

        const userObj = db.data.users.find(u => u.username === currentUser);
        if (!userObj || userObj.role !== "Administrator") {
            return res.status(403).json({ success: false, message: "Unauthorized" });
        }

        const { username, password, role } = req.body;

        if (!username || !password || !role) {
            return res.status(400).json({ success: false, message: "Missing fields" });
        }

        if (db.data.users.find(u => u.username === username)) {
            return res.status(400).json({ success: false, message: "Username exists" });
        }

        const hashed = await bcrypt.hash(password, 10);
        db.data.users.push({ username, password: hashed, role });
        await db.write();

        return res.json({ success: true });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "Server error" });
    }
});

// -------------------------------------------------
// Admin: View all users
// -------------------------------------------------
app.get("/users", async (req, res) => {
    const currentUser = req.cookies.user4000;
    await db.read();

    const userObj = db.data.users.find(u => u.username === currentUser);
    if (!userObj || userObj.role !== "Administrator") {
        return res.status(403).json({ success: false, message: "Unauthorized" });
    }

    const users = db.data.users.map(u => ({
        username: u.username,
        role: u.role
    }));

    return res.json({ success: true, users });
});

// -------------------------------------------------
// Admin: Update user role
// -------------------------------------------------
app.post("/update-user", async (req, res) => {
    await db.read();

    const { username, role } = req.body;

    if (!username || !role) {
        return res.json({ success: false, message: "Missing fields" });
    }

    const user = db.data.users.find(u => u.username === username);

    if (!user) return res.json({ success: false, message: "User not found" });

    user.role = role;
    await db.write();

    return res.json({ success: true });
});

// -------------------------------------------------
// Admin: Delete user
// -------------------------------------------------
app.post("/delete-user", async (req, res) => {
    const { username } = req.body;

    await db.read();

    const index = db.data.users.findIndex(u => u.username === username);

    if (index === -1) return res.json({ success: false, message: "User not found" });

    db.data.users.splice(index, 1);
    await db.write();

    return res.json({ success: true });
});

// -------------------------------------------------
// Start server
// -------------------------------------------------
app.listen(port, () =>
    console.log(`Server running at http://localhost:${port}`)
);
