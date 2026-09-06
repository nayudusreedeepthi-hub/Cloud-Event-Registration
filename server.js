const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 5000;

// ===============================
// Configuration
// ===============================

const JWT_SECRET = "cloud_event_registration_secret_2026";

const DATA_DIR = path.join(__dirname, "data");

const USERS_FILE = path.join(DATA_DIR, "users.json");
const EVENTS_FILE = path.join(DATA_DIR, "events.json");
const REGISTRATIONS_FILE = path.join(DATA_DIR, "registrations.json");


// ===============================
// Middleware
// ===============================

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve HTML, CSS and JS from project root
app.use(express.static(__dirname));


// ===============================
// Create data folder/files
// ===============================

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

function createFileIfNotExists(file, defaultData) {
    if (!fs.existsSync(file)) {
        fs.writeFileSync(
            file,
            JSON.stringify(defaultData, null, 2)
        );
    }
}

createFileIfNotExists(USERS_FILE, []);
createFileIfNotExists(EVENTS_FILE, []);
createFileIfNotExists(REGISTRATIONS_FILE, []);


// ===============================
// File Helpers
// ===============================

function readData(file) {
    try {
        return JSON.parse(
            fs.readFileSync(file, "utf8")
        );
    } catch (error) {
        return [];
    }
}

function writeData(file, data) {
    fs.writeFileSync(
        file,
        JSON.stringify(data, null, 2)
    );
}


// ===============================
// Create Admin Account
// ===============================

let users = readData(USERS_FILE);

if (!users.some(user => user.email === "admin@event.com")) {

    const adminPassword = bcrypt.hashSync(
        "admin123",
        10
    );

    users.push({
        id: "admin-1",
        name: "Administrator",
        email: "admin@event.com",
        password: adminPassword,
        role: "admin"
    });

    writeData(USERS_FILE, users);

    console.log("Default admin created");
    console.log("Email: admin@event.com");
    console.log("Password: admin123");
}


// ===============================
// Create Sample Events
// ===============================

let events = readData(EVENTS_FILE);

if (events.length === 0) {

    events = [
        {
            id: "event-1",
            title: "Cloud Computing Workshop",
            description:
                "Learn the fundamentals of cloud computing, virtualization and cloud services.",
            date: "2026-09-15",
            time: "10:00 AM",
            venue: "Seminar Hall",
            capacity: 100
        },
        {
            id: "event-2",
            title: "Web Development Workshop",
            description:
                "Learn HTML, CSS, JavaScript and modern web development.",
            date: "2026-09-20",
            time: "11:00 AM",
            venue: "Computer Lab",
            capacity: 80
        },
        {
            id: "event-3",
            title: "Artificial Intelligence Seminar",
            description:
                "Introduction to Artificial Intelligence and Machine Learning.",
            date: "2026-09-25",
            time: "02:00 PM",
            venue: "Auditorium",
            capacity: 150
        }
    ];

    writeData(EVENTS_FILE, events);
}


// ===============================
// Authentication Middleware
// ===============================

function authenticateToken(req, res, next) {

    const authHeader =
        req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({
            message: "Authentication required"
        });
    }

    const token =
        authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            message: "Invalid token"
        });
    }

    try {

        const user =
            jwt.verify(token, JWT_SECRET);

        req.user = user;

        next();

    } catch (error) {

        return res.status(403).json({
            message: "Invalid or expired token"
        });
    }
}


// ===============================
// Admin Middleware
// ===============================

function requireAdmin(req, res, next) {

    if (!req.user || req.user.role !== "admin") {

        return res.status(403).json({
            message: "Admin access required"
        });
    }

    next();
}


// ===============================
// HOME
// ===============================

app.get("/", (req, res) => {

    const indexPath =
        path.join(__dirname, "index.html");

    const registerPath =
        path.join(__dirname, "register.html");

    if (fs.existsSync(indexPath)) {

        return res.sendFile(indexPath);

    } else if (fs.existsSync(registerPath)) {

        return res.sendFile(registerPath);

    } else {

        return res.status(404).send(
            "index.html or register.html not found"
        );
    }
});


// ===============================
// REGISTER USER
// ===============================

app.post("/api/register", async (req, res) => {

    try {

        const {
            name,
            email,
            password
        } = req.body;

        if (!name || !email || !password) {

            return res.status(400).json({
                message:
                    "Name, email and password are required"
            });
        }

        let users =
            readData(USERS_FILE);

        const existingUser =
            users.find(
                user =>
                    user.email.toLowerCase() ===
                    email.toLowerCase()
            );

        if (existingUser) {

            return res.status(400).json({
                message:
                    "User already exists"
            });
        }

        const hashedPassword =
            await bcrypt.hash(password, 10);

        const newUser = {

            id:
                Date.now().toString(),

            name,

            email,

            password:
                hashedPassword,

            role:
                "user"
        };

        users.push(newUser);

        writeData(
            USERS_FILE,
            users
        );

        res.status(201).json({
            message:
                "Registration successful"
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message:
                "Server error"
        });
    }
});


// ===============================
// LOGIN
// ===============================

app.post("/api/login", async (req, res) => {

    try {

        const {
            email,
            password
        } = req.body;

        const users =
            readData(USERS_FILE);

        const user =
            users.find(
                u =>
                    u.email.toLowerCase() ===
                    email.toLowerCase()
            );

        if (!user) {

            return res.status(401).json({
                message:
                    "Invalid email or password"
            });
        }

        const passwordMatch =
            await bcrypt.compare(
                password,
                user.password
            );

        if (!passwordMatch) {

            return res.status(401).json({
                message:
                    "Invalid email or password"
            });
        }

        const token =
            jwt.sign(
                {
                    id: user.id,
                    email: user.email,
                    role: user.role,
                    name: user.name
                },
                JWT_SECRET,
                {
                    expiresIn: "24h"
                }
            );

        res.json({
            message:
                "Login successful",

            token,

            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message:
                "Server error"
        });
    }
});


// ===============================
// GET CURRENT USER
// ===============================

app.get(
    "/api/me",
    authenticateToken,
    (req, res) => {

        res.json({
            user: req.user
        });
    }
);


// ===============================
// GET ALL EVENTS
// ===============================

app.get("/api/events", (req, res) => {

    const events =
        readData(EVENTS_FILE);

    res.json(events);
});


// ===============================
// GET SINGLE EVENT
// ===============================

app.get("/api/events/:id", (req, res) => {

    const events =
        readData(EVENTS_FILE);

    const event =
        events.find(
            e => e.id === req.params.id
        );

    if (!event) {

        return res.status(404).json({
            message:
                "Event not found"
        });
    }

    res.json(event);
});


// ===============================
// ADD EVENT - ADMIN
// ===============================

app.post(
    "/api/events",
    authenticateToken,
    requireAdmin,
    (req, res) => {

        const {
            title,
            description,
            date,
            time,
            venue,
            capacity
        } = req.body;

        if (
            !title ||
            !date ||
            !time ||
            !venue ||
            !capacity
        ) {

            return res.status(400).json({
                message:
                    "Please provide all event details"
            });
        }

        const events =
            readData(EVENTS_FILE);

        const newEvent = {

            id:
                "event-" +
                Date.now(),

            title,

            description:
                description || "",

            date,

            time,

            venue,

            capacity:
                Number(capacity)
        };

        events.push(newEvent);

        writeData(
            EVENTS_FILE,
            events
        );

        res.status(201).json({
            message:
                "Event added successfully",

            event:
                newEvent
        });
    }
);


// ===============================
// UPDATE EVENT - ADMIN
// ===============================

app.put(
    "/api/events/:id",
    authenticateToken,
    requireAdmin,
    (req, res) => {

        const events =
            readData(EVENTS_FILE);

        const index =
            events.findIndex(
                e =>
                    e.id === req.params.id
            );

        if (index === -1) {

            return res.status(404).json({
                message:
                    "Event not found"
            });
        }

        events[index] = {

            ...events[index],

            ...req.body,

            id:
                events[index].id
        };

        writeData(
            EVENTS_FILE,
            events
        );

        res.json({
            message:
                "Event updated successfully",

            event:
                events[index]
        });
    }
);


// ===============================
// DELETE EVENT - ADMIN
// ===============================

app.delete(
    "/api/events/:id",
    authenticateToken,
    requireAdmin,
    (req, res) => {

        let events =
            readData(EVENTS_FILE);

        const exists =
            events.some(
                e =>
                    e.id === req.params.id
            );

        if (!exists) {

            return res.status(404).json({
                message:
                    "Event not found"
            });
        }

        events =
            events.filter(
                e =>
                    e.id !== req.params.id
            );

        writeData(
            EVENTS_FILE,
            events
        );

        res.json({
            message:
                "Event deleted successfully"
        });
    }
);


// ===============================
// REGISTER FOR EVENT
// ===============================

app.post(
    "/api/events/:id/register",
    (req, res) => {

        const eventId =
            req.params.id;

        const {
            name,
            email,
            phone,
            college
        } = req.body;

        if (
            !name ||
            !email ||
            !phone ||
            !college
        ) {

            return res.status(400).json({
                message:
                    "Please fill in all details"
            });
        }

        const events =
            readData(EVENTS_FILE);

        const event =
            events.find(
                e =>
                    e.id === eventId
            );

        if (!event) {

            return res.status(404).json({
                message:
                    "Selected event not found"
            });
        }

        let registrations =
            readData(REGISTRATIONS_FILE);


        // Check duplicate registration
        const alreadyRegistered =
            registrations.find(
                r =>
                    r.eventId === eventId &&
                    r.email.toLowerCase() ===
                    email.toLowerCase()
            );

        if (alreadyRegistered) {

            return res.status(400).json({
                message:
                    "You are already registered for this event"
            });
        }


        // Check capacity
        const eventRegistrations =
            registrations.filter(
                r =>
                    r.eventId === eventId
            );

        if (
            eventRegistrations.length >=
            Number(event.capacity)
        ) {

            return res.status(400).json({
                message:
                    "This event is full"
            });
        }


        const registration = {

            id:
                "registration-" +
                Date.now(),

            eventId,

            eventTitle:
                event.title,

            name,

            email,

            phone,

            college,

            registeredAt:
                new Date().toISOString()
        };

        registrations.push(
            registration
        );

        writeData(
            REGISTRATIONS_FILE,
            registrations
        );

        res.status(201).json({

            message:
                "Successfully registered for the event",

            registration
        });
    }
);


// ===============================
// GET MY REGISTRATIONS
// ===============================

app.get(
    "/api/my-registrations",
    authenticateToken,
    (req, res) => {

        const registrations =
            readData(REGISTRATIONS_FILE);

        const myRegistrations =
            registrations.filter(
                r =>
                    r.email ===
                    req.user.email
            );

        res.json(
            myRegistrations
        );
    }
);


// ===============================
// DELETE REGISTRATION
// ===============================

app.delete(
    "/api/registrations/:id",
    authenticateToken,
    (req, res) => {

        let registrations =
            readData(REGISTRATIONS_FILE);

        const registration =
            registrations.find(
                r =>
                    r.id ===
                    req.params.id
            );

        if (!registration) {

            return res.status(404).json({
                message:
                    "Registration not found"
            });
        }

        if (
            registration.email !==
            req.user.email &&
            req.user.role !== "admin"
        ) {

            return res.status(403).json({
                message:
                    "You cannot cancel this registration"
            });
        }

        registrations =
            registrations.filter(
                r =>
                    r.id !==
                    req.params.id
            );

        writeData(
            REGISTRATIONS_FILE,
            registrations
        );

        res.json({
            message:
                "Registration cancelled successfully"
        });
    }
);


// ===============================
// ADMIN - ALL REGISTRATIONS
// ===============================

app.get(
    "/api/admin/registrations",
    authenticateToken,
    requireAdmin,
    (req, res) => {

        const registrations =
            readData(REGISTRATIONS_FILE);

        res.json(
            registrations
        );
    }
);


// ===============================
// ADMIN - STATISTICS
// ===============================

app.get(
    "/api/admin/stats",
    authenticateToken,
    requireAdmin,
    (req, res) => {

        const events =
            readData(EVENTS_FILE);

        const registrations =
            readData(REGISTRATIONS_FILE);

        res.json({

            totalEvents:
                events.length,

            totalRegistrations:
                registrations.length,

            totalUsers:
                readData(USERS_FILE).length - 1
        });
    }
);


// ===============================
// SERVER START
// ===============================

app.listen(PORT, () => {

    console.log("");
    console.log("======================================");
    console.log("☁️ Cloud Event Registration");
    console.log("======================================");
    console.log(
        `Server running on http://localhost:${PORT}`
    );
    console.log("");
    console.log(
        "Open: http://localhost:5000/index.html"
    );
    console.log("");
    console.log(
        "Admin Login:"
    );
    console.log(
        "Email: admin@event.com"
    );
    console.log(
        "Password: admin123"
    );
    console.log("======================================");
});