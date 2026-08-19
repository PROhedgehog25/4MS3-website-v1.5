const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { Chess } = require("chess.js");
const webpush = require("web-push");

const app = express();
const PORT = 3000;

/* =====================================================
   4MS3 WEB PUSH NOTIFICATIONS
===================================================== */

const VAPID_PUBLIC_KEY =
    process.env.VAPID_PUBLIC_KEY || "";

const VAPID_PRIVATE_KEY =
    process.env.VAPID_PRIVATE_KEY || "";

const VAPID_SUBJECT =
    process.env.VAPID_SUBJECT ||
    "mailto:4ms3@example.com";


if (
    VAPID_PUBLIC_KEY &&
    VAPID_PRIVATE_KEY
) {

    webpush.setVapidDetails(

        VAPID_SUBJECT,

        VAPID_PUBLIC_KEY,

        VAPID_PRIVATE_KEY

    );

} else {

    console.warn(
        "⚠ WEB PUSH VAPID KEYS ARE NOT CONFIGURED."
    );

}

app.use(express.json());

/* =====================================================
   4MS3 SECURITY / AUTHENTICATION SYSTEM
===================================================== */

const crypto =
    require("crypto");


/* =========================================
   SECURITY FILES
========================================= */

const studentAuthFile =
    path.join(
        __dirname,
        "studentAuth.json"
    );


const bannedUsersFile =
    path.join(
        __dirname,
        "bannedUsers.json"
    );


/* =========================================
   CREATE SECURITY FILES
========================================= */

if (
    !fs.existsSync(
        studentAuthFile
    )
) {

    fs.writeFileSync(
        studentAuthFile,
        "{}",
        "utf8"
    );

}


if (
    !fs.existsSync(
        bannedUsersFile
    )
) {

    fs.writeFileSync(
        bannedUsersFile,
        "{}",
        "utf8"
    );

}


/* =========================================
   ADMIN PASSWORD
========================================= */

/*
 * For a real deployment, set:
 *
 * ADMIN_PASSWORD
 *
 * as an environment variable.
 *
 * Example:
 *
 * Windows CMD:
 * set ADMIN_PASSWORD=YourSecretPassword
 *
 * PowerShell:
 * $env:ADMIN_PASSWORD="YourSecretPassword"
 *
 * The fallback below is only here so the
 * server doesn't crash if you haven't
 * configured it yet.
 */

const ADMIN_PASSWORD =
    process.env.ADMIN_PASSWORD ||
    "PROpass25-26";


/* =========================================
   SESSION STORAGE
========================================= */

const studentSessions =
    new Map();

/* =========================================
   WEB PUSH SUBSCRIPTIONS
========================================= */

const pushSubscriptionsFile =
    path.join(
        __dirname,
        "pushSubscriptions.json"
    );


if (
    !fs.existsSync(
        pushSubscriptionsFile
    )
) {

    fs.writeFileSync(
        pushSubscriptionsFile,
        "{}",
        "utf8"
    );

}


function loadPushSubscriptions() {

    return loadJsonFile(
        pushSubscriptionsFile,
        {}
    );

}


function savePushSubscriptions(
    subscriptions
) {

    saveJsonFile(
        pushSubscriptionsFile,
        subscriptions
    );

}


const adminSessions =
    new Map();


const SESSION_DURATION =
    7 * 24 * 60 * 60 * 1000;


/* =========================================
   NORMALIZE NAME
========================================= */

function normalizeAuthName(
    name
) {

    return String(
        name || ""
    )
    .trim()
    .replace(
        /\s+/g,
        " "
    )
    .toLowerCase();

}


/* =========================================
   LOAD JSON FILE
========================================= */

function loadJsonFile(
    filePath,
    fallback
) {

    try {

        const data =
            fs.readFileSync(
                filePath,
                "utf8"
            );


        const parsed =
            JSON.parse(
                data
            );


        return parsed;

    }

    catch (error) {

        console.error(
            "Security data load error:",
            error
        );


        return fallback;

    }

}


/* =========================================
   SAVE JSON FILE
========================================= */

function saveJsonFile(
    filePath,
    data
) {

    fs.writeFileSync(

        filePath,

        JSON.stringify(
            data,
            null,
            4
        ),

        "utf8"

    );

}


/* =========================================
   PBKDF2 HASH
========================================= */

function hashPin(
    pin,
    salt = crypto.randomBytes(16).toString("hex")
) {

    const hash =
        crypto.pbkdf2Sync(

            String(pin),

            salt,

            120000,

            64,

            "sha512"

        )
        .toString("hex");


    return {

        salt:
            salt,

        hash:
            hash

    };

}


/* =========================================
   VERIFY PIN
========================================= */

function verifyPin(
    pin,
    stored
) {

    if (
        !stored ||
        !stored.hash ||
        !stored.salt
    ) {

        return false;

    }


    const calculated =
        crypto.pbkdf2Sync(

            String(pin),

            stored.salt,

            120000,

            64,

            "sha512"

        )
        .toString("hex");


    try {

        return crypto.timingSafeEqual(

            Buffer.from(
                calculated,
                "hex"
            ),

            Buffer.from(
                stored.hash,
                "hex"
            )

        );

    }

    catch {

        return false;

    }

}


/* =========================================
   RANDOM TOKEN
========================================= */

function createSecurityToken() {

    return crypto.randomBytes(
        32
    )
    .toString("hex");

}


/* =========================================
   COOKIE HELPERS
========================================= */

function getCookies(
    req
) {

    const header =
        req.headers.cookie ||
        "";


    const cookies = {};


    header
        .split(";")
        .forEach(
            part => {

                const index =
                    part.indexOf("=");


                if (
                    index === -1
                ) {

                    return;

                }


                const key =
                    part
                        .slice(
                            0,
                            index
                        )
                        .trim();


                const value =
                    part
                        .slice(
                            index + 1
                        )
                        .trim();


                cookies[key] =
                    decodeURIComponent(
                        value
                    );

            }
        );


    return cookies;

}


function setCookie(
    res,
    name,
    value,
    maxAge
) {

    const cookie =
        `${name}=${encodeURIComponent(value)}; Max-Age=${Math.floor(
            maxAge / 1000
        )}; Path=/; HttpOnly; SameSite=Lax`;


    res.setHeader(
        "Set-Cookie",
        cookie
    );

}


function clearCookie(
    res,
    name
) {

    res.setHeader(

        "Set-Cookie",

        `${name}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax`

    );

}


/* =========================================
   BAN DATA
========================================= */

function loadBannedUsers() {

    const data =
        loadJsonFile(
            bannedUsersFile,
            {}
        );


    return (
        data &&
        typeof data === "object"
    )
        ? data
        : {};

}


function isUserBanned(
    name
) {

    const banned =
        loadBannedUsers();


    return Boolean(
        banned[
            normalizeAuthName(
                name
            )
        ]
    );

}


/* =========================================
   CURRENT STUDENT SESSION
========================================= */

function getAuthenticatedStudent(
    req
) {

    const cookies =
        getCookies(
            req
        );


    const token =
        cookies[
            "4ms3_session"
        ];


    if (!token) {

        return null;

    }


    const session =
        studentSessions.get(
            token
        );


    if (!session) {

        return null;

    }


    if (
        Date.now() >
        session.expiresAt
    ) {

        studentSessions.delete(
            token
        );

        return null;

    }


    /*
     * IMPORTANT:
     *
     * Do NOT delete the session here when
     * the student is banned.
     *
     * /api/session needs to be able to
     * detect the ban and return the reason.
     */

    return session;

}

/* =========================================
   REQUIRE STUDENT LOGIN
========================================= */

function requireStudentAuth(
    req,
    res,
    next
) {

    const session =
        getAuthenticatedStudent(
            req
        );


    if (!session) {

        return res.status(
            401
        ).json({

            success:
                false,

            authenticated:
                false,

            message:
                "You must be logged in."

        });

    }


    /*
     * The server becomes the source
     * of truth for the student name.
     */

    req.user =
        session;


    /*
     * Prevent clients from pretending
     * to be another student.
     */

    if (
        req.body &&
        typeof req.body === "object"
    ) {

        req.body.name =
            session.name;

    }


    if (
        req.query &&
        typeof req.query === "object"
    ) {

        req.query.name =
            session.name;

    }


    next();

}


/* =========================================
   ADMIN SESSION
========================================= */

function getAuthenticatedAdmin(
    req
) {

    const cookies =
        getCookies(
            req
        );


    const token =
        cookies[
            "4ms3_admin_session"
        ];


    if (!token) {

        return null;

    }


    const session =
        adminSessions.get(
            token
        );


    if (!session) {

        return null;

    }


    if (
        Date.now() >
        session.expiresAt
    ) {

        adminSessions.delete(
            token
        );

        return null;

    }


    return session;

}


/* =========================================
   REQUIRE ADMIN
========================================= */

function requireAdmin(
    req,
    res,
    next
) {

    const session =
        getAuthenticatedAdmin(
            req
        );


    if (!session) {

        return res.status(
            401
        ).json({

            success:
                false,

            authenticated:
                false,

            message:
                "Admin authentication required."

        });

    }


    req.admin =
        session;


    next();

}


/* =========================================
   STUDENT LOGIN
========================================= */

app.post(
    "/api/login",
    (req, res) => {

        try {

            const name =
                String(
                    req.body.name ||
                    ""
                )
                .trim()
                .replace(
                    /\s+/g,
                    " "
                );


            const pin =
                String(
                    req.body.pin ||
                    ""
                )
                .trim();


            if (
                !name ||
                !pin
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    message:
                        "Name and PIN are required."

                });

            }


            if (
    isUserBanned(
        name
    )
) {

    const bannedUsers =
        loadBannedUsers();

    const bannedRecord =
        bannedUsers[
            normalizeAuthName(
                name
            )
        ];

    return res.status(
        403
    ).json({

        success:
            false,

        banned:
            true,

        message:
            "Your 4MS3 account has been banned.",

        reason:
            bannedRecord &&
            bannedRecord.reason
                ? bannedRecord.reason
                : "Banned by administrator."

    });

}


            const leaderboard =
                loadJsonFile(
                    leaderboardFile,
                    []
                );


            const normalizedName =
                normalizeAuthName(
                    name
                );


            const student =
                leaderboard.find(
                    entry =>
                        normalizeAuthName(
                            entry.name
                        ) ===
                        normalizedName
                );


            if (!student) {

                return res.status(
                    401
                ).json({

                    success:
                        false,

                    message:
                        "That name isn't on the 4MS3 class list."

                });

            }


            const authData =
                loadJsonFile(
                    studentAuthFile,
                    {}
                );


            const account =
                authData[
                    normalizedName
                ];


            if (
                !account ||
                !account.pinHash
            ) {

                return res.status(
                    403
                ).json({

                    success:
                        false,

                    message:
                        "This student account does not have a PIN yet. Ask the 4MS3 admin to create one."

                });

            }


            if (
                !verifyPin(
                    pin,
                    account.pinHash
                )
            ) {

                return res.status(
                    401
                ).json({

                    success:
                        false,

                    message:
                        "Incorrect name or PIN."

                });

            }


            const token =
                createSecurityToken();


            studentSessions.set(
                token,
                {

                    name:
                        student.name,

                    createdAt:
                        Date.now(),

                    expiresAt:
                        Date.now() +
                        SESSION_DURATION

                }
            );


            setCookie(
                res,
                "4ms3_session",
                token,
                SESSION_DURATION
            );


            res.json({

                success:
                    true,

                authenticated:
                    true,

                name:
                    student.name

            });

        }

        catch (error) {

            console.error(
                "Student login error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't log in."

            });

        }

    }
);


/* =========================================
   GET CURRENT SESSION
========================================= */

app.get(
    "/api/session",
    (req, res) => {

        const cookies =
            getCookies(
                req
            );


        const token =
            cookies[
                "4ms3_session"
            ];


        /*
         * No login cookie.
         */

        if (!token) {

            return res.status(
                401
            ).json({

                success:
                    false,

                authenticated:
                    false

            });

        }


        const session =
            studentSessions.get(
                token
            );


        /*
         * Cookie exists but the session
         * doesn't exist anymore.
         */

        if (!session) {

            return res.status(
                401
            ).json({

                success:
                    false,

                authenticated:
                    false

            });

        }


        /*
         * Session expired.
         */

        if (
            Date.now() >
            session.expiresAt
        ) {

            studentSessions.delete(
                token
            );


            return res.status(
                401
            ).json({

                success:
                    false,

                authenticated:
                    false

            });

        }


        /*
         * CHECK BAN
         *
         * Do this BEFORE returning success.
         */

        const bannedUsers =
            loadBannedUsers();


        const bannedRecord =
            bannedUsers[
                normalizeAuthName(
                    session.name
                )
            ];


        if (
            bannedRecord
        ) {

            /*
             * Remove the active session.
             */

            studentSessions.delete(
                token
            );


            clearCookie(
                res,
                "4ms3_session"
            );


            return res.status(
                403
            ).json({

                success:
                    false,

                authenticated:
                    false,

                banned:
                    true,

                message:
                    "Your 4MS3 account has been banned.",

                reason:
                    bannedRecord.reason ||
                    "Banned by administrator."

            });

        }


        /*
         * VALID SESSION
         */

        return res.json({

            success:
                true,

            authenticated:
                true,

            name:
                session.name

        });

    }
);

/* =========================================
   STUDENT LOGOUT
========================================= */

app.post(
    "/api/logout",
    (req, res) => {

        const cookies =
            getCookies(
                req
            );


        const token =
            cookies[
                "4ms3_session"
            ];


        if (token) {

            studentSessions.delete(
                token
            );

        }


        clearCookie(
            res,
            "4ms3_session"
        );


        res.json({

            success:
                true

        });

    }
);

/* =========================================
   ADMIN — LIST STUDENT ACCESS
========================================= */

app.get(
    "/api/admin/access",
    requireAdmin,
    (req, res) => {

        try {

            const leaderboard =
                loadJsonFile(
                    leaderboardFile,
                    []
                );


            const authData =
                loadJsonFile(
                    studentAuthFile,
                    {}
                );


            const banned =
                loadBannedUsers();


            const students =
                leaderboard.map(
                    student => {

                        const key =
                            normalizeAuthName(
                                student.name
                            );


                        return {

                            name:
                                student.name,

                            hasPin:
                                Boolean(
                                    authData[key] &&
                                    authData[key].pinHash
                                ),

                            banned:
                                Boolean(
                                    banned[key]
                                ),

                            banReason:
                                banned[key]
                                    ? banned[key].reason ||
                                      ""
                                    : ""

                        };

                    }
                );


            res.json({

                success:
                    true,

                students:
                    students

            });

        }

        catch (error) {

            console.error(
                "Admin access list error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't load student access."

            });

        }

    }
);


/* =========================================
   ADMIN — GENERATE / RESET PIN
========================================= */

app.post(
    "/api/admin/student-pin",
    requireAdmin,
    (req, res) => {

        try {

            const name =
                String(
                    req.body.name ||
                    ""
                )
                .trim();


            const leaderboard =
                loadJsonFile(
                    leaderboardFile,
                    []
                );


            const student =
                leaderboard.find(
                    entry =>
                        normalizeAuthName(
                            entry.name
                        ) ===
                        normalizeAuthName(
                            name
                        )
                );


            if (!student) {

                return res.status(
                    404
                ).json({

                    success:
                        false,

                    message:
                        "Student not found."

                });

            }


            const pin =
                String(
                    crypto.randomInt(
                        100000,
                        1000000
                    )
                );


            const authData =
                loadJsonFile(
                    studentAuthFile,
                    {}
                );


            const key =
                normalizeAuthName(
                    student.name
                );


            const existing =
                authData[key] ||
                {};


            authData[key] = {

                name:
                    student.name,

                pinHash:
                    hashPin(
                        pin
                    ),

                nameChangeUsed:
                    Boolean(
                        existing.nameChangeUsed
                    ),

                createdAt:
                    existing.createdAt ||
                    new Date().toISOString(),

                updatedAt:
                    new Date().toISOString()

            };


            saveJsonFile(
                studentAuthFile,
                authData
            );


            res.json({

                success:
                    true,

                name:
                    student.name,

                pin:
                    pin

            });

        }

        catch (error) {

            console.error(
                "Admin PIN error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't create PIN."

            });

        }

    }
);


/* =========================================
   ADMIN — BAN STUDENT
========================================= */

app.post(
    "/api/admin/ban",
    requireAdmin,
    (req, res) => {

        try {

            const name =
                String(
                    req.body.name ||
                    ""
                )
                .trim();


            const reason =
                String(
                    req.body.reason ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    300
                );


            if (!name) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    message:
                        "Student name is required."

                });

            }


            const key =
                normalizeAuthName(
                    name
                );


            const banned =
                loadBannedUsers();


            banned[key] = {

                name:
                    name,

                reason:
                    reason ||
                    "Banned by administrator.",

                createdAt:
                    new Date().toISOString()

            };


            saveJsonFile(
                bannedUsersFile,
                banned
            );


            /*
             * Immediately kill every active
             * session belonging to this student.
             */

            for (
                const [
                    token,
                    session
                ]
                of studentSessions
            ) {

                if (
                    normalizeAuthName(
                        session.name
                    ) === key
                ) {

                    studentSessions.delete(
                        token
                    );

                }

            }


            console.log(
                `🚫 BANNED STUDENT: ${name}`
            );


            res.json({

                success:
                    true,

                banned:
                    true

            });

        }

        catch (error) {

            console.error(
                "Ban student error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't ban student."

            });

        }

    }
);


/* =========================================
   ADMIN — UNBAN STUDENT
========================================= */

app.post(
    "/api/admin/unban",
    requireAdmin,
    (req, res) => {

        try {

            const name =
                String(
                    req.body.name ||
                    ""
                )
                .trim();


            const key =
                normalizeAuthName(
                    name
                );


            const banned =
                loadBannedUsers();


            delete banned[key];


            saveJsonFile(
                bannedUsersFile,
                banned
            );


            console.log(
                `✅ UNBANNED STUDENT: ${name}`
            );


            res.json({

                success:
                    true,

                banned:
                    false

            });

        }

        catch (error) {

            console.error(
                "Unban student error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't unban student."

            });

        }

    }
);

/* =========================================
   ADMIN LOGIN
========================================= */

app.post(
    "/api/admin/login",
    (req, res) => {

        const password =
            String(
                req.body.password ||
                ""
            );


        if (
            !password ||
            password !==
            ADMIN_PASSWORD
        ) {

            return res.status(
                401
            ).json({

                success:
                    false,

                message:
                    "Incorrect admin password."

            });

        }


        const token =
            createSecurityToken();


        adminSessions.set(
            token,
            {

                role:
                    "admin",

                createdAt:
                    Date.now(),

                expiresAt:
                    Date.now() +
                    SESSION_DURATION

            }
        );


        setCookie(
            res,
            "4ms3_admin_session",
            token,
            SESSION_DURATION
        );


        res.json({

            success:
                true,

            authenticated:
                true

        });

    }
);


/* =========================================
   ADMIN SESSION
========================================= */

app.get(
    "/api/admin/session",
    (req, res) => {

        const session =
            getAuthenticatedAdmin(
                req
            );


        if (!session) {

            return res.status(
                401
            ).json({

                success:
                    false,

                authenticated:
                    false

            });

        }


        res.json({

            success:
                true,

            authenticated:
                true

        });

    }
);


/* =========================================
   ADMIN LOGOUT
========================================= */

app.post(
    "/api/admin/logout",
    (req, res) => {

        const cookies =
            getCookies(
                req
            );


        const token =
            cookies[
                "4ms3_admin_session"
            ];


        if (token) {

            adminSessions.delete(
                token
            );

        }


        clearCookie(
            res,
            "4ms3_admin_session"
        );


        res.json({

            success:
                true

        });

    }
);


/* =========================================
   FOLDERS
========================================= */

const pendingFolder =
    path.join(__dirname, "uploads", "pending");

const approvedFolder =
    path.join(__dirname, "uploads", "approved");

const leaderboardFile =
    path.join(
        __dirname,
        "leaderboard.json"
    );


fs.mkdirSync(pendingFolder, {
    recursive: true
});

fs.mkdirSync(approvedFolder, {
    recursive: true
});


/* =========================================
   FILE UPLOAD SETTINGS
========================================= */

const storage = multer.diskStorage({

    destination: (req, file, cb) => {

        cb(null, pendingFolder);

    },

    filename: (req, file, cb) => {

        const extension =
            path.extname(file.originalname);

        const uniqueName =
            Date.now() +
            "-" +
            Math.round(Math.random() * 1e9) +
            extension;

        cb(null, uniqueName);

    }

});


const upload = multer({

    storage: storage,

    limits: {

        /* 50 MB for images, MP3 and MP4 */

        fileSize:
            50 * 1024 * 1024

    },

    fileFilter: (req, file, cb) => {

        const isImage =
            file.mimetype.startsWith(
                "image/"
            );

        const isMP3 =
            file.mimetype ===
                "audio/mpeg" ||
            file.originalname
                .toLowerCase()
                .endsWith(".mp3");

        const isMP4 =
            file.mimetype ===
                "video/mp4" ||
            file.originalname
                .toLowerCase()
                .endsWith(".mp4");


        if (
            isImage ||
            isMP3 ||
            isMP4
        ) {

            cb(
                null,
                true
            );

        } else {

            cb(
                new Error(
                    "Only image, MP3 and MP4 files are allowed."
                )
            );

        }

    }

});


/* =========================================
   WEBSITE
========================================= */

app.use(
    express.static(__dirname)
);

/* =========================================
   PROTECT STUDENT ACTIONS
========================================= */

app.use(
    [
        "/upload",
        "/api/shoutbox",
        "/api/chess"
    ],
    requireStudentAuth
);


/* =========================================
   UPLOAD PHOTO
========================================= */

/* =========================================
   SECURE GALLERY UPLOAD
========================================= */

app.post(
    "/upload",
    requireStudentAuth,
    upload.single("photo"),
    (req, res) => {

        /*
         * The student's identity comes from
         * the authenticated server session.
         *
         * We DO NOT trust req.body.name.
         */

        if (!req.file) {

            return res.status(400).json({

                success: false,

                message:
                    "No photo was uploaded."

            });

        }


        const name =
            String(
                req.user.name
            )
            .trim()
            .slice(0, 80);


        if (!name) {

            try {

                fs.unlinkSync(
                    path.join(
                        pendingFolder,
                        req.file.filename
                    )
                );

            } catch (_) {}


            return res.status(401).json({

                success: false,

                message:
                    "Your student session is invalid."

            });

        }


        const metadataPath =
            path.join(
                pendingFolder,
                `${req.file.filename}.json`
            );


        try {

            fs.writeFileSync(

                metadataPath,

                JSON.stringify(

                    {

                        name:
                            name,

                        originalName:
                            req.file.originalname,

                        submittedAt:
                            new Date().toISOString()

                    },

                    null,

                    2

                ),

                "utf8"

            );


            console.log(
                `📥 New Gallery upload from ${name}: ${req.file.filename}`
            );


            res.json({

                success: true,

                message:
                    "Media submitted for review."

            });


        }

        catch (error) {

            console.error(
                "Gallery upload error:",
                error
            );


            try {

                fs.unlinkSync(
                    path.join(
                        pendingFolder,
                        req.file.filename
                    )
                );

            }

            catch (_) {}


            res.status(500).json({

                success: false,

                message:
                    "Couldn't save media information."

            });

        }

    }
);

/* =========================================
   LIST PENDING PHOTOS
========================================= */

app.get(
    "/api/pending",
    (req, res) => {

        try {

            const files =
                fs.readdirSync(
                    pendingFolder
                );


            const photos = files

                .filter(file => {

                    return /\.(jpg|jpeg|png|webp|gif|mp3|mp4)$/i
                        .test(file);

                })

                .map(file => {

                    const metadataPath =
                        path.join(
                            pendingFolder,
                            `${file}.json`
                        );


                    let metadata = {

                        name:
                            "Anonymous"

                    };


                    if (
                        fs.existsSync(
                            metadataPath
                        )
                    ) {

                        try {

                            metadata =
                                JSON.parse(

                                    fs.readFileSync(

                                        metadataPath,

                                        "utf8"

                                    )

                                );

                        } catch (error) {

                            console.error(
                                `Couldn't read metadata for ${file}:`,
                                error
                            );

                        }

                    }


                    return {

                        filename:
                            file,

                        name:
                            metadata.name ||
                            "Anonymous",

                        originalName:
                            metadata.originalName ||
                            file,

                        submittedAt:
                            metadata.submittedAt ||
                            null

                    };

                });


            res.json(photos);


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    "Couldn't read pending photos."

            });

        }

    }
);


/* =========================================
   SERVE PENDING PHOTOS
========================================= */

app.use(
    "/pending",
    express.static(pendingFolder)
);


/* =========================================
   SERVE APPROVED PHOTOS
========================================= */

app.use(
    "/approved",
    express.static(approvedFolder)
);






/* =========================================
   SERVE APPROVED GALLERY MEDIA
========================================= */

app.use(
    "/approved",
    express.static(
        approvedFolder
    )
);


/* =========================================
   GET APPROVED GALLERY MEDIA
========================================= */

app.get(
    "/api/approved",
    (req, res) => {

        try {

            const files =
                fs.readdirSync(
                    approvedFolder
                );


            const media =
                files
                    .filter(file => {

                        return /\.(jpg|jpeg|png|webp|gif|mp3|mp4)$/i
                            .test(file);

                    })
                    .map(file => {

                        const metadataPath =
                            path.join(
                                approvedFolder,
                                `${file}.json`
                            );


                        let metadata = {

                            name: "4MS3",

                            originalName: file,

                            submittedAt: null

                        };


                        if (
                            fs.existsSync(
                                metadataPath
                            )
                        ) {

                            try {

                                metadata =
                                    JSON.parse(
                                        fs.readFileSync(
                                            metadataPath,
                                            "utf8"
                                        )
                                    );

                            }

                            catch (error) {

                                console.error(
                                    "Gallery metadata error:",
                                    error
                                );

                            }

                        }


                        const extension =
                            path.extname(file)
                                .toLowerCase();


                        let type =
                            "image";


                        if (
                            extension === ".mp3"
                        ) {

                            type =
                                "audio";

                        }


                        else if (
                            extension === ".mp4"
                        ) {

                            type =
                                "video";

                        }


                        return {

                            filename:
                                file,

                            originalName:
                                metadata.originalName ||
                                file,

                            name:
                                metadata.name ||
                                "4MS3",

                            submittedAt:
                                metadata.submittedAt ||
                                null,

                            type:
                                type

                        };

                    });


            media.sort(
                (a, b) => {

                    const aDate =
                        new Date(
                            a.submittedAt || 0
                        ).getTime();


                    const bDate =
                        new Date(
                            b.submittedAt || 0
                        ).getTime();


                    return (
                        bDate -
                        aDate
                    );

                }
            );


            res.json(
                media
            );

        }


        catch (error) {

            console.error(
                "Approved gallery error:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Couldn't load approved gallery media."

            });

        }

    }
);

/* =========================================
   APPROVE PHOTO
========================================= */

app.post(
    "/api/approve",
    (req, res) => {

        const filename =
            path.basename(
                req.body.filename || ""
            );


        if (!filename) {

            return res.status(400).json({

                success: false,

                message:
                    "Missing filename."

            });

        }


        const source =
            path.join(
                pendingFolder,
                filename
            );


        const destination =
            path.join(
                approvedFolder,
                filename
            );


        const metadataSource =
            path.join(
                pendingFolder,
                `${filename}.json`
            );


        const metadataDestination =
            path.join(
                approvedFolder,
                `${filename}.json`
            );


        if (
            !fs.existsSync(source)
        ) {

            return res.status(404).json({

                success: false,

                message:
                    "Photo not found."

            });

        }


        try {

            fs.renameSync(
                source,
                destination
            );


            if (
                fs.existsSync(
                    metadataSource
                )
            ) {

                fs.renameSync(
                    metadataSource,
                    metadataDestination
                );

            }


            console.log(
                `✅ Approved: ${filename}`
            );


            res.json({

                success: true

            });


        } catch (error) {

            console.error(error);


            try {

                if (

                    fs.existsSync(
                        destination
                    )

                    &&

                    !fs.existsSync(
                        source
                    )

                ) {

                    fs.renameSync(
                        destination,
                        source
                    );

                }

            } catch (_) {}


            res.status(500).json({

                success: false,

                message:
                    "Couldn't approve photo."

            });

        }

    }
);


/* =========================================
   REJECT PHOTO
========================================= */

app.post(
    "/api/reject",
    (req, res) => {

        const filename =
            path.basename(
                req.body.filename || ""
            );


        if (!filename) {

            return res.status(400).json({

                success: false,

                message:
                    "Missing filename."

            });

        }


        const filePath =
            path.join(
                pendingFolder,
                filename
            );


        const metadataPath =
            path.join(
                pendingFolder,
                `${filename}.json`
            );


        if (
            !fs.existsSync(filePath)
        ) {

            return res.status(404).json({

                success: false,

                message:
                    "Photo not found."

            });

        }


        try {

            fs.unlinkSync(
                filePath
            );


            if (
                fs.existsSync(
                    metadataPath
                )
            ) {

                fs.unlinkSync(
                    metadataPath
                );

            }


            console.log(
                `❌ Rejected: ${filename}`
            );


            res.json({

                success: true

            });


        } catch (error) {

            console.error(error);


            res.status(500).json({

                success: false,

                message:
                    "Couldn't reject photo."

            });

        }

    }
);


/* =========================================
   ASSETS SYSTEM
========================================= */

const assetsFolder =
    path.join(
        __dirname,
        "assets",
        "files"
    );


fs.mkdirSync(
    assetsFolder,
    {
        recursive: true
    }
);


/* Serve downloadable assets */

app.use(
    "/assets/files",
    express.static(assetsFolder)
);


/* =========================================
   FORCE ASSET DOWNLOAD
========================================= */

app.get(
    "/api/assets/download/:filename",
    (req, res) => {

        const filename =
            path.basename(
                req.params.filename
            );


        const filePath =
            path.join(
                assetsFolder,
                filename
            );


        if (
            !fs.existsSync(filePath)
        ) {

            return res.status(404).send(
                "Asset not found."
            );

        }


        res.download(
            filePath,
            filename,
            error => {

                if (error) {

                    console.error(
                        "Asset download error:",
                        error
                    );

                }

            }
        );

    }
);


/* =========================================
   ASSET UPLOAD
========================================= */

const assetStorage =
    multer.diskStorage({

        destination: (
            req,
            file,
            cb
        ) => {

            cb(
                null,
                assetsFolder
            );

        },

        filename: (
            req,
            file,
            cb
        ) => {

            const extension =
                path.extname(
                    file.originalname
                );


            const cleanName =
                path.basename(
                    file.originalname,
                    extension
                )
                .replace(
                    /[^a-zA-Z0-9_-]/g,
                    "_"
                );


            cb(

                null,

                cleanName +
                "-" +
                Date.now() +
                extension

            );

        }

    });


const assetUpload =
    multer({

        storage:
            assetStorage,

        limits: {

            fileSize:
                50 *
                1024 *
                1024

        }

    });


/* =========================================
   GET ASSETS
========================================= */

app.get(
    "/api/assets",
    (req, res) => {

        try {

            const files =
                fs.readdirSync(
                    assetsFolder
                );


            const assets =
                files

                    .filter(
                        file => {

                            return (
                                file !== ".gitkeep" &&
                                !file.endsWith(".json")
                            );

                        }
                    )

                    .map(
                        file => {

                            const filePath =
                                path.join(
                                    assetsFolder,
                                    file
                                );


                            const stats =
                                fs.statSync(
                                    filePath
                                );


                            const metadataPath =
                                path.join(
                                    assetsFolder,
                                    `${file}.json`
                                );


                            let metadata = {

                                title:
                                    path.parse(file).name,

                                category:
                                    "Other"

                            };


                            if (
                                fs.existsSync(
                                    metadataPath
                                )
                            ) {

                                try {

                                    metadata =
                                        JSON.parse(
                                            fs.readFileSync(
                                                metadataPath,
                                                "utf8"
                                            )
                                        );

                                } catch (_) {}

                            }


                            return {

                                filename:
                                    file,

                                title:
                                    metadata.title ||
                                    path.parse(file).name,

                                category:
                                    metadata.category ||
                                    "Other",

                                size:
                                    stats.size

                            };

                        }
                    );


            res.json(
                assets
            );


        } catch (error) {

            console.error(
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Couldn't load assets."

            });

        }

    }
);


/* =========================================
   UPLOAD ASSET
========================================= */

app.post(
    "/api/assets/upload",
    assetUpload.single("asset"),
    (req, res) => {

        if (!req.file) {

            return res.status(400).json({

                success: false,

                message:
                    "No asset was uploaded."

            });

        }


        const title =
            String(
                req.body.title ||
                req.file.originalname
            )
            .trim()
            .slice(0, 80);


        const category =
            String(
                req.body.category ||
                "Other"
            )
            .trim()
            .slice(0, 30);


        const metadataPath =
            path.join(
                assetsFolder,
                `${req.file.filename}.json`
            );


        try {

            fs.writeFileSync(

                metadataPath,

                JSON.stringify(

                    {

                        title:
                            title,

                        category:
                            category,

                        originalName:
                            req.file.originalname,

                        uploadedAt:
                            new Date().toISOString()

                    },

                    null,

                    2

                ),

                "utf8"

            );


            console.log(
                `📦 New asset: ${title}`
            );


            res.json({

                success: true,

                message:
                    "Asset uploaded."

            });


        } catch (error) {

            console.error(
                error
            );


            try {

                fs.unlinkSync(
                    req.file.path
                );

            } catch (_) {}


            res.status(500).json({

                success: false,

                message:
                    "Couldn't save asset."

            });

        }

    }
);


/* =========================================
   DELETE ASSET
========================================= */

app.delete(
    "/api/assets/:filename",
    (req, res) => {

        const filename =
            path.basename(
                req.params.filename
            );


        const filePath =
            path.join(
                assetsFolder,
                filename
            );


        const metadataPath =
            path.join(
                assetsFolder,
                `${filename}.json`
            );


        if (
            !fs.existsSync(filePath)
        ) {

            return res.status(404).json({

                success: false,

                message:
                    "Asset not found."

            });

        }


        try {

            fs.unlinkSync(
                filePath
            );


            if (
                fs.existsSync(
                    metadataPath
                )
            ) {

                fs.unlinkSync(
                    metadataPath
                );

            }


            console.log(
                `🗑️ Deleted asset: ${filename}`
            );


            res.json({

                success: true

            });


        } catch (error) {

            console.error(
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Couldn't delete asset."

            });

        }

    }
);





if (!fs.existsSync(leaderboardFile)) {

    fs.writeFileSync(
        leaderboardFile,
        "[]",
        "utf8"
    );

}


/* =========================================
   GET LEADERBOARD
========================================= */

app.get(
    "/api/leaderboard",
    (req, res) => {

        try {

            const data =
                fs.readFileSync(
                    leaderboardFile,
                    "utf8"
                );


            const leaderboard =
                JSON.parse(data);


            leaderboard.sort(
                (a, b) =>
                    Number(b.grade) -
                    Number(a.grade)
            );


            res.json(
                leaderboard
            );


        } catch (error) {

            console.error(
                "Leaderboard load error:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Couldn't load leaderboard."

            });

        }

    }
);




/* =========================================
   SAVE LEADERBOARD
========================================= */

app.post(
    "/api/leaderboard",
    (req, res) => {

        try {

            if (
                !Array.isArray(
                    req.body
                )
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid leaderboard data."

                });

            }


            const cleaned =
                req.body

                    .map(
                        student => {

                            return {

                                name:
                                    String(
                                        student.name ||
                                        ""
                                    )
                                    .trim()
                                    .slice(
                                        0,
                                        80
                                    ),

                                grade:
                                    Number(
                                        student.grade
                                    )

                            };

                        }
                    )

                    .filter(
                        student => {

                            return (

                                student.name &&

                                Number.isFinite(
                                    student.grade
                                ) &&

                                student.grade >=
                                    0 &&

                                student.grade <=
                                    20

                            );

                        }
                    );


            cleaned.sort(
                (a, b) =>
                    b.grade -
                    a.grade
            );


            fs.writeFileSync(

                leaderboardFile,

                JSON.stringify(
                    cleaned,
                    null,
                    4
                ),

                "utf8"

            );


            console.log(
                "🏆 Leaderboard updated."
            );


            res.json({

                success:
                    true,

                leaderboard:
                    cleaned

            });


        } catch (error) {

            console.error(
                "Leaderboard save error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't save leaderboard."

            });

        }

    }
);


/* =========================================
   NOTIFICATION SYSTEM
========================================= */

const notificationsFile =
    path.join(
        __dirname,
        "notifications.json"
    );


if (!fs.existsSync(notificationsFile)) {

    fs.writeFileSync(
        notificationsFile,
        "[]",
        "utf8"
    );

}


/* =========================================
   GET NOTIFICATIONS
========================================= */

app.get(
    "/api/notifications",
    (req, res) => {

        try {

            const data =
                fs.readFileSync(
                    notificationsFile,
                    "utf8"
                );


            const notifications =
                JSON.parse(data);


            notifications.sort(
                (a, b) =>
                    new Date(
                        b.createdAt
                    ) -
                    new Date(
                        a.createdAt
                    )
            );


            res.json(
                notifications
            );


        } catch (error) {

            console.error(
                "Notification load error:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Couldn't load notifications."

            });

        }

    }
);


/* =========================================
   CREATE NOTIFICATION
========================================= */

app.post(
    "/api/notifications",
    (req, res) => {

        try {

            const title =
                String(
                    req.body.title || ""
                )
                .trim()
                .slice(
                    0,
                    100
                );


            const message =
                String(
                    req.body.message || ""
                )
                .trim()
                .slice(
                    0,
                    300
                );


            const type =
                String(
                    req.body.type ||
                    "info"
                )
                .trim()
                .slice(
                    0,
                    30
                );


            if (
                !title ||
                !message
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Title and message are required."

                });

            }


            const data =
                fs.readFileSync(
                    notificationsFile,
                    "utf8"
                );


            const notifications =
                JSON.parse(data);


            const notification = {

                id:
                    Date.now().toString(),

                title:
                    title,

                message:
                    message,

                type:
                    type,

                createdAt:
                    new Date().toISOString()

            };


            notifications.push(
                notification
            );


            const limited =
                notifications.slice(
                    -100
                );


            fs.writeFileSync(

                notificationsFile,

                JSON.stringify(
                    limited,
                    null,
                    4
                ),

                "utf8"

            );


            console.log(
                `🔔 New notification: ${title}`
            );


            res.json({

                success:
                    true,

                notification:
                    notification

            });


        } catch (error) {

            console.error(
                "Notification save error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't create notification."

            });

        }

    }
);


/* =========================================
   DELETE NOTIFICATION
========================================= */

app.delete(
    "/api/notifications/:id",
    (req, res) => {

        try {

            const id =
                String(
                    req.params.id
                );


            const data =
                fs.readFileSync(
                    notificationsFile,
                    "utf8"
                );


            const notifications =
                JSON.parse(data);


            const filtered =
                notifications.filter(
                    notification =>
                        String(
                            notification.id
                        ) !==
                        id
                );


            fs.writeFileSync(

                notificationsFile,

                JSON.stringify(
                    filtered,
                    null,
                    4
                ),

                "utf8"

            );


            res.json({

                success:
                    true

            });


        } catch (error) {

            console.error(
                "Notification delete error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't delete notification."

            });

        }

    }
);


/* =========================================
   STUDENT OF THE WEEK
========================================= */

const studentOfWeekFile =
    path.join(
        __dirname,
        "studentOfWeek.json"
    );


if (!fs.existsSync(studentOfWeekFile)) {

    fs.writeFileSync(

        studentOfWeekFile,

        JSON.stringify(

            {

                student:
                    "",

                title:
                    "",

                reason:
                    "",

                updatedAt:
                    null

            },

            null,

            4

        ),

        "utf8"

    );

}


/* =========================================
   GET STUDENT OF THE WEEK
========================================= */

app.get(
    "/api/student-of-week",
    (req, res) => {

        try {

            const data =
                fs.readFileSync(
                    studentOfWeekFile,
                    "utf8"
                );


            const studentOfWeek =
                JSON.parse(data);


            res.json(
                studentOfWeek
            );


        } catch (error) {

            console.error(
                "Student of the week load error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't load Student of the Week."

            });

        }

    }
);


/* =========================================
   SAVE STUDENT OF THE WEEK
========================================= */

app.post(
    "/api/student-of-week",
    (req, res) => {

        try {

            const student =
                String(
                    req.body.student ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    80
                );


            const title =
                String(
                    req.body.title ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    100
                );


            const reason =
                String(
                    req.body.reason ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    300
                );


            if (
                !student ||
                !title ||
                !reason
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Student, title and reason are required."

                });

            }


            const leaderboardData =
                fs.readFileSync(
                    leaderboardFile,
                    "utf8"
                );


            const leaderboard =
                JSON.parse(
                    leaderboardData
                );


            const studentExists =
                leaderboard.some(
                    entry =>
                        String(
                            entry.name || ""
                        )
                        .trim()
                        .toLowerCase() ===
                        student.toLowerCase()
                );


            if (!studentExists) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "That student is not in the class leaderboard."

                });

            }


            const result = {

                student:
                    student,

                title:
                    title,

                reason:
                    reason,

                updatedAt:
                    new Date().toISOString()

            };


            fs.writeFileSync(

                studentOfWeekFile,

                JSON.stringify(
                    result,
                    null,
                    4
                ),

                "utf8"

            );


            const notificationsData =
                fs.readFileSync(
                    notificationsFile,
                    "utf8"
                );


            const notifications =
                JSON.parse(
                    notificationsData
                );


            notifications.push({

                id:
                    Date.now().toString(),

                title:
                    "Student of the Week",

                message:
                    `${student} has been selected as Student of the Week!`,

                type:
                    "info",

                createdAt:
                    new Date().toISOString()

            });


            fs.writeFileSync(

                notificationsFile,

                JSON.stringify(
                    notifications.slice(-100),
                    null,
                    4
                ),

                "utf8"

            );


            console.log(
                `⭐ Student of the Week: ${student}`
            );


            res.json({

                success:
                    true,

                studentOfWeek:
                    result

            });


        } catch (error) {

            console.error(
                "Student of the week save error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't save Student of the Week."

            });

        }

    }
);

/* =========================================
   STUDENT ACHIEVEMENTS SYSTEM
========================================= */

const achievementsFile =
    path.join(
        __dirname,
        "achievements.json"
    );


if (
    !fs.existsSync(
        achievementsFile
    )
) {

    fs.writeFileSync(
        achievementsFile,
        "{}",
        "utf8"
    );

}


/* =========================================
   NORMALIZE STUDENT NAME
========================================= */

function normalizeAchievementName(
    name
) {

    return String(
        name || ""
    )
    .trim()
    .replace(
        /\s+/g,
        " "
    )
    .toLowerCase();

}


/* =========================================
   LOAD ACHIEVEMENTS
========================================= */

function loadAchievements() {

    try {

        const data =
            fs.readFileSync(
                achievementsFile,
                "utf8"
            );


        const achievements =
            JSON.parse(
                data
            );


        if (
            achievements &&
            typeof achievements === "object" &&
            !Array.isArray(achievements)
        ) {

            return achievements;

        }


        return {};

    }

    catch (error) {

        console.error(
            "Achievement load error:",
            error
        );


        return {};

    }

}


/* =========================================
   SAVE ACHIEVEMENTS
========================================= */

function saveAchievements(
    achievements
) {

    fs.writeFileSync(

        achievementsFile,

        JSON.stringify(
            achievements,
            null,
            4
        ),

        "utf8"

    );

}


/* =========================================
   GET ALL STUDENT ACHIEVEMENTS
========================================= */

app.get(
    "/api/student-achievements",
    (req, res) => {

        try {

            const achievements =
                loadAchievements();


            res.json(
                achievements
            );

        }

        catch (error) {

            console.error(
                "Student achievement API error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't load achievements."

            });

        }

    }
);


/* =========================================
   GET ONE STUDENT'S ACHIEVEMENTS
========================================= */

app.get(
    "/api/student-achievements/:student",
    (req, res) => {

        try {

            const student =
                String(
                    req.params.student ||
                    ""
                )
                .trim();


            const achievements =
                loadAchievements();


            const key =
                normalizeAchievementName(
                    student
                );


            res.json({

                success:
                    true,

                student:
                    student,

                achievements:
                    Array.isArray(
                        achievements[key]
                    )
                        ? achievements[key]
                        : []

            });

        }

        catch (error) {

            console.error(
                "Student achievement load error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't load student achievements."

            });

        }

    }
);


/* =========================================
   ADD STUDENT ACHIEVEMENT
========================================= */

app.post(
    "/api/student-achievements",
    (req, res) => {

        try {

            const student =
                String(
                    req.body.student ||
                    ""
                )
                .trim()
                .replace(
                    /\s+/g,
                    " "
                )
                .slice(
                    0,
                    80
                );


            const icon =
                String(
                    req.body.icon ||
                    "🏆"
                )
                .trim()
                .slice(
                    0,
                    10
                );


            const title =
                String(
                    req.body.title ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    100
                );


            const date =
                String(
                    req.body.date ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    50
                );


            const description =
                String(
                    req.body.description ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    400
                );


            if (
                !student ||
                !title ||
                !description
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    message:
                        "Student, title and description are required."

                });

            }


            const achievements =
                loadAchievements();


            const key =
                normalizeAchievementName(
                    student
                );


            if (
                !achievements[key]
            ) {

                achievements[key] =
                    [];

            }


            const achievement = {

                id:
                    Date.now().toString() +
                    "-" +
                    Math.random()
                        .toString(36)
                        .slice(
                            2,
                            8
                        ),

                student:
                    student,

                icon:
                    icon || "🏆",

                title:
                    title,

                date:
                    date,

                description:
                    description,

                createdAt:
                    new Date().toISOString()

            };


            achievements[key].push(
                achievement
            );


            saveAchievements(
                achievements
            );


            console.log(
                `🏆 Achievement added for ${student}: ${title}`
            );


            res.json({

                success:
                    true,

                achievement:
                    achievement

            });

        }

        catch (error) {

            console.error(
                "Achievement save error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't save achievement."

            });

        }

    }
);


/* =========================================
   DELETE STUDENT ACHIEVEMENT
========================================= */

app.delete(
    "/api/student-achievements/:student/:id",
    (req, res) => {

        try {

            const student =
                String(
                    req.params.student ||
                    ""
                )
                .trim();


            const id =
                String(
                    req.params.id ||
                    ""
                );


            const achievements =
                loadAchievements();


            const key =
                normalizeAchievementName(
                    student
                );


            if (
                !Array.isArray(
                    achievements[key]
                )
            ) {

                return res.status(
                    404
                ).json({

                    success:
                        false,

                    message:
                        "Student achievements not found."

                });

            }


            const before =
                achievements[key].length;


            achievements[key] =
                achievements[key].filter(
                    achievement =>
                        String(
                            achievement.id
                        ) !== id
                );


            if (
                achievements[key].length ===
                before
            ) {

                return res.status(
                    404
                ).json({

                    success:
                        false,

                    message:
                        "Achievement not found."

                });

            }


            if (
                achievements[key].length === 0
            ) {

                delete achievements[key];

            }


            saveAchievements(
                achievements
            );


            console.log(
                `🗑️ Achievement deleted for ${student}`
            );


            res.json({

                success:
                    true

            });

        }

        catch (error) {

            console.error(
                "Achievement delete error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't delete achievement."

            });

        }

    }
);

/* =========================================
   WEB PUSH PUBLIC KEY
========================================= */

app.get(
    "/api/push/public-key",
    (req, res) => {

        if (
            !VAPID_PUBLIC_KEY
        ) {

            return res.status(
                503
            ).json({

                success:
                    false,

                message:
                    "Push notifications are not configured."

            });

        }


        res.json({

            success:
                true,

            publicKey:
                VAPID_PUBLIC_KEY

        });

    }
);

/* =========================================
   SAVE PUSH SUBSCRIPTION
========================================= */

app.post(
    "/api/push/subscribe",
    requireStudentAuth,
    (req, res) => {

        try {

            const subscription =
                req.body.subscription;


            if (
                !subscription ||
                !subscription.endpoint
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    message:
                        "Invalid push subscription."

                });

            }


            const studentName =
                req.user.name;


            const subscriptions =
                loadPushSubscriptions();


            const key =
                normalizeAuthName(
                    studentName
                );


            if (
                !Array.isArray(
                    subscriptions[key]
                )
            ) {

                subscriptions[key] =
                    [];

            }


            const alreadyExists =
                subscriptions[key].some(
                    item =>
                        item.endpoint ===
                        subscription.endpoint
                );


            if (
                !alreadyExists
            ) {

                subscriptions[key].push(
                    subscription
                );

            }


            savePushSubscriptions(
                subscriptions
            );


            res.json({

                success:
                    true

            });

        }

        catch (error) {

            console.error(
                "Push subscription error:",
                error
            );


            res.status(
                500
            ).json({

                success:
                    false,

                message:
                    "Couldn't save notification settings."

            });

        }

    }
);

/* =========================================
   SEND PUSH NOTIFICATION
========================================= */

async function sendShoutboxPush(
    senderName,
    message
) {

    if (
        !VAPID_PUBLIC_KEY ||
        !VAPID_PRIVATE_KEY
    ) {

        return;

    }


    const subscriptions =
        loadPushSubscriptions();


    const senderKey =
        normalizeAuthName(
            senderName
        );


    const payload =
        JSON.stringify({

            title:
                "💬 New 4MS3 Shoutbox Message",

            body:
                `${senderName}: ${message}`,

            url:
                "/#shoutbox"

        });


    for (
        const [
            studentKey,
            studentSubscriptions
        ]
        of Object.entries(
            subscriptions
        )
    ) {

        /*
         * Don't notify the person who
         * sent the message.
         */

        if (
            studentKey ===
            senderKey
        ) {

            continue;

        }


        if (
            !Array.isArray(
                studentSubscriptions
            )
        ) {

            continue;

        }


        const remaining =
            [];


        for (
            const subscription
            of studentSubscriptions
        ) {

            try {

                await webpush.sendNotification(
                    subscription,
                    payload
                );


                remaining.push(
                    subscription
                );

            }

            catch (error) {

                /*
                 * 404 / 410 means the browser
                 * subscription is no longer valid.
                 */

                if (
                    error.statusCode !==
                        404 &&
                    error.statusCode !==
                        410
                ) {

                    console.error(
                        "Push notification error:",
                        error
                    );


                    remaining.push(
                        subscription
                    );

                }

            }

        }


        subscriptions[studentKey] =
            remaining;

    }


    savePushSubscriptions(
        subscriptions
    );

}


/* =========================================
   SHOUTBOX SYSTEM
========================================= */

const shoutboxFile =
    path.join(
        __dirname,
        "shoutbox.json"
    );


if (!fs.existsSync(shoutboxFile)) {

    fs.writeFileSync(
        shoutboxFile,
        "[]",
        "utf8"
    );

}


/* =========================================
   GET SHOUTBOX
========================================= */

app.get(
    "/api/shoutbox",
    (req, res) => {

        try {

            const data =
                fs.readFileSync(
                    shoutboxFile,
                    "utf8"
                );


            const messages =
                JSON.parse(data);


            messages.sort(
                (a, b) =>
                    new Date(
                        a.createdAt
                    ) -
                    new Date(
                        b.createdAt
                    )
            );


            res.json(
                messages
            );


        } catch (error) {

            console.error(
                "Shoutbox load error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't load shoutbox."

            });

        }

    }
);


/* =========================================
   POST SHOUTBOX MESSAGE
========================================= */

app.post(
    "/api/shoutbox",
    (req, res) => {

        try {

            const name =
                String(
                    req.body.name ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    80
                );


            const message =
                String(
                    req.body.message ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    300
                );


            if (
                !name ||
                !message
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Name and message are required."

                });

            }


            const data =
                fs.readFileSync(
                    shoutboxFile,
                    "utf8"
                );


            const messages =
                JSON.parse(
                    data
                );


            const newMessage = {

                id:
                    Date.now().toString() +
                    "-" +
                    Math.random()
                        .toString(36)
                        .slice(
                            2,
                            8
                        ),

                name:
                    name,

                message:
                    message,

                createdAt:
                    new Date().toISOString()

            };


            messages.push(
                newMessage
            );


            fs.writeFileSync(

                shoutboxFile,

                JSON.stringify(
                    messages.slice(-200),
                    null,
                    4
                ),

                "utf8"

            );


console.log(
    `💬 Shoutbox message from ${name}`
);


/*
 * Notify everyone who enabled
 * Shoutbox push notifications.
 *
 * Don't make the Shoutbox request
 * wait for notifications to finish.
 */

sendShoutboxPush(
    name,
    message
).catch(
    error => {

        console.error(
            "Shoutbox push error:",
            error
        );

    }
);

            res.json({

                success:
                    true,

                message:
                    newMessage

            });


        } catch (error) {

            console.error(
                "Shoutbox save error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't send message."

            });

        }

    }
);


/* =========================================
   DELETE SHOUTBOX MESSAGE
========================================= */

app.delete(
    "/api/shoutbox/:id",
    (req, res) => {

        try {

            const id =
                String(
                    req.params.id
                );


            const data =
                fs.readFileSync(
                    shoutboxFile,
                    "utf8"
                );


            const messages =
                JSON.parse(data);


            const filtered =
                messages.filter(
                    item =>
                        String(
                            item.id
                        ) !==
                        id
                );


            fs.writeFileSync(

                shoutboxFile,

                JSON.stringify(
                    filtered,
                    null,
                    4
                ),

                "utf8"

            );


            res.json({

                success:
                    true

            });


        } catch (error) {

            console.error(
                "Shoutbox delete error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't delete message."

            });

        }

    }
);



/* =========================================
   ANNOUNCEMENTS SYSTEM
========================================= */

const announcementsFile =
    path.join(
        __dirname,
        "announcements.json"
    );


if (!fs.existsSync(announcementsFile)) {

    fs.writeFileSync(
        announcementsFile,
        "[]",
        "utf8"
    );

}


/* =========================================
   GET ANNOUNCEMENTS
========================================= */

app.get(
    "/api/announcements",
    (req, res) => {

        try {

            const data =
                fs.readFileSync(
                    announcementsFile,
                    "utf8"
                );


            const announcements =
                JSON.parse(
                    data
                );


            announcements.sort(
                (a, b) =>
                    new Date(
                        b.createdAt
                    ) -
                    new Date(
                        a.createdAt
                    )
            );


            res.json(
                announcements
            );


        } catch (error) {

            console.error(
                "Announcement load error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't load announcements."

            });

        }

    }
);


/* =========================================
   CREATE ANNOUNCEMENT
========================================= */

app.post(
    "/api/announcements",
    (req, res) => {

        try {

            const title =
                String(
                    req.body.title ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    100
                );


            const message =
                String(
                    req.body.message ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    500
                );


            const type =
                String(
                    req.body.type ||
                    "info"
                )
                .trim()
                .slice(
                    0,
                    30
                );


            const dueDate =
                String(
                    req.body.dueDate ||
                    ""
                )
                .trim()
                .slice(
                    0,
                    20
                );


            if (
                !title ||
                !message
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        "Title and message are required."

                });

            }


            const data =
                fs.readFileSync(
                    announcementsFile,
                    "utf8"
                );


            const announcements =
                JSON.parse(
                    data
                );


            const announcement = {

                id:
                    Date.now().toString(),

                title:
                    title,

                message:
                    message,

                type:
                    type,

                dueDate:
                    dueDate,

                createdAt:
                    new Date().toISOString()

            };


            announcements.push(
                announcement
            );


            fs.writeFileSync(

                announcementsFile,

                JSON.stringify(
                    announcements.slice(-100),
                    null,
                    4
                ),

                "utf8"

            );


            const notificationsData =
                fs.readFileSync(
                    notificationsFile,
                    "utf8"
                );


            const notifications =
                JSON.parse(
                    notificationsData
                );


            notifications.push({

                id:
                    Date.now().toString() +
                    "-announcement",

                title:
                    title,

                message:
                    message,

                type:
                    "event",

                createdAt:
                    new Date().toISOString()

            });


            fs.writeFileSync(

                notificationsFile,

                JSON.stringify(
                    notifications.slice(-100),
                    null,
                    4
                ),

                "utf8"

            );


            console.log(
                `📅 New announcement: ${title}`
            );


            res.json({

                success:
                    true,

                announcement:
                    announcement

            });


        } catch (error) {

            console.error(
                "Announcement save error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't create announcement."

            });

        }

    }
);


/* =========================================
   DELETE ANNOUNCEMENT
========================================= */

app.delete(
    "/api/announcements/:id",
    (req, res) => {

        try {

            const id =
                String(
                    req.params.id
                );


            const data =
                fs.readFileSync(
                    announcementsFile,
                    "utf8"
                );


            const announcements =
                JSON.parse(
                    data
                );


            const filtered =
                announcements.filter(
                    announcement =>
                        String(
                            announcement.id
                        ) !==
                        id
                );


            fs.writeFileSync(

                announcementsFile,

                JSON.stringify(
                    filtered,
                    null,
                    4
                ),

                "utf8"

            );


            res.json({

                success:
                    true

            });


        } catch (error) {

            console.error(
                "Announcement delete error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't delete announcement."

            });

        }

    }
);


/* =========================================
   CHESS MATCHMAKING + ONLINE GAME SYSTEM
========================================= */

/* =========================================
   CHESS MATCHMAKING + ONLINE GAME SYSTEM
========================================= */

let chessQueue = [];

const chessMatches =
    new Map();
/* =========================================
   CHESS CLOCK SETTINGS
========================================= */

const CHESS_INITIAL_TIME =
    15 * 60 * 1000;


/* =========================================
   GET LIVE CLOCKS
========================================= */

function getChessClockState(match) {

    let whiteTime =
        match.whiteTimeMs;

    let blackTime =
        match.blackTimeMs;


    /*
     * Once a player has made a move,
     * their clock stops and the opponent's
     * clock starts.
     */

    if (
        !match.timeOutBy &&
        !match.game.isGameOver() &&
        match.turnStartedAt
    ) {

        const elapsed =
            Date.now() -
            match.turnStartedAt;


        if (
            match.game.turn() === "w"
        ) {

            whiteTime =
                Math.max(
                    0,
                    whiteTime -
                    elapsed
                );

        } else {

            blackTime =
                Math.max(
                    0,
                    blackTime -
                    elapsed
                );

        }

    }


    return {
        whiteTimeMs:
            whiteTime,

        blackTimeMs:
            blackTime,

        turnStartedAt:
            match.turnStartedAt || null
    };

}


/* =========================================
   CHECK CLOCK TIMEOUT
========================================= */

function updateChessTimeout(
    match
) {

    if (
        match.timeOutBy ||
        match.game.isGameOver()
    ) {

        return;

    }


    const clocks =
        getChessClockState(
            match
        );


    const currentColor =
        match.game.turn() === "w"
            ? "white"
            : "black";


    const currentTime =
        currentColor === "white"
            ? clocks.whiteTimeMs
            : clocks.blackTimeMs;


    if (
        currentTime > 0
    ) {

        return;

    }


    const timedOutPlayer =
        match.players.find(
            player =>
                match.colors[player] ===
                currentColor
        );


    if (
        !timedOutPlayer
    ) {

        return;

    }


    /*
     * Store the frozen clock values.
     */

    match.whiteTimeMs =
        clocks.whiteTimeMs;

    match.blackTimeMs =
        clocks.blackTimeMs;


    match.timeOutBy =
        timedOutPlayer;


    console.log(
        `⏱ CHESS TIMEOUT: ${timedOutPlayer} ran out of time in ${match.matchId}`
    );

}

/* =========================================
   CHESS STATISTICS
========================================= */

const chessStatsFile =
    path.join(
        __dirname,
        "chessStats.json"
    );


if (
    !fs.existsSync(
        chessStatsFile
    )
) {

    fs.writeFileSync(
        chessStatsFile,
        "{}",
        "utf8"
    );

}


/* =========================================
   LOAD CHESS STATS
========================================= */

function loadChessStats() {

    try {

        const data =
            fs.readFileSync(
                chessStatsFile,
                "utf8"
            );

        const stats =
            JSON.parse(data);

        return (
            stats &&
            typeof stats === "object"
        )
            ? stats
            : {};

    } catch (error) {

        console.error(
            "Chess stats load error:",
            error
        );

        return {};

    }

}


/* =========================================
   SAVE CHESS STATS
========================================= */

function saveChessStats(
    stats
) {

    fs.writeFileSync(
        chessStatsFile,
        JSON.stringify(
            stats,
            null,
            4
        ),
        "utf8"
    );

}


/* =========================================
   NORMALIZE STUDENT NAME
========================================= */

function normalizeChessStatsName(
    name
) {

    return String(
        name || ""
    )
    .trim()
    .replace(
        /\s+/g,
        " "
    )
    .toLowerCase();

}


/* =========================================
   RECORD CHESS RESULT
========================================= */

function recordChessResult(
    match
) {

    if (
        !match ||
        match.statsRecorded ||
        match.players.length !== 2
    ) {

        return;

    }


const gameEnded =
    match.game.isGameOver() ||
    Boolean(
        match.resignedBy
    ) ||
    Boolean(
        match.timeOutBy
    );


    if (!gameEnded) {

        return;

    }


    const stats =
        loadChessStats();


    const players =
        match.players;


    const playerA =
        players[0];


    const playerB =
        players[1];


    const keyA =
        normalizeChessStatsName(
            playerA
        );


    const keyB =
        normalizeChessStatsName(
            playerB
        );


    if (!keyA || !keyB) {

        return;

    }


    if (!stats[keyA]) {

        stats[keyA] = {
            name:
                playerA,
            games:
                0,
            wins:
                0,
            losses:
                0,
            draws:
                0
        };

    }


    if (!stats[keyB]) {

        stats[keyB] = {
            name:
                playerB,
            games:
                0,
            wins:
                0,
            losses:
                0,
            draws:
                0
        };

    }


    stats[keyA].games++;
    stats[keyB].games++;


    /* =====================================
       RESIGNATION
    ===================================== */

    if (
        match.resignedBy
    ) {

        const resignedKey =
            normalizeChessStatsName(
                match.resignedBy
            );


        if (
            resignedKey ===
            keyA
        ) {

            stats[keyA].losses++;
            stats[keyB].wins++;

        }

        else if (
            resignedKey ===
            keyB
        ) {

            stats[keyB].losses++;
            stats[keyA].wins++;

        }

    }


    /* =====================================
       CHECKMATE
    ===================================== */

    else if (
        match.game.isCheckmate()
    ) {

        /*
         * chess.js leaves the losing
         * side as the side to move.
         */

        const loserColor =
            match.game.turn() === "w"
                ? "white"
                : "black";


        const loser =
            match.players.find(
                player =>
                    match.colors[player] ===
                    loserColor
            );


        const winner =
            match.players.find(
                player =>
                    player !== loser
            );


        if (
            loser &&
            winner
        ) {

            const loserKey =
                normalizeChessStatsName(
                    loser
                );


            const winnerKey =
                normalizeChessStatsName(
                    winner
                );


            if (
                stats[loserKey] &&
                stats[winnerKey]
            ) {

                stats[loserKey].losses++;
                stats[winnerKey].wins++;

            }

        }

    }


    /* =====================================
       DRAW
    ===================================== */

    else {

        stats[keyA].draws++;
        stats[keyB].draws++;

    }


    match.statsRecorded =
        true;


    saveChessStats(
        stats
    );


    console.log(
        `📊 Chess result recorded: ${playerA} vs ${playerB}`
    );

}
/* =========================================
   CREATE MATCH
========================================= */

function createChessMatch(
    playerA,
    playerB,
    swapColors = false
) {

    const matchId =
        Date.now().toString() +
        "-" +
        Math.random()
            .toString(36)
            .slice(2, 8);


    const chessGame =
        new Chess();


    const colors =
        swapColors

            ? {
                [playerA]: "black",
                [playerB]: "white"
            }

            : {
                [playerA]: "white",
                [playerB]: "black"
            };


    const match = {

        matchId:

            matchId,


        players: [

            playerA,

            playerB

        ],


        colors:


            colors,


        game:

            chessGame,


        lastMove:

            null,


        resignedBy:

            null,


        createdAt:

            Date.now(),


        rematchRequest:

            null,


        rematchResponse:

            null,


        rematchMatchId:

    null,


/* =========================================
   CHESS CLOCKS
========================================= */

whiteTimeMs:

    CHESS_INITIAL_TIME,


blackTimeMs:

    CHESS_INITIAL_TIME,


turnStartedAt:

    Date.now(),


timeOutBy:

    null,

            
        statsRecorded:
         false
   
        

    };


    chessMatches.set(
        matchId,
        match
    );


    return match;

}


/* =========================================
   FIND ACTIVE MATCH
========================================= */

function findChessActiveMatch(
    name
) {

    const normalizedName =
        String(
            name || ""
        )
        .trim()
        .toLowerCase();


    if (
        !normalizedName
    ) {

        return null;

    }


    for (
        const match
        of chessMatches.values()
    ) {

        if (
            !match.game ||
            match.resignedBy
        ) {

            continue;

        }


        if (
            match.game.isGameOver()
        ) {

            continue;

        }


        const belongsToMatch =
            match.players.some(
                player =>
                    player
                        .toLowerCase() ===
                    normalizedName
            );


        if (
            belongsToMatch
        ) {

            return match;

        }

    }


    return null;

}


/* =========================================
   FIND ANY MATCH
========================================= */

function findChessMatch(
    name
) {

    const normalizedName =
        String(
            name || ""
        )
        .trim()
        .toLowerCase();


    if (
        !normalizedName
    ) {

        return null;

    }


    for (
        const match
        of chessMatches.values()
    ) {

        const belongsToMatch =
            match.players.some(
                player =>
                    player
                        .toLowerCase() ===
                    normalizedName
            );


        if (
            belongsToMatch
        ) {

            return match;

        }

    }


    return null;

}


/* =========================================
   CLEAN OLD CHESS DATA
========================================= */

function cleanChessData() {

    const now =
        Date.now();


    /*
     * Waiting players expire after 10 minutes.
     */

    chessQueue =
        chessQueue.filter(
            player =>
                now -
                player.joinedAt <
                10 * 60 * 1000
        );


    /*
     * Matches expire after 2 hours.
     */

    for (
        const [
            matchId,
            match
        ]
        of chessMatches
    ) {

        if (
            now -
            match.createdAt >
            2 * 60 * 60 * 1000
        ) {

            chessMatches.delete(
                matchId
            );

        }

    }

}


/* =========================================
   MATCH STATE FOR PLAYER
========================================= */

function getChessMatchState(
    match,
    playerName
) {

    const normalizedName =
        String(
            playerName || ""
        )
        .trim()
        .toLowerCase();


    const playerIndex =
        match.players.findIndex(
            player =>
                player
                    .toLowerCase() ===
                normalizedName
        );


    if (
        playerIndex === -1
    ) {

        return null;

    }


    const player =
        match.players[
            playerIndex
        ];


    const opponent =
        match.players[
            playerIndex === 0
                ? 1
                : 0
        ];

updateChessTimeout(
    match
);

const clockState =
    getChessClockState(
        match
);
    return {

        success:
            true,


        matched:
            true,


        matchId:
            match.matchId,


        player:
            player,


        opponent:
            opponent,


        color:
            match.colors[
                player
            ],


        opponentColor:
            match.colors[
                opponent
            ],


        fen:
            match.game.fen(),


        turn:
            match.game.turn(),


        isGameOver:
            match.game.isGameOver(),


        isCheck:
            match.game.inCheck(),


        isCheckmate:
            match.game.isCheckmate(),


        isStalemate:
            match.game.isStalemate(),


        isDraw:
            match.game.isDraw(),


        resignedBy:
            match.resignedBy ||
            null,
            timeOutBy:
    match.timeOutBy ||
    null,

whiteTimeMs:
    clockState.whiteTimeMs,

blackTimeMs:
    clockState.blackTimeMs,

turnStartedAt:
    clockState.turnStartedAt,


        lastMove:
            match.lastMove ||
            null

    };

}


/* =========================================
   QUEUE STATUS
========================================= */

app.get(
    "/api/chess/queue",
    (req, res) => {

        try {

            cleanChessData();


            res.json({

                success:
                    true,


                waiting:
                    chessQueue.length

            });


        } catch (error) {

            console.error(
                "Chess queue status error:",
                error
            );


            res.status(500).json({

                success:
                    false,


                message:
                    "Couldn't read chess queue."

            });

        }

    }
);


/* =========================================
   PLAYER MATCH / QUEUE STATUS
========================================= */

app.get(
    "/api/chess/queue/status",
    (req, res) => {

        try {

            cleanChessData();


            const name =
                String(
                    req.query.name || ""
                )
                .trim();


            if (
                !name
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,


                    message:
                        "Name is required."

                });

            }


            /*
             * ONLY return an active match.
             *
             * Finished games must NOT
             * automatically count as matches.
             */

            const activeMatch =
                findChessActiveMatch(
                    name
                );


            if (
                !activeMatch
            ) {

                const waiting =
                    chessQueue.some(
                        player =>
                            player.name
                                .toLowerCase() ===
                            name.toLowerCase()
                    );


                return res.json({

                    success:
                        true,


                    matched:
                        false,


                    waiting:
                        waiting

                });

            }


            const state =
                getChessMatchState(
                    activeMatch,
                    name
                );


            if (
                !state
            ) {

                return res.status(
                    403
                ).json({

                    success:
                        false,


                    message:
                        "You are not part of this match."

                });

            }


            res.json(
                state
            );


        } catch (error) {

            console.error(
                "Chess match status error:",
                error
            );


            res.status(500).json({

                success:
                    false,


                message:
                    "Couldn't check match status."

            });

        }

    }
);


/* =========================================
   JOIN NORMAL QUEUE
========================================= */

app.post(
    "/api/chess/queue/join",
    (req, res) => {

        try {

            cleanChessData();


            const name =
                String(
                    req.body.name || ""
                )
                .trim()
                .slice(0, 80);


            const avoidOpponent =
                String(
                    req.body.avoidOpponent ||
                    ""
                )
                .trim()
                .toLowerCase();


            if (
                !name
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,


                    message:
                        "Your name is required."

                });

            }


            const normalizedName =
                name.toLowerCase();


            /*
             * Already in an active game?
             * Return that game.
             */

            const existingMatch =
                findChessActiveMatch(
                    name
                );


            if (
                existingMatch
            ) {

                return res.json(
                    getChessMatchState(
                        existingMatch,
                        name
                    )
                );

            }


            /*
             * Remove stale duplicate queue entry.
             */

            chessQueue =
                chessQueue.filter(
                    player =>
                        player.name
                            .toLowerCase() !==
                        normalizedName
                );


            /*
             * Find a waiting opponent.
             *
             * IMPORTANT:
             * avoidOpponent is honored.
             */

            const opponentIndex =
    chessQueue.findIndex(
        player => {

            const otherName =
                player.name
                    .toLowerCase();


            const otherAvoidOpponent =
                String(
                    player.avoidOpponent ||
                    ""
                )
                .trim()
                .toLowerCase();


            if (
                otherName ===
                normalizedName
            ) {

                return false;

            }


            if (
                avoidOpponent &&
                otherName ===
                avoidOpponent
            ) {

                return false;

            }


            if (
                otherAvoidOpponent &&
                otherAvoidOpponent ===
                normalizedName
            ) {

                return false;

            }


            return true;

        }
    );

            /*
             * Someone is waiting.
             */

            if (
                opponentIndex !== -1
            ) {

                const opponent =
                    chessQueue.splice(
                        opponentIndex,
                        1
                    )[0];


                const match =
                    createChessMatch(
                        opponent.name,
                        name,
                        false
                    );


                console.log(
                    `♟ ONLINE CHESS MATCH: ${opponent.name} vs ${name}`
                );


                return res.json(
                    getChessMatchState(
                        match,
                        name
                    )
                );

            }


            /*
             * Nobody available.
             */

            chessQueue.push({

                name:
                    name,


                joinedAt:
                    Date.now(),


                avoidOpponent:
                    avoidOpponent ||
                    null

            });


            return res.json({

                success:
                    true,


                matched:
                    false,


                waiting:
                    true

            });


        } catch (error) {

            console.error(
                "Chess queue join error:",
                error
            );


            res.status(500).json({

                success:
                    false,


                message:
                    "Couldn't join chess queue."

            });

        }

    }
);


/* =========================================
   LEAVE QUEUE
========================================= */

app.post(
    "/api/chess/queue/leave",
    (req, res) => {

        try {

            cleanChessData();


            const name =
                String(
                    req.body.name || ""
                )
                .trim()
                .toLowerCase();


            chessQueue =
                chessQueue.filter(
                    player =>
                        player.name
                            .toLowerCase() !==
                        name
                );


            res.json({

                success:
                    true,


                waiting:
                    chessQueue.length

            });


        } catch (error) {

            console.error(
                "Chess queue leave error:",
                error
            );


            res.status(500).json({

                success:
                    false,


                message:
                    "Couldn't leave chess queue."

            });

        }

    }
);


/* =========================================
   GET MATCH STATE
========================================= */

app.get(
    "/api/chess/match/:matchId",
    (req, res) => {

        try {

            cleanChessData();


            const match =
                chessMatches.get(
                    req.params.matchId
                );


            if (
                !match
            ) {

                return res.status(
                    404
                ).json({

                    success:
                        false,


                    message:
                        "Match not found."

                });

            }


            const playerName =
                String(
                    req.query.name || ""
                )
                .trim();


            const state =
                getChessMatchState(
                    match,
                    playerName
                );


            if (
                !state
            ) {

                return res.status(
                    403
                ).json({

                    success:
                        false,


                    message:
                        "You are not part of this match."

                });

            }


            res.json(
                state
            );


        } catch (error) {

            console.error(
                "Chess game state error:",
                error
            );


            res.status(500).json({

                success:
                    false,


                message:
                    "Couldn't load chess game."

            });

        }

    }
);


/* =========================================
   MAKE CHESS MOVE
========================================= */

app.post(
    "/api/chess/match/:matchId/move",
    (req, res) => {

        try {

            cleanChessData();


            const match =
                chessMatches.get(
                    req.params.matchId
                );


            if (
                !match
            ) {

                return res.status(
                    404
                ).json({

                    success:
                        false,


                    message:
                        "Match not found."

                });

            }


            const playerName =
                String(
                    req.body.name || ""
                )
                .trim();


            const from =
                String(
                    req.body.from || ""
                )
                .trim()
                .toLowerCase();


            const to =
                String(
                    req.body.to || ""
                )
                .trim()
                .toLowerCase();


            const promotion =
                String(
                    req.body.promotion ||
                    "q"
                )
                .trim()
                .toLowerCase();


            const player =
                match.players.find(
                    name =>
                        name
                            .toLowerCase() ===
                        playerName.toLowerCase()
                );


            if (
                !player
            ) {

                return res.status(
                    403
                ).json({

                    success:
                        false,


                    message:
                        "You are not part of this match."

                });

            }


            if (
    match.resignedBy ||
    match.timeOutBy
) {

                return res.status(
                    400
                ).json({

                    success:
                        false,


                    message:
    match.timeOutBy
        ? "This game has ended on time."
        : "This match has ended."

                });

            }


            if (
                match.game.isGameOver()
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,


                    message:
                        "This game is already over."

                });

            }


            const playerColor =
                match.colors[
                    player
                ];


            const currentTurn =
                match.game.turn() === "w"
                    ? "white"
                    : "black";


            if (
                playerColor !==
                currentTurn
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,


                    message:
                        "It is not your turn."

                });

            }


            const legalMoves =
                match.game.moves({

                    square:
                        from,


                    verbose:
                        true

                });


            const legalMove =
                legalMoves.find(
                    move =>
                        move.to ===
                        to
                );


            if (
                !legalMove
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,


                    message:
                        "Illegal chess move."

                });

            }


            const move =
                match.game.move({

                    from:
                        from,


                    to:
                        to,


                    promotion:

                        (
                            promotion === "r" ||
                            promotion === "b" ||
                            promotion === "n"
                        )

                            ? promotion

                            : "q"

                });


            match.lastMove = {

                from:
                    move.from,


                to:
                    move.to,


                promotion:
                    move.promotion ||
                    null,


                player:
                    player,


                createdAt:
                    Date.now()

            };
            /* =========================================
   UPDATE CHESS CLOCK
========================================= */

const elapsed =
    Date.now() -
    match.turnStartedAt;


if (
    match.game.turn() === "b"
) {

    /*
     * White just moved.
     */

    match.whiteTimeMs =
        Math.max(
            0,
            match.whiteTimeMs -
            elapsed
        );

} else {

    /*
     * Black just moved.
     */

    match.blackTimeMs =
        Math.max(
            0,
            match.blackTimeMs -
            elapsed
        );

}


/*
 * The opponent's clock starts now.
 */

match.turnStartedAt =
    Date.now();


updateChessTimeout(
    match
);

            recordChessResult(
                match
            );
    
            console.log(
                `♟ MOVE ${match.matchId}: ${player} ${move.from}-${move.to}`
            );


            res.json(
                getChessMatchState(
                    match,
                    player
                )
            );


        } catch (error) {

            console.error(
                "Chess move error:",
                error
            );


            res.status(500).json({

                success:
                    false,


                message:
                    "Couldn't make chess move."

            });

        }

    }
);


/* =========================================
   RESIGN
========================================= */

app.post(
    "/api/chess/match/:matchId/resign",
    (req, res) => {

        try {

            const match =
                chessMatches.get(
                    req.params.matchId
                );


            if (
                !match
            ) {

                return res.status(
                    404
                ).json({

                    success:
                        false,


                    message:
                        "Match not found."

                });

            }


            const name =
                String(
                    req.body.name || ""
                )
                .trim();


            const player =
                match.players.find(
                    item =>
                        item
                            .toLowerCase() ===
                        name.toLowerCase()
                );


            if (
                !player
            ) {

                return res.status(
                    403
                ).json({

                    success:
                        false,


                    message:
                        "You are not part of this match."

                });

            }


            if (
                match.resignedBy ||
                match.game.isGameOver()
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,


                    message:
                        "This game has already ended."

                });

            }


            match.resignedBy =
                player;
                recordChessResult(
    match
);


            console.log(
                `🏳 CHESS RESIGN: ${player} resigned from ${match.matchId}`
            );


            res.json({

                success:
                    true,


                resigned:
                    player

            });


        } catch (error) {

            console.error(
                "Chess resignation error:",
                error
            );


            res.status(500).json({

                success:
                    false,


                message:
                    "Couldn't resign."

            });

        }

    }
);
/* =========================================
   GET CHESS STATS FOR STUDENT
========================================= */

app.get(
    "/api/chess/stats",
    (req, res) => {

        try {

            const name =
                String(
                    req.query.name || ""
                )
                .trim();


            if (!name) {

                return res.status(
                    400
                ).json({

                    success:
                        false,

                    message:
                        "Name is required."

                });

            }


            const stats =
                loadChessStats();


            const key =
                normalizeChessStatsName(
                    name
                );


            const student =
                stats[key];


            if (!student) {

                return res.json({

                    success:
                        true,

                    name:
                        name,

                    games:
                        0,

                    wins:
                        0,

                    losses:
                        0,

                    draws:
                        0,

                    winRate:
                        0

                });

            }


            const games =
                Number(
                    student.games
                ) || 0;


            const wins =
                Number(
                    student.wins
                ) || 0;


            const losses =
                Number(
                    student.losses
                ) || 0;


            const draws =
                Number(
                    student.draws
                ) || 0;


            const winRate =
                games > 0
                    ? Number(
                        (
                            wins /
                            games *
                            100
                        ).toFixed(1)
                    )
                    : 0;


            res.json({

                success:
                    true,

                name:
                    student.name,

                games:
                    games,

                wins:
                    wins,

                losses:
                    losses,

                draws:
                    draws,

                winRate:
                    winRate

            });

        }

        catch (error) {

            console.error(
                "Chess stats error:",
                error
            );


            res.status(500).json({

                success:
                    false,

                message:
                    "Couldn't load chess statistics."

            });

        }

    }
);


/* =========================================
   REMATCH REQUEST
========================================= */

app.post(
    "/api/chess/match/:matchId/rematch/request",
    (req, res) => {

        try {

            cleanChessData();


            const match =
                chessMatches.get(
                    req.params.matchId
                );


            if (
                !match
            ) {

                return res.status(
                    404
                ).json({

                    success:
                        false,


                    message:
                        "Match not found."

                });

            }


            const name =
                String(
                    req.body.name || ""
                )
                .trim();


            const player =
                match.players.find(
                    item =>
                        item
                            .toLowerCase() ===
                        name.toLowerCase()
                );


            if (
                !player
            ) {

                return res.status(
                    403
                ).json({

                    success:
                        false,


                    message:
                        "You are not part of this match."

                });

            }


            /*
             * Rematch only after the old
             * game is finished.
             */

            const gameEnded =
                match.game.isGameOver() ||
                Boolean(
                    match.resignedBy
                );


            if (
                !gameEnded
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,


                    message:
                        "The game is still active."

                });

            }


            /*
             * Already accepted / created?
             */

            if (
                match.rematchMatchId
            ) {

                return res.json({

                    success:
                        true,


                    ready:
                        true,


                    rematchMatchId:
                        match.rematchMatchId

                });

            }


            /*
             * Don't let someone send a
             * second request.
             */

            if (
                match.rematchRequest
            ) {

                const requester =
                    match.rematchRequest
                        .requester
                        .toLowerCase();


                if (
                    requester ===
                    player.toLowerCase()
                ) {

                    return res.json({

                        success:
                            true,


                        waiting:
                            true,


                        requestedByMe:
                            true

                    });

                }


                return res.status(
                    400
                ).json({

                    success:
                        false,


                    message:
                        `${match.rematchRequest.requester} already requested a rematch.`

                });

            }


            match.rematchRequest = {

                requester:
                    player,


                createdAt:
                    Date.now()

            };


            match.rematchResponse =
                null;


            console.log(
                `↻ REMATCH REQUEST: ${player} -> ${match.players.find(item => item !== player)}`
            );


            res.json({

                success:
                    true,


                waiting:
                    true,


                requestedByMe:
                    true

            });


        } catch (error) {

            console.error(
                "Rematch request error:",
                error
            );


            res.status(500).json({

                success:
                    false,


                message:
                    "Couldn't request rematch."

            });

        }

    }
);


/* =========================================
   REMATCH STATUS
========================================= */

app.get(
    "/api/chess/match/:matchId/rematch/status",
    (req, res) => {

        try {

            const match =
                chessMatches.get(
                    req.params.matchId
                );


            if (
                !match
            ) {

                return res.status(
                    404
                ).json({

                    success:
                        false,


                    message:
                        "Match not found."

                });

            }


            const name =
                String(
                    req.query.name || ""
                )
                .trim();


            const player =
                match.players.find(
                    item =>
                        item
                            .toLowerCase() ===
                        name.toLowerCase()
                );


            if (
                !player
            ) {

                return res.status(
                    403
                ).json({

                    success:
                        false,


                    message:
                        "You are not part of this match."

                });

            }


            /*
             * Rematch already accepted.
             */

            if (
                match.rematchMatchId
            ) {

                return res.json({

                    success:
                        true,


                    ready:
                        true,


                    matchId:
                        match.rematchMatchId

                });

            }


            /*
             * Opponent refused.
             */

            if (
                match.rematchResponse ===
                "refused"
            ) {

                match.rematchResponse =
                    null;


                return res.json({

                    success:
                        true,


                    refused:
                        true

                });

            }


            const request =
                match.rematchRequest;


            if (
                !request
            ) {

                return res.json({

                    success:
                        true,


                    incomingRequest:
                        false,


                    requestedByMe:
                        false,


                    waiting:
                        false

                });

            }


            const requestedByMe =
                request.requester
                    .toLowerCase() ===
                player
                    .toLowerCase();


            return res.json({

                success:
                    true,


                incomingRequest:
                    !requestedByMe,


                requestedByMe:
                    requestedByMe,


                requester:
                    request.requester,


                waiting:
                    requestedByMe

            });


        } catch (error) {

            console.error(
                "Rematch status error:",
                error
            );


            res.status(500).json({

                success:
                    false,


                message:
                    "Couldn't check rematch status."

            });

        }

    }
);


/* =========================================
   ACCEPT / REFUSE REMATCH
========================================= */

app.post(
    "/api/chess/match/:matchId/rematch/respond",
    (req, res) => {

        try {

            cleanChessData();


            const match =
    chessMatches.get(
        req.params.matchId
    );


if (
    !match
) {

    return res.status(
        404
    ).json({

        success:
            false,

        message:
            "Match not found."

    });

}


updateChessTimeout(
    match
);

            const name =
                String(
                    req.body.name || ""
                )
                .trim();


            const action =
                String(
                    req.body.action || ""
                )
                .trim()
                .toLowerCase();


            const player =
                match.players.find(
                    item =>
                        item
                            .toLowerCase() ===
                        name.toLowerCase()
                );


            if (
                !player
            ) {

                return res.status(
                    403
                ).json({

                    success:
                        false,


                    message:
                        "You are not part of this match."

                });

            }


            const request =
                match.rematchRequest;


            if (
                !request
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,


                    message:
                        "There is no pending rematch request."

                });

            }


            if (
                request.requester
                    .toLowerCase() ===
                player
                    .toLowerCase()
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,


                    message:
                        "You cannot answer your own rematch request."

                });

            }


            /*
             * REFUSE
             */

            if (
                action ===
                "refuse"
            ) {

                match.rematchRequest =
                    null;


                match.rematchResponse =
                    "refused";


                console.log(
                    `✕ REMATCH REFUSED by ${player}`
                );


                return res.json({

                    success:
                        true,


                    refused:
                        true

                });

            }


            /*
             * ACCEPT
             */

            if (
                action !==
                "accept"
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,


                    message:
                        "Invalid rematch action."

                });

            }


            const requester =
                request.requester;


            /*
             * Swap colors in the rematch.
             */

            const newMatch =
                createChessMatch(
                    requester,
                    player,
                    true
                );


            match.rematchMatchId =
                newMatch.matchId;


            match.rematchRequest =
                null;


            match.rematchResponse =
                "accepted";


            console.log(
                `↻ CHESS REMATCH STARTED: ${requester} vs ${player}`
            );


            return res.json({

                success:
                    true,


                accepted:
                    true,


                rematchMatchId:
                    newMatch.matchId

            });


        } catch (error) {

            console.error(
                "Rematch response error:",
                error
            );


            res.status(500).json({

                success:
                    false,


                message:
                    "Couldn't process rematch response."

            });

        }

    }
);


/* =========================================
   PLAY AGAIN
   FIND A DIFFERENT OPPONENT
========================================= */

app.post(
    "/api/chess/play-again",
    (req, res) => {

        try {

            cleanChessData();


            const name =
                String(
                    req.body.name || ""
                )
                .trim()
                .slice(0, 80);


            const avoidOpponent =
                String(
                    req.body.avoidOpponent || ""
                )
                .trim()
                .toLowerCase();


            if (
                !name
            ) {

                return res.status(
                    400
                ).json({

                    success:
                        false,


                    message:
                        "Your name is required."

                });

            }


            const normalizedName =
                name.toLowerCase();


            /*
             * Remove the current player from
             * any existing queue entry.
             */

            chessQueue =
                chessQueue.filter(
                    player =>
                        player.name
                            .toLowerCase() !==
                        normalizedName
                );


            /*
             * IMPORTANT:
             *
             * Find someone waiting who is NOT
             * the previous opponent.
             */

const opponentIndex =
    chessQueue.findIndex(
        player => {

            const otherName =
                player.name
                    .toLowerCase();


            const otherAvoidOpponent =
                String(
                    player.avoidOpponent ||
                    ""
                )
                .trim()
                .toLowerCase();


            /*
             * Never match a player with themselves.
             */

            if (
                otherName ===
                normalizedName
            ) {

                return false;

            }


            /*
             * YOU don't want your previous opponent.
             */

            if (
                avoidOpponent &&
                otherName ===
                avoidOpponent
            ) {

                return false;

            }


            /*
             * The waiting player also doesn't
             * want YOU if you're their previous opponent.
             */

            if (
                otherAvoidOpponent &&
                otherAvoidOpponent ===
                normalizedName
            ) {

                return false;

            }


            return true;

        }
    );


            /*
             * Found somebody new.
             */

            if (
                opponentIndex !== -1
            ) {

                const opponent =
                    chessQueue.splice(
                        opponentIndex,
                        1
                    )[0];


                const match =
                    createChessMatch(
                        opponent.name,
                        name,
                        false
                    );


                console.log(
                    `⚡ PLAY AGAIN: ${opponent.name} vs ${name}`
                );


                return res.json(
                    getChessMatchState(
                        match,
                        name
                    )
                );

            }


            /*
             * Nobody new is available.
             * Stay in the queue.
             */

            chessQueue.push({

                name:
                    name,


                joinedAt:
                    Date.now(),


                avoidOpponent:
                    avoidOpponent ||
                    null

            });


            return res.json({

                success:
                    true,


                matched:
                    false,


                waiting:
                    true

            });


        } catch (error) {

            console.error(
                "Play again error:",
                error
            );


            res.status(500).json({

                success:
                    false,


                message:
                    "Couldn't start matchmaking."

            });

        }

    }
);

/* =========================================
   START SERVER
========================================= */

app.listen(
    PORT,
    () => {

        console.log("");

        console.log(
            "⚡ 4MS3 SERVER IS RUNNING"
        );

        console.log("");

        console.log(
            `🌐 http://localhost:${PORT}`
        );

        console.log("");

        console.log(
            "📥 Pending photos:",
            pendingFolder
        );

        console.log(
            "✅ Approved photos:",
            approvedFolder
        );

        console.log("");

    }
);