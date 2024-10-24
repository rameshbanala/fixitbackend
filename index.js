const express = require("express");
const cors = require("cors");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const app = express();
const path = require("path");
const fs = require("fs");
const { workerData } = require("worker_threads");
const { request } = require("http");

app.use(express.json());
app.use(cors());
app.use(
  "/worker_proofs",
  express.static(path.join(__dirname, "../worker_proofs"))
);

const MY_SECRET_TOKEN = "THIS_IS_FIXIT_LOGIN";

const db = mysql.createConnection({
  host: "localhost",
  user: "root", // Replace with your MySQL username
  password: "", // Replace with your MySQL password
  database: "projectdb", // Database name
});

db.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err);
  } else {
    console.log("Connected to MySQL database");
  }
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, "../worker_proofs"));
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

// File type and size validation
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // Limit file size to 5MB
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif|pdf/; // Allowed file types
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = filetypes.test(file.mimetype);

    if (extname && mimetype) {
      return cb(null, true);
    }
    cb("Error: File type not supported");
  },
});

// Upload endpoint
app.post("/worker-application", upload.single("file"), (req, res) => {
  const file = req.file;

  if (!file) {
    return res.status(400).json({ message: "No file uploaded." });
  }

  // Extracting data from the request body
  const {
    name,
    dob,
    email,
    password,
    phone_no,
    address,
    city,
    pincode,
    types_of_professions,
    is_verified,
  } = req.body;

  // Check if all required fields are present
  if (
    !name ||
    !dob ||
    !email ||
    !password ||
    !phone_no ||
    !address ||
    !city ||
    !pincode ||
    !types_of_professions
  ) {
    return res.status(400).json({ message: "All fields are required." });
  }

  // Insert file and application details into the database
  const query = `INSERT INTO worker_applications (id, name, dob, email, password, phone_no, address, city, pincode, types_of_professions, file_name, file_path,is_verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)`;
  const values = [
    uuidv4(), // Generating a unique ID
    name,
    dob,
    email,
    bcrypt.hashSync(password, 10), // Hashing the password
    phone_no,
    address,
    city,
    pincode,
    types_of_professions,
    file.filename,
    `worker_proofs/${file.filename}`,
    is_verified,
  ];

  db.query(query, values, (err, result) => {
    if (err) {
      console.error("Database error:", err); // Log the specific database error
      return res
        .status(500)
        .json({ message: "Error saving application info to the database." });
    }

    res.status(200).json({
      message: "Application submitted successfully",
      applicationId: result.insertId,
    });
  });
});

// File retrieval endpoint
app.get("/files/:id", (req, res) => {
  const fileId = req.params.id;

  const query = `SELECT * FROM worker_files WHERE id = ?`;
  db.query(query, [fileId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ message: "File not found" });
    }

    const file = results[0];
    res.sendFile(path.resolve(__dirname, file.file_path));
  });
});

app.post("/user-signup", async (req, res) => {
  const { name, dob, email, phone_no, password, address, city, pincode } =
    req.body;

  // Validate the required fields
  if (
    !name ||
    !dob ||
    !email ||
    !phone_no ||
    !password ||
    !address ||
    !city ||
    !pincode
  ) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    // Generate UUID for the user
    const id = uuidv4();

    // Hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // SQL query to insert user data into the users table
    const query = `INSERT INTO users (id, name, dob, email, phone_no, password, address, city, pincode) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    // Execute the query
    db.query(
      query,
      [id, name, dob, email, phone_no, hashedPassword, address, city, pincode],
      (err, result) => {
        if (err) {
          console.error("Error inserting user data:", err);
          return res.status(500).json({ message: "Error inserting user data" });
        }

        // Respond with success
        res
          .status(201)
          .json({ message: "User registered successfully", userId: id });
      }
    );
  } catch (error) {
    console.error("Error during signup:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/login", (req, res) => {
  const { email, password, user_type } = req.body;
  let selectUserQuery;
  let is_admin = false;
  let tableName;

  if (email.includes("@admin.fixit")) {
    selectUserQuery = "SELECT * FROM administrator WHERE email = ?";
    is_admin = true;
  } else {
    tableName = user_type === "USER" ? "users" : "worker_applications";
    selectUserQuery = `SELECT * FROM ${tableName} WHERE email = ?`;
  }

  db.query(selectUserQuery, [email], async (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Internal Server Error" });
    }

    if (result.length === 0) {
      if (user_type === "WORKER") {
        //console.log(user_type)
        const queryRejectedWorker = `SELECT * FROM worker_application_rejected WHERE email = ?`;

        return db.query(
          queryRejectedWorker,
          [email],
          (error, rejectedResult) => {
            if (error) {
              return res.status(500).json({ message: "Internal Server Error" });
            }

            if (rejectedResult.length === 0) {
              // Worker not found in both worker_applications and worker_application_rejected
              return res.status(400).json({
                message: "Worker not found. Please sign up for a new account.",
              });
            }

            // Worker found in rejected applications
            return res.status(403).json({
              message:
                "Your application was rejected. Please provide valid credentials.",
            });
          }
        );
      } else {
        return res
          .status(400)
          .json({ message: "User not found Please singup for a new account" });
      }
    }

    const user = result[0];

    let isPasswordMatched;
    if (email.includes("@admin.fixit") && password === user.password) {
      isPasswordMatched = true;
    } else {
      isPasswordMatched = await bcrypt.compare(password, user.password);
    }

    if (!isPasswordMatched) {
      return res.status(400).json({ message: "Invalid Password" });
    } else {
      if (tableName === "worker_applications" && user.is_verified === "false") {
        return res.status(202).json({
          message:
            "Still your application is under verification...thank you for your patience",
        });
      }
      const payload = {
        user_id: user.id,
        user_type: is_admin ? "ADMIN" : user_type,
      };
      const jwtToken = jwt.sign(payload, MY_SECRET_TOKEN);
      return res.status(200).json({
        jwt_token: jwtToken,
        user_type: is_admin ? "ADMIN" : user_type,
      });
    }
  });
});

//after login and signup admin and user and workers apis

const authenticateToken = (request, response, next) => {
  let jwt_token;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwt_token = authHeader.split(" ")[1];
  }
  if (jwt_token === undefined) {
    response.status(401).json({ message: "Invalid jwt token" });
  } else {
    jwt.verify(jwt_token, MY_SECRET_TOKEN, async (error, payload) => {
      if (error) {
        response.status(401);
        response.send("Invalid JWT Token");
      } else {
        request.user_id = payload.user_id;
        request.user_type = payload.user_type;
        next();
      }
    });
  }
};

app.get("/admin-page-details", authenticateToken, (request, response) => {
  const first_query = "SELECT * FROM users;";
  const second_query = "SELECT * FROM worker_applications;";
  const third_query = "SELECT * FROM feedback;";

  db.query(first_query, (err, usersData) => {
    if (err) {
      console.error("Database error:", err);
      return response.status(500).json({ message: "Internal Server Error" });
    }

    db.query(second_query, (err, workerData) => {
      if (err) {
        console.error("Database error:", err);
        return response.status(500).json({ message: "Internal Server Error" });
      }
      db.query(third_query, (err, feedback) => {
        if (err) {
          console.error("Database error:", err);
          return response
            .status(500)
            .json({ message: "Internal Server Error" });
        }
        response.status(200).json({ usersData, workerData, feedback });
      });
    });
  });
});

app.post("/verify-the-worker", authenticateToken, (request, response) => {
  const { id } = request.body;

  // Parameterized query to prevent SQL injection
  const query = `UPDATE worker_applications SET is_verified = ? WHERE id = ?`;

  db.query(query, ["true", id], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return response
        .status(500)
        .json({ message: "Internal Server Error", error: err.message });
    }

    // Check if any row was affected
    if (result.affectedRows === 0) {
      return response.status(404).json({ message: "Worker not found" });
    }

    response.status(200).json({ message: "Document verified successfully" });
  });
});

app.post("/reject-the-worker", authenticateToken, (request, response) => {
  const { id } = request.body;
  const query = `SELECT email, password, file_path FROM worker_applications WHERE id = ?`;

  db.query(query, [id], (error, result) => {
    if (error) {
      console.error("Database error:", error);
      return response
        .status(500)
        .json({ message: "Internal Server Error", error: error.message });
    }

    if (result.length === 0) {
      return response.status(404).json({ message: "Worker not found" });
    }

    // Destructure email, password, and file_path from the result
    const { email, password, file_path } = result[0];

    const complete_path = path.join("D:/projects/", file_path);

    // Delete the file
    fs.unlink(complete_path, (err) => {
      if (err) {
        console.error("File deletion failed:", err);
        return response.status(500).json({ message: "File deletion failed" });
      }

      // Insert into worker_application_rejected
      const query_2 = `INSERT INTO worker_application_rejected (email) VALUES (?)`;
      db.query(query_2, [email], (error, result) => {
        if (error) {
          console.error("Database error:", error);
          return response
            .status(500)
            .json({ message: "Internal Server Error", error: error.message });
        }

        if (result.affectedRows === 0) {
          return response
            .status(404)
            .json({ message: "Worker rejection failed" });
        }

        // Delete the original entry from worker_applications
        const query_3 = `DELETE FROM worker_applications WHERE id = ?`;
        db.query(query_3, [id], (error, result) => {
          if (error) {
            console.error("Database error:", error);
            return response
              .status(500)
              .json({ message: "Internal Server Error", error: error.message });
          }

          response.status(200).json({ message: "Rejected Successfully" });
        });
      });
    });
  });
});

app.get("/get-user-data", authenticateToken, (request, response) => {
  const { user_id } = request;
  const query = `SELECT * FROM users WHERE id = ?`;
  db.query(query, [user_id], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return response
        .status(500)
        .json({ message: "Internal Server Error", error: err.message });
    }
    if (result[0].length !== 0) {
      return response.status(200).send({ user_data: result[0] });
    } else {
      return response.status(400).json({ message: "User Data Not Found" });
    }
  });
});

app.get("/get-worker-data", authenticateToken, (request, response) => {
  const { user_id } = request;
  const query = `SELECT * FROM worker_applications WHERE id = ?`;
  db.query(query, [user_id], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return response
        .status(500)
        .json({ message: "Internal Server Error", error: err.message });
    }
    if (result[0].length !== 0) {
      return response.status(200).send({ worker_data: result[0] });
    } else {
      return response.status(400).json({ message: "User Data Not Found" });
    }
  });
});

app.post("/feedback", authenticateToken, (request, response) => {
  const { rating, comments } = request.body;
  const { user_id, user_type } = request;
  const query = `INSERT INTO feedback(id,user_type,rating,comments) VALUES (?,?,?,?)`;
  db.query(
    query,
    [user_id, user_type, parseInt(rating), comments],
    (error, result) => {
      if (error) {
        return response
          .status(500)
          .json({ message: "Internal Server Error", error: error.message });
      }
      response.status(200).send("Successfully submitted the feedback");
    }
  );
});

app.get("/user-worker-options", authenticateToken, (request, response) => {
  const { req_type } = request.query;
  const { user_type } = request;
  if (user_type === "WORKER") {
    return response.status(401).json({ message: "Unauthorized access" });
  }
  const query = `SELECT id, name, email, phone_no, city 
                 FROM worker_applications 
                 WHERE LOWER(types_of_professions) LIKE '%${req_type.toLowerCase()}%' 
                 AND is_verified = 'true';`;

  db.query(query, (err, result) => {
    if (err) {
      return response
        .status(500)
        .json({ message: "Internal Server Error", error: err.message });
    }

    if (result.length !== 0) {
      return response.status(200).json(result);
    } else {
      return response
        .status(404)
        .json({ message: "No matching workers found" });
    }
  });
});

app.get(
  "/worker-profile-details/:id",
  authenticateToken,
  (request, response) => {
    const { id } = request.params;

    const query = `SELECT * FROM worker_applications where id='${id}' AND is_verified='true';`;
    db.query(query, (error, result) => {
      if (error) {
        return response
          .status(500)
          .json({ message: "Internal Server Error", error: err.message });
      }
      if (result.length !== 0) {
        return response.status(200).json(result);
      } else {
        return response
          .status(404)
          .json({ message: "No matching workers found" });
      }
    });
  }
);

app.post("/booking-worker", authenticateToken, (request, response) => {
  const { user_id } = request;
  const { worker_id, work_type } = request.body;

  if (!worker_id || !work_type) {
    // 400 Bad Request - Missing required parameters
    return response
      .status(400)
      .json({ message: "Worker ID and work type are required." });
  }

  const booked_at = new Date();
  const status = "IN PROGRESS";
  const status_changed_by = "USER BOOKED";
  const id = uuidv4();

  const query = `
    INSERT INTO booking (id, user_id, worker_id, b_status, work_type, booked_at, status_changed_by) 
    VALUES (?, ?, ?, ?, ?, ?, ?);
  `;
  const queryParams = [
    id,
    user_id,
    worker_id,
    status,
    work_type,
    booked_at,
    status_changed_by,
  ];

  db.query(query, queryParams, (error, result) => {
    if (error) {
      // 500 Internal Server Error - Database query error
      return response
        .status(500)
        .json({ message: "Internal server error", error: error.message });
    }

    if (result.affectedRows === 0) {
      // 400 Bad Request - Failed to insert booking
      return response
        .status(400)
        .json({ message: "Failed to insert booking." });
    }

    // 201 Created - Booking successful
    return response
      .status(201)
      .json({ message: "Successfully Booked", booking_id: id });
  });
});

app.get("/", (request, response) => {
  response.send("<h1>Hello this is fixit backend</h1>");
});

app.listen(8000, () => {
  console.log("Listening at http://localhost:8000");
});