const bcrypt = require('bcrypt');

const password = "ram@9573";
const saltRounds = 10;

bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
  if (err) {
    console.error("Error hashing password:", err);
  } else {
    console.log("Hashed Password:", hashedPassword);
  }
});
