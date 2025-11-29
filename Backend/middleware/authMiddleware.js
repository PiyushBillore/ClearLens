const joi = require("joi");
const jwt = require("jsonwebtoken");
const { UserModel } = require("../models/users");

// Validate signup body
const signupValidation = (req, res, next) => {
  const Schema = joi.object({
    name: joi.string().min(3).max(100).required(),
    email: joi.string().email().required(),
    password: joi.string().min(8).max(100).required()
  });

  const { error } = Schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: "Bad Request", error });
  }
  next();
};

// Validate login body
const loginValidation = (req, res, next) => {
  const Schema = joi.object({
    email: joi.string().email().required(),
    password: joi.string().min(8).max(100).required()
  });

  const { error } = Schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: "Bad Request", error });
  }
  next();
};

// JWT auth middleware (for protected routes like leaderboard update)
const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization; // "Bearer <token>"

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "No token provided", success: false });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // get fresh user data
    const user = await UserModel.findById(decoded._id).select("_id name email");
    if (!user) {
      return res.status(401).json({ message: "User not found", success: false });
    }

    req.user = user; // now we can use req.user._id, req.user.name, req.user.email
    next();
  } catch (err) {
    console.error("Auth error:", err.message);
    return res.status(401).json({ message: "Invalid or expired token", success: false });
  }
};

module.exports = {
  signupValidation,
  loginValidation,
  authMiddleware
};
