import cors from "cors";

const allowedOrigins = new Set(["https://app.example.test"]);

export const corsPolicy = cors({
  origin(origin, callback) {
    callback(null, origin === undefined || allowedOrigins.has(origin));
  },
  credentials: true,
});
