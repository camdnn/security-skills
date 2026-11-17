import cors from "cors";

export const corsPolicy = cors({
  origin(origin, callback) {
    callback(null, origin);
  },
  credentials: true,
});
