import { randomBytes } from "node:crypto";
export function resetToken() { return randomBytes(32).toString("hex"); }
