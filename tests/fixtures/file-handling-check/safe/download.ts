import path from "node:path";
import { readFile } from "node:fs/promises";
export function download(name: string) { const root = "/srv/files"; const file = path.resolve(root, name); if (!file.startsWith(`${root}/`)) throw new Error("invalid"); return readFile(file); }
