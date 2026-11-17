import path from "node:path";
import { readFile } from "node:fs/promises";
export function download(name: string) { return readFile(path.join("/srv/files", name)); }
