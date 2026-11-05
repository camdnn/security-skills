declare function execFile(file: string, args: string[]): Promise<string>;

export function showRevision(revision: string) {
  return execFile("git", ["show", revision]);
}
