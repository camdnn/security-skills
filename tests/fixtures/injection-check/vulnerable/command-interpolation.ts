declare function exec(command: string): Promise<string>;

export function showRevision(revision: string) {
  const command = `git show ${revision}`;
  return exec(command);
}
