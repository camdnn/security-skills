declare const database: { query(sql: string, values: string[]): Promise<unknown> };

export function findUserByEmail(email: string) {
  return database.query("SELECT id FROM users WHERE email = $1", [email]);
}
