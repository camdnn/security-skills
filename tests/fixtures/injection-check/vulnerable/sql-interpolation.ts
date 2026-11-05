declare const database: { query(sql: string): Promise<unknown> };

export function findUserByEmail(email: string) {
  const query = `SELECT id FROM users WHERE email = '${email}'`;
  return database.query(query);
}
