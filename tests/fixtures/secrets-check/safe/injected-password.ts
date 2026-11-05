export function databaseOptions(password: string) {
  return {
    host: "db.internal.example",
    username: "service-account",
    password,
  };
}
