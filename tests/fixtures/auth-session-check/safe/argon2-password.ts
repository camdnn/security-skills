import argon2 from "argon2";

type AccountStore = { save(account: { email: string; passwordHash: string }): Promise<void> };

export async function register(store: AccountStore, email: string, password: string) {
  const passwordHash = await argon2.hash(password);
  await store.save({ email, passwordHash });
}
