type AccountStore = { save(account: { email: string; password: string }): Promise<void> };

export async function register(store: AccountStore, email: string, password: string) {
  await store.save({ email, password });
}
