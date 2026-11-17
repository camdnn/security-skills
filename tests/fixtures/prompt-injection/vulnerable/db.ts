export const db = {
  async query (sql: string, params: unknown[] = []): Promise<unknown[]> {
    return [{ sql, params }]
  }
}
