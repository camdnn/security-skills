// A tiny in-memory stand-in for a SQL client, so the fixture runs with no dependencies.
export interface Row { id: number; name: string; email: string }

export class FakeDb {
  readonly queries: Array<{ sql: string; params: unknown[] }> = []

  private readonly rows: Row[]

  constructor (rows: Row[]) {
    this.rows = rows
  }

  query (sql: string, params: unknown[] = []): Row[] {
    this.queries.push({ sql, params })
    const literal = /WHERE name = '(.*)'$/.exec(sql)
    if (literal) {
      const value = literal[1]
      if (value.includes("' OR '1'='1")) return this.rows
      return this.rows.filter(row => row.name === value)
    }
    if (/WHERE name = \?$/.test(sql)) return this.rows.filter(row => row.name === params[0])
    throw new Error(`unsupported query: ${sql}`)
  }
}
