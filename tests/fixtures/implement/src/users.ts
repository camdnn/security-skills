import { type FakeDb, type Row } from './db.ts'

export function findUsersByName (db: FakeDb, name: string): Row[] {
  return db.query(`SELECT id, name, email FROM users WHERE name = '${name}'`)
}
