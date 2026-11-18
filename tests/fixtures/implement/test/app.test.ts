// The existing suite: normal behaviour that every fix must keep working.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { FakeDb } from '../src/db.ts'
import { findUsersByName } from '../src/users.ts'
import { readReport } from '../src/files.ts'
import { getOrder, type Order } from '../src/orders.ts'

const here = path.dirname(fileURLToPath(import.meta.url))
const rows = [{ id: 1, name: 'ada', email: 'ada@example.test' }, { id: 2, name: 'bob', email: 'bob@example.test' }]

test('finds a user by name', () => {
  assert.deepEqual(findUsersByName(new FakeDb(rows), 'ada').map(r => r.id), [1])
})

test('reads a report by name', () => {
  assert.equal(readReport(path.join(here, '../reports'), 'q3.txt'), 'Q3 revenue: 42\n')
})

test('a customer can read their own order', () => {
  const orders = new Map<string, Order>([['o1', { id: 'o1', ownerId: 'u1', total: 10 }]])
  assert.equal(getOrder(orders, { id: 'u1', role: 'customer' }, 'o1')?.total, 10)
})

test('support can read any order', () => {
  const orders = new Map<string, Order>([['o1', { id: 'o1', ownerId: 'u1', total: 10 }]])
  assert.equal(getOrder(orders, { id: 's1', role: 'support' }, 'o1')?.total, 10)
})
