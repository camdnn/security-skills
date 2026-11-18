import { readFileSync } from 'node:fs'
import path from 'node:path'

export function readReport (reportsDir: string, name: string): string {
  const file = path.join(reportsDir, name)
  return readFileSync(file, 'utf8')
}
