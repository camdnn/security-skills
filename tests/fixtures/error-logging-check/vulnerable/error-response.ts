export function handleError(error: Error, response: { status(n: number): { send(body: string): void } }) { response.status(500).send(error.stack ?? error.message); }
