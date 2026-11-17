export function handleError(error: Error, response: { status(n: number): { send(body: string): void } }) { console.error(error); response.status(500).send("Internal server error"); }
