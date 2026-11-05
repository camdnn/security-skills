type Request = { params: { userId: string } };
type Response = { json(value: unknown): void };

declare const accounts: { findById(id: string): Promise<unknown> };

export async function getAccount(request: Request, response: Response) {
  const account = await accounts.findById(request.params.userId);
  response.json(account);
}
