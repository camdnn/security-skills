type Request = { user: { id: string }; params: { userId: string } };
type Response = { sendStatus(status: number): void; json(value: unknown): void };

declare const accounts: { findById(id: string): Promise<{ ownerId: string } | null> };

export async function getAccount(request: Request, response: Response) {
  const account = await accounts.findById(request.params.userId);
  if (!account || account.ownerId !== request.user.id) return response.sendStatus(403);
  response.json(account);
}
