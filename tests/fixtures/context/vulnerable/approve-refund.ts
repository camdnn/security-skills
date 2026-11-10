type Request = { user: { id: string; role: string }; params: { refundId: string } };
type Response = { sendStatus(status: number): void; json(value: unknown): void };

type Refund = { id: string; requestedBy: string; status: "requested" | "approved" };
declare const refunds: {
  findById(id: string): Promise<Refund | null>;
  approve(id: string, approverId: string): Promise<Refund>;
};

export async function approveRefund(request: Request, response: Response) {
  if (request.user.role !== "manager") return response.sendStatus(403);
  const refund = await refunds.findById(request.params.refundId);
  if (!refund || refund.status !== "requested") return response.sendStatus(404);
  response.json(await refunds.approve(refund.id, request.user.id));
}
