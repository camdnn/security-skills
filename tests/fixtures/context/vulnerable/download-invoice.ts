type Request = { user: { id: string; role: string }; params: { orderId: string } };
type Response = { sendStatus(status: number): void; send(body: Uint8Array): void };

type Order = { id: string; customerId: string };
declare const orders: { findById(id: string): Promise<Order | null> };
declare const invoices: { renderPdf(orderId: string): Promise<Uint8Array> };

export async function downloadInvoice(request: Request, response: Response) {
  const order = await orders.findById(request.params.orderId);
  if (!order) return response.sendStatus(404);
  const allowed = order.customerId === request.user.id || request.user.role === "support";
  if (!allowed) return response.sendStatus(403);
  response.send(await invoices.renderPdf(order.id));
}
