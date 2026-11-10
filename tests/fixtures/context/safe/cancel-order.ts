type Request = { user: { id: string; role: string }; params: { orderId: string } };
type Response = { sendStatus(status: number): void; json(value: unknown): void };

type Order = { id: string; customerId: string; status: "placed" | "shipped" };
declare const orders: { findById(id: string): Promise<Order | null>; cancel(id: string): Promise<Order> };

export async function cancelOrder(request: Request, response: Response) {
  const order = await orders.findById(request.params.orderId);
  if (!order) return response.sendStatus(404);
  const allowed = order.customerId === request.user.id || request.user.role === "support";
  if (!allowed) return response.sendStatus(403);
  if (order.status !== "placed") return response.sendStatus(409);
  response.json(await orders.cancel(order.id));
}
