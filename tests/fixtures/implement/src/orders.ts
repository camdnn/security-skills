export interface Order { id: string; ownerId: string; total: number }
export interface User { id: string; role: 'customer' | 'support' }

export function getOrder (orders: Map<string, Order>, user: User, orderId: string): Order | undefined {
  return orders.get(orderId)
}
