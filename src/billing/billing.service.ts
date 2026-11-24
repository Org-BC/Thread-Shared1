import type Stripe from "stripe";
import type { Db } from "../db/types.js";

export interface SubscriptionView {
  plan: string;
  status: string;
  currentPeriodEnd: string | null;
  cancelAtPeriodEnd: boolean;
}

export class NoStripeCustomerError extends Error {
  constructor() {
    super("No Stripe customer exists for this account");
  }
}

interface SubscriptionRow {
  plan: string;
  status: string;
  current_period_end: Date | string | null;
  cancel_at_period_end: boolean;
}

const idOf = (ref: string | { id: string } | null | undefined): string | null =>
  typeof ref === "string" ? ref : (ref?.id ?? null);

export class BillingService {
  constructor(
    private readonly db: Db,
    private readonly stripe: Stripe,
    private readonly returnUrl: string,
  ) {}

  private async findCustomerId(userId: string): Promise<string | null> {
    const { rows } = await this.db.query<{ stripe_customer_id: string }>(
      "SELECT stripe_customer_id FROM billing_customers WHERE user_id = $1",
      [userId],
    );
    return rows[0]?.stripe_customer_id ?? null;
  }

  async getOrCreateCustomer(userId: string, email?: string): Promise<string> {
    const existing = await this.findCustomerId(userId);
    if (existing) return existing;

    // The idempotency key makes concurrent first visits resolve to the same Stripe customer.
    const customer = await this.stripe.customers.create(
      { email, metadata: { user_id: userId } },
      { idempotencyKey: `portal-customer-${userId}` },
    );
    await this.db.query(
      "INSERT INTO billing_customers (user_id, stripe_customer_id) VALUES ($1, $2) ON CONFLICT (user_id) DO NOTHING",
      [userId, customer.id],
    );
    return (await this.findCustomerId(userId)) ?? customer.id;
  }

  async getSubscription(userId: string): Promise<SubscriptionView | null> {
    const { rows } = await this.db.query<SubscriptionRow>(
      `SELECT plan, status, current_period_end, cancel_at_period_end
         FROM subscriptions WHERE user_id = $1
         ORDER BY updated_at DESC LIMIT 1`,
      [userId],
    );
    const row = rows[0];
    if (!row) return null;
    return {
      plan: row.plan,
      status: row.status,
      currentPeriodEnd: row.current_period_end ? new Date(row.current_period_end).toISOString() : null,
      cancelAtPeriodEnd: row.cancel_at_period_end,
    };
  }

  async createPortalSession(userId: string): Promise<string> {
    const customerId = await this.findCustomerId(userId);
    if (!customerId) throw new NoStripeCustomerError();
    const session = await this.stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: this.returnUrl,
    });
    return session.url;
  }

  /** Returns false when the event was already processed. */
  async handleEvent(event: Stripe.Event): Promise<boolean> {
    const seen = await this.db.query("SELECT 1 FROM stripe_events WHERE event_id = $1", [event.id]);
    if (seen.rows.length > 0) return false;

    switch (event.type) {
      case "customer.subscription.created":
      case "customer.subscription.updated":
      case "customer.subscription.deleted":
        await this.applySubscription(event.data.object, event.created);
        break;
      case "invoice.paid":
        await this.applyInvoiceStatus(event.data.object, "active", event.created);
        break;
      case "invoice.payment_failed":
        await this.applyInvoiceStatus(event.data.object, "past_due", event.created);
        break;
    }

    await this.db.query(
      "INSERT INTO stripe_events (event_id) VALUES ($1) ON CONFLICT (event_id) DO NOTHING",
      [event.id],
    );
    return true;
  }

  private async applySubscription(sub: Stripe.Subscription, eventCreated: number): Promise<void> {
    const customerId = idOf(sub.customer);
    const owner = customerId
      ? await this.db.query<{ user_id: string }>(
          "SELECT user_id FROM billing_customers WHERE stripe_customer_id = $1",
          [customerId],
        )
      : { rows: [] };
    const userId = owner.rows[0]?.user_id;
    if (!userId) {
      console.warn(`Ignoring subscription ${sub.id}: unknown Stripe customer`);
      return;
    }

    const item = sub.items.data[0];
    const plan = item?.price.lookup_key ?? item?.price.nickname ?? item?.price.id ?? "unknown";
    const periodEnd = item?.current_period_end ? new Date(item.current_period_end * 1000) : null;

    // The WHERE clause drops events older than the one already applied (out-of-order delivery).
    await this.db.query(
      `INSERT INTO subscriptions
         (stripe_subscription_id, user_id, plan, status, current_period_end, cancel_at_period_end, last_event_created, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, now())
       ON CONFLICT (stripe_subscription_id) DO UPDATE SET
         plan = EXCLUDED.plan,
         status = EXCLUDED.status,
         current_period_end = EXCLUDED.current_period_end,
         cancel_at_period_end = EXCLUDED.cancel_at_period_end,
         last_event_created = EXCLUDED.last_event_created,
         updated_at = now()
       WHERE subscriptions.last_event_created <= EXCLUDED.last_event_created`,
      [sub.id, userId, plan, sub.status, periodEnd, sub.cancel_at_period_end, eventCreated],
    );
  }

  private async applyInvoiceStatus(invoice: Stripe.Invoice, status: string, eventCreated: number): Promise<void> {
    const subscriptionId = idOf(invoice.parent?.subscription_details?.subscription);
    if (!subscriptionId) return;
    await this.db.query(
      `UPDATE subscriptions SET status = $1, last_event_created = $2, updated_at = now()
         WHERE stripe_subscription_id = $3 AND last_event_created <= $2`,
      [status, eventCreated, subscriptionId],
    );
  }
}
