import { beforeEach, describe, expect, it } from "vitest";
import type Stripe from "stripe";
import { BillingService, NoStripeCustomerError } from "../src/billing/billing.service.js";
import { createTestDb, fakeStripe, RETURN_URL, subscriptionEvent, invoiceEvent } from "./helpers.js";
import type { Db } from "../src/db/types.js";

let db: Db;
let stripe: ReturnType<typeof fakeStripe>;
let service: BillingService;

beforeEach(async () => {
  db = await createTestDb();
  stripe = fakeStripe();
  service = new BillingService(db, stripe as unknown as Stripe, RETURN_URL);
});

const event = (e: object) => e as unknown as Stripe.Event;

describe("getOrCreateCustomer", () => {
  it("creates a Stripe customer and stores it", async () => {
    expect(await service.getOrCreateCustomer("u1", "a@b.c")).toBe("cus_new");
    const { rows } = await db.query("SELECT * FROM billing_customers WHERE user_id = 'u1'");
    expect(rows).toHaveLength(1);
  });

  it("reuses the existing customer without calling Stripe again", async () => {
    await service.getOrCreateCustomer("u1");
    await service.getOrCreateCustomer("u1");
    expect(stripe.customers.create).toHaveBeenCalledTimes(1);
  });
});

describe("getSubscription", () => {
  it("returns null when the user has no subscription", async () => {
    expect(await service.getSubscription("u1")).toBeNull();
  });

  it("maps the stored subscription", async () => {
    await service.getOrCreateCustomer("u1");
    await service.handleEvent(event(subscriptionEvent("evt_1", "customer.subscription.created", { cancel: true })));
    expect(await service.getSubscription("u1")).toEqual({
      plan: "pro",
      status: "active",
      currentPeriodEnd: new Date(1_800_000_000 * 1000).toISOString(),
      cancelAtPeriodEnd: true,
    });
  });
});

describe("createPortalSession", () => {
  it("throws NoStripeCustomerError without a customer", async () => {
    await expect(service.createPortalSession("u1")).rejects.toBeInstanceOf(NoStripeCustomerError);
  });

  it("creates a session with the return URL", async () => {
    await service.getOrCreateCustomer("u1");
    expect(await service.createPortalSession("u1")).toBe("https://billing.stripe.com/session/test");
    expect(stripe.billingPortal.sessions.create).toHaveBeenCalledWith({ customer: "cus_new", return_url: RETURN_URL });
  });
});

describe("handleEvent", () => {
  beforeEach(async () => {
    await service.getOrCreateCustomer("u1");
  });

  it("applies updates and deletions", async () => {
    await service.handleEvent(event(subscriptionEvent("evt_1", "customer.subscription.created")));
    await service.handleEvent(
      event(subscriptionEvent("evt_2", "customer.subscription.deleted", { status: "canceled", created: 1_700_000_050 })),
    );
    expect((await service.getSubscription("u1"))?.status).toBe("canceled");
  });

  it("sets status from invoice events", async () => {
    await service.handleEvent(event(subscriptionEvent("evt_1", "customer.subscription.created")));
    await service.handleEvent(event(invoiceEvent("evt_2", "invoice.payment_failed")));
    expect((await service.getSubscription("u1"))?.status).toBe("past_due");
    await service.handleEvent(event(invoiceEvent("evt_3", "invoice.paid", "sub_1", 1_700_000_200)));
    expect((await service.getSubscription("u1"))?.status).toBe("active");
  });

  it("does not apply a duplicate event twice", async () => {
    const e = event(subscriptionEvent("evt_1", "customer.subscription.created"));
    expect(await service.handleEvent(e)).toBe(true);
    expect(await service.handleEvent(e)).toBe(false);
  });

  it("ignores an older event that arrives after a newer one", async () => {
    await service.handleEvent(
      event(subscriptionEvent("evt_new", "customer.subscription.updated", { status: "canceled", created: 1_700_000_500 })),
    );
    await service.handleEvent(
      event(subscriptionEvent("evt_old", "customer.subscription.updated", { status: "active", created: 1_700_000_100 })),
    );
    expect((await service.getSubscription("u1"))?.status).toBe("canceled");
  });

  it("ignores subscriptions of unknown customers", async () => {
    await service.handleEvent(event(subscriptionEvent("evt_1", "customer.subscription.created", { customer: "cus_other" })));
    const { rows } = await db.query("SELECT * FROM subscriptions");
    expect(rows).toHaveLength(0);
  });
});
