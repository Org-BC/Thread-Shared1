import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { createTestApp, invoiceEvent, signedWebhook, subscriptionEvent } from "./helpers.js";

let ctx: Awaited<ReturnType<typeof createTestApp>>;
beforeEach(async () => {
  ctx = await createTestApp();
  await ctx.service.getOrCreateCustomer("u1");
});

const post = (body: string, header?: string) => {
  const req = request(ctx.app).post("/api/billing/webhook").set("Content-Type", "application/json");
  if (header) req.set("stripe-signature", header);
  return req.send(body);
};

describe("POST /api/billing/webhook", () => {
  it("rejects a missing signature with 400 and changes nothing", async () => {
    await post(JSON.stringify(subscriptionEvent("evt_1", "customer.subscription.created"))).expect(400);
    expect((await ctx.db.query("SELECT * FROM subscriptions")).rows).toHaveLength(0);
  });

  it("rejects an invalid signature with 400 and changes nothing", async () => {
    const { body, header } = signedWebhook(subscriptionEvent("evt_1", "customer.subscription.created"), "whsec_wrong");
    await post(body, header).expect(400);
    expect((await ctx.db.query("SELECT * FROM subscriptions")).rows).toHaveLength(0);
    expect((await ctx.db.query("SELECT * FROM stripe_events")).rows).toHaveLength(0);
  });

  it("applies a valid subscription event", async () => {
    const { body, header } = signedWebhook(subscriptionEvent("evt_1", "customer.subscription.created"));
    await post(body, header).expect(200);
    expect((await ctx.service.getSubscription("u1"))?.status).toBe("active");
  });

  it("acknowledges a duplicate event with 200 without re-applying it", async () => {
    const created = signedWebhook(subscriptionEvent("evt_1", "customer.subscription.created"));
    await post(created.body, created.header).expect(200);
    await ctx.db.query("UPDATE subscriptions SET status = 'paused'");
    await post(created.body, created.header).expect(200);
    expect((await ctx.service.getSubscription("u1"))?.status).toBe("paused");
  });

  it("applies invoice.payment_failed", async () => {
    const a = signedWebhook(subscriptionEvent("evt_1", "customer.subscription.created"));
    await post(a.body, a.header).expect(200);
    const b = signedWebhook(invoiceEvent("evt_2", "invoice.payment_failed"));
    await post(b.body, b.header).expect(200);
    expect((await ctx.service.getSubscription("u1"))?.status).toBe("past_due");
  });

  it("returns 500 so Stripe retries when processing fails", async () => {
    const { body, header } = signedWebhook(subscriptionEvent("evt_1", "customer.subscription.created"));
    await ctx.db.query("DROP TABLE subscriptions");
    await post(body, header).expect(500);
    expect((await ctx.db.query("SELECT * FROM stripe_events")).rows).toHaveLength(0);
  });
});
