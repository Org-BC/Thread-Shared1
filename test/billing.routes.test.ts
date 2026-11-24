import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { createTestApp, subscriptionEvent, tokenFor, signedWebhook } from "./helpers.js";

let ctx: Awaited<ReturnType<typeof createTestApp>>;
beforeEach(async () => {
  ctx = await createTestApp();
});

describe("GET /api/billing/subscription", () => {
  it("requires authentication", async () => {
    await request(ctx.app).get("/api/billing/subscription").expect(401);
    await request(ctx.app).get("/api/billing/subscription").set("Authorization", "Bearer nope").expect(401);
  });

  it("returns an empty state with 200 when there is no subscription", async () => {
    const res = await request(ctx.app)
      .get("/api/billing/subscription")
      .set("Authorization", `Bearer ${tokenFor("u1")}`)
      .expect(200);
    expect(res.body).toEqual({ subscription: null });
  });

  it("returns only the caller's subscription", async () => {
    await ctx.service.getOrCreateCustomer("u1");
    const { body, header } = signedWebhook(subscriptionEvent("evt_1", "customer.subscription.created"));
    await request(ctx.app)
      .post("/api/billing/webhook")
      .set("stripe-signature", header)
      .set("Content-Type", "application/json")
      .send(body)
      .expect(200);

    const mine = await request(ctx.app)
      .get("/api/billing/subscription")
      .set("Authorization", `Bearer ${tokenFor("u1")}`)
      .expect(200);
    expect(mine.body.subscription).toMatchObject({ plan: "pro", status: "active", cancelAtPeriodEnd: false });

    const other = await request(ctx.app)
      .get("/api/billing/subscription")
      .set("Authorization", `Bearer ${tokenFor("u2")}`)
      .expect(200);
    expect(other.body).toEqual({ subscription: null });
  });
});

describe("POST /api/billing/portal-session", () => {
  it("requires authentication", async () => {
    await request(ctx.app).post("/api/billing/portal-session").expect(401);
  });

  it("returns 409 when the user has no Stripe customer", async () => {
    const res = await request(ctx.app)
      .post("/api/billing/portal-session")
      .set("Authorization", `Bearer ${tokenFor("u1")}`)
      .expect(409);
    expect(res.body.error).toMatch(/no stripe customer/i);
  });

  it("returns the portal URL", async () => {
    await ctx.service.getOrCreateCustomer("u1");
    const res = await request(ctx.app)
      .post("/api/billing/portal-session")
      .set("Authorization", `Bearer ${tokenFor("u1")}`)
      .expect(200);
    expect(res.body.url).toBe("https://billing.stripe.com/session/test");
  });

  it("returns 502 when Stripe fails", async () => {
    await ctx.service.getOrCreateCustomer("u1");
    ctx.stripe.billingPortal.sessions.create.mockRejectedValueOnce(new Error("stripe down sk_test_secret"));
    const res = await request(ctx.app)
      .post("/api/billing/portal-session")
      .set("Authorization", `Bearer ${tokenFor("u1")}`)
      .expect(502);
    expect(JSON.stringify(res.body)).not.toContain("sk_test_secret");
  });
});
