import { readFileSync } from "node:fs";
import { newDb } from "pg-mem";
import Stripe from "stripe";
import jwt from "jsonwebtoken";
import { vi } from "vitest";
import { createApp } from "../src/app.js";
import type { Db } from "../src/db/types.js";

export const JWT_SECRET = "test-jwt-secret";
export const WEBHOOK_SECRET = "whsec_test";
export const RETURN_URL = "https://portal.example.com/billing";

export async function createTestDb(): Promise<Db> {
  const mem = newDb();
  const { Pool } = mem.adapters.createPg();
  const pool = new Pool();
  await pool.query(readFileSync(new URL("../migrations/001_billing.sql", import.meta.url), "utf8"));
  return pool as unknown as Db;
}

export function fakeStripe() {
  return {
    customers: { create: vi.fn(async () => ({ id: "cus_new" })) },
    billingPortal: {
      sessions: { create: vi.fn(async () => ({ url: "https://billing.stripe.com/session/test" })) },
    },
    webhooks: new Stripe("sk_test_dummy").webhooks,
  };
}

export type FakeStripe = ReturnType<typeof fakeStripe>;

export async function createTestApp() {
  const db = await createTestDb();
  const stripe = fakeStripe();
  const { app, service } = createApp({
    db,
    stripe: stripe as unknown as Stripe,
    stripeConfig: { secretKey: "sk_test_dummy", webhookSecret: WEBHOOK_SECRET, returnUrl: RETURN_URL },
    jwtSecret: JWT_SECRET,
  });
  return { app, service, db, stripe };
}

export const tokenFor = (userId: string) => jwt.sign({ sub: userId }, JWT_SECRET, { algorithm: "HS256" });

export function signedWebhook(payload: object, secret = WEBHOOK_SECRET) {
  const body = JSON.stringify(payload);
  const header = new Stripe("sk_test_dummy").webhooks.generateTestHeaderString({
    payload: body,
    secret,
  });
  return { body, header };
}

export function subscriptionEvent(
  id: string,
  type: string,
  overrides: { status?: string; cancel?: boolean; created?: number; customer?: string; subId?: string } = {},
) {
  return {
    id,
    object: "event",
    type,
    created: overrides.created ?? 1_700_000_000,
    data: {
      object: {
        id: overrides.subId ?? "sub_1",
        object: "subscription",
        customer: overrides.customer ?? "cus_new",
        status: overrides.status ?? "active",
        cancel_at_period_end: overrides.cancel ?? false,
        items: {
          data: [{ current_period_end: 1_800_000_000, price: { id: "price_1", lookup_key: "pro", nickname: null } }],
        },
      },
    },
  };
}

export function invoiceEvent(id: string, type: string, subId = "sub_1", created = 1_700_000_100) {
  return {
    id,
    object: "event",
    type,
    created,
    data: { object: { id: "in_1", object: "invoice", parent: { subscription_details: { subscription: subId } } } },
  };
}
