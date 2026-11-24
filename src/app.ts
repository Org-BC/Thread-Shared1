import express from "express";
import type Stripe from "stripe";
import { requireAuth } from "./auth/middleware.js";
import { BillingService } from "./billing/billing.service.js";
import { billingRouter } from "./billing/billing.routes.js";
import { webhookRouter } from "./billing/webhook.route.js";
import type { StripeConfig } from "./config/stripe.js";
import type { Db } from "./db/types.js";

export interface AppDeps {
  db: Db;
  stripe: Stripe;
  stripeConfig: StripeConfig;
  jwtSecret: string;
}

export function createApp({ db, stripe, stripeConfig, jwtSecret }: AppDeps) {
  const app = express();
  const service = new BillingService(db, stripe, stripeConfig.returnUrl);

  // The webhook needs the raw body, so it is mounted before the JSON parser.
  app.use("/api/billing", webhookRouter(stripe, service, stripeConfig.webhookSecret));

  app.use(express.json());
  app.use("/api/billing", requireAuth(jwtSecret), billingRouter(service));

  return { app, service };
}
