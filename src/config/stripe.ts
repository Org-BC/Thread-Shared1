import Stripe from "stripe";
import { requireEnv } from "./env.js";

export interface StripeConfig {
  secretKey: string;
  webhookSecret: string;
  returnUrl: string;
}

export function loadStripeConfig(env: NodeJS.ProcessEnv = process.env): StripeConfig {
  return {
    secretKey: requireEnv(env, "STRIPE_SECRET_KEY"),
    webhookSecret: requireEnv(env, "STRIPE_WEBHOOK_SECRET"),
    returnUrl: requireEnv(env, "BILLING_RETURN_URL"),
  };
}

export function createStripeClient(config: StripeConfig): Stripe {
  return new Stripe(config.secretKey);
}
