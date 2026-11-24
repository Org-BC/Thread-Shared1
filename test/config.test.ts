import { describe, expect, it } from "vitest";
import { loadStripeConfig } from "../src/config/stripe.js";

const full = { STRIPE_SECRET_KEY: "sk", STRIPE_WEBHOOK_SECRET: "wh", BILLING_RETURN_URL: "https://x" };

describe("loadStripeConfig", () => {
  it("reads the three variables", () => {
    expect(loadStripeConfig(full)).toEqual({ secretKey: "sk", webhookSecret: "wh", returnUrl: "https://x" });
  });

  it.each(Object.keys(full))("fails naming %s when it is missing", (name) => {
    const env: NodeJS.ProcessEnv = { ...full };
    delete env[name];
    expect(() => loadStripeConfig(env)).toThrow(name);
  });
});
