import express, { Router } from "express";
import type { Request, Response } from "express";
import type Stripe from "stripe";
import type { BillingService } from "./billing.service.js";

export function webhookRouter(stripe: Stripe, service: BillingService, webhookSecret: string): Router {
  const router = Router();

  router.post("/webhook", express.raw({ type: "application/json" }), async (req: Request, res: Response) => {
    const signature = req.headers["stripe-signature"];
    if (typeof signature !== "string" || !Buffer.isBuffer(req.body)) {
      res.status(400).json({ error: "Missing signature" });
      return;
    }

    let event: Stripe.Event;
    try {
      event = stripe.webhooks.constructEvent(req.body, signature, webhookSecret);
    } catch {
      res.status(400).json({ error: "Invalid signature" });
      return;
    }

    try {
      await service.handleEvent(event);
      res.status(200).json({ received: true });
    } catch (err) {
      console.error(`Webhook ${event.id} failed`, err instanceof Error ? err.message : err);
      res.status(500).json({ error: "Processing failed" });
    }
  });

  return router;
}
