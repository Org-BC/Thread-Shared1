import { Router } from "express";
import type { Request, Response } from "express";
import { BillingService, NoStripeCustomerError } from "./billing.service.js";

export function billingRouter(service: BillingService): Router {
  const router = Router();

  router.get("/subscription", async (req: Request, res: Response) => {
    try {
      const subscription = await service.getSubscription(req.userId!);
      res.status(200).json({ subscription });
    } catch (err) {
      console.error("Failed to load subscription", err instanceof Error ? err.message : err);
      res.status(500).json({ error: "Could not load subscription" });
    }
  });

  router.post("/portal-session", async (req: Request, res: Response) => {
    try {
      const url = await service.createPortalSession(req.userId!);
      res.status(200).json({ url });
    } catch (err) {
      if (err instanceof NoStripeCustomerError) {
        res.status(409).json({ error: err.message });
        return;
      }
      console.error("Failed to create portal session", err instanceof Error ? err.message : err);
      res.status(502).json({ error: "Billing provider unavailable" });
    }
  });

  return router;
}
