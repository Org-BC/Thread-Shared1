import pg from "pg";
import { createApp } from "./app.js";
import { requireEnv } from "./config/env.js";
import { createStripeClient, loadStripeConfig } from "./config/stripe.js";

const stripeConfig = loadStripeConfig();
const jwtSecret = requireEnv(process.env, "JWT_SECRET");
const pool = new pg.Pool({ connectionString: requireEnv(process.env, "DATABASE_URL") });

const { app } = createApp({
  db: pool,
  stripe: createStripeClient(stripeConfig),
  stripeConfig,
  jwtSecret,
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => console.log(`Billing API listening on ${port}`));
