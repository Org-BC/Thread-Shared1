CREATE TABLE IF NOT EXISTS billing_customers (
  user_id            TEXT PRIMARY KEY,
  stripe_customer_id TEXT NOT NULL UNIQUE,
  created_at         TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS subscriptions (
  stripe_subscription_id TEXT PRIMARY KEY,
  user_id                TEXT NOT NULL,
  plan                   TEXT NOT NULL,
  status                 TEXT NOT NULL,
  current_period_end     TIMESTAMP,
  cancel_at_period_end   BOOLEAN NOT NULL DEFAULT false,
  last_event_created     BIGINT NOT NULL DEFAULT 0,
  updated_at             TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS subscriptions_user_id_idx ON subscriptions (user_id);

CREATE TABLE IF NOT EXISTS stripe_events (
  event_id     TEXT PRIMARY KEY,
  processed_at TIMESTAMP NOT NULL DEFAULT now()
);
