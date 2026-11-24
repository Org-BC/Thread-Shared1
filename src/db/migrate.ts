import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { requireEnv } from "../config/env.js";
import type { Db } from "./types.js";

const migrationsDir = join(fileURLToPath(import.meta.url), "../../../migrations");

export async function runMigrations(db: Db, dir = migrationsDir): Promise<void> {
  const files = readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
  for (const file of files) {
    await db.query(readFileSync(join(dir, file), "utf8"));
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const pool = new pg.Pool({ connectionString: requireEnv(process.env, "DATABASE_URL") });
  runMigrations(pool)
    .then(() => console.log("Migrations applied"))
    .catch((err) => {
      console.error(err);
      process.exitCode = 1;
    })
    .finally(() => pool.end());
}
