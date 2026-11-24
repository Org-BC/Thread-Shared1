import { loadConfig } from './config.js';
import { openDb, purgeExpired } from './db.js';
import { createApp } from './app.js';

const config = loadConfig();
const db = openDb(config.databasePath);
const app = createApp({ config, db });

setInterval(() => purgeExpired(db), 10 * 60 * 1000).unref();
app.listen(config.port, () => console.log(`CPR portal auth listening on ${config.baseUrl}`));
