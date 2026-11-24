// CacheProvider for node-saml backed by SQLite, so request IDs and seen assertion IDs
// survive restarts and are shared by every process using the database.
// Keys are namespaced per identity provider so a response from one IdP cannot answer
// a request sent to another.
export function createSqlCache(db, namespace, ttlMs) {
  const k = (key) => `${namespace}:${key}`;
  const purge = () => db.prepare('DELETE FROM kv_cache WHERE expires_at <= ?').run(Date.now());
  return {
    async saveAsync(key, value) {
      const now = Date.now();
      purge();
      db.prepare('INSERT OR REPLACE INTO kv_cache (key, value, created_at, expires_at) VALUES (?, ?, ?, ?)').run(
        k(key), value, now, now + ttlMs,
      );
      return { value, createdAt: now };
    },
    async getAsync(key) {
      return db.prepare('SELECT value FROM kv_cache WHERE key = ? AND expires_at > ?').get(k(key), Date.now())?.value ?? null;
    },
    async removeAsync(key) {
      if (key == null) return null;
      return db.prepare('DELETE FROM kv_cache WHERE key = ? RETURNING value').get(k(key))?.value ?? null;
    },
    async consumeAsync(key) {
      const row = db.prepare('DELETE FROM kv_cache WHERE key = ? RETURNING value, expires_at').get(k(key));
      return row && row.expires_at > Date.now() ? row.value : null;
    },
    async saveIfAbsentAsync(key, value, expiresAtMs) {
      purge();
      const info = db
        .prepare('INSERT INTO kv_cache (key, value, created_at, expires_at) VALUES (?, ?, ?, ?) ON CONFLICT(key) DO NOTHING')
        .run(k(key), value, Date.now(), expiresAtMs);
      return info.changes === 1;
    },
  };
}
