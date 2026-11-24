import { randomBytes } from 'node:crypto';

export function newCorrelationId() {
  return randomBytes(6).toString('hex');
}

// Writes one JSON line per event. Callers pass only non-secret fields
// (never tokens, assertions or client secrets).
export function createAudit(sink = (line) => console.log(line)) {
  return function audit(event) {
    sink(JSON.stringify({ ts: new Date().toISOString(), ...event }));
  };
}
