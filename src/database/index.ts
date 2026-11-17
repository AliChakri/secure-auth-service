
import 'dotenv/config';

import { Pool } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';

import * as schema from './schema/index.js';

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  throw new Error('DATABASE_URL is not defined');
}

export const pool = new Pool({
  connectionString: DATABASE_URL,

  // Connection pool
  max: 10,
  min: 0,

  // Connection lifecycle
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,

  // Query execution
  statement_timeout: 15_000,

  // Connection identification
  application_name: 'auth-api',
});

// Drizzle ORM instance
export const db = drizzle({
  client: pool,
  schema,
});

// Handle unexpected idle-client errors
pool.on('error', (error) => {
  console.error('Unexpected PostgreSQL pool error:', error);
});
