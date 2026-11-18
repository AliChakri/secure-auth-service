import dotenv from 'dotenv';
import { defineConfig } from 'drizzle-kit';


dotenv.config();

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  throw new Error('DATABASE_URL is not defined');
}

export default defineConfig({
  dialect: 'postgresql',

  schema: './src/database/schema/index.ts',

  out: './src/database/migrations',

  dbCredentials: {
    url: DATABASE_URL,
  },

  migrations: {
    schema: 'drizzle',
    table: '__drizzle_migrations',
  },

  schemaFilter: ['public'],

  verbose: true,

  strict: true,
});