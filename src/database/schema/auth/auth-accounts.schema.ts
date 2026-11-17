import { sql } from 'drizzle-orm';

import {
  pgTable,
  uuid,
  varchar,
  timestamp,
  uniqueIndex,
  index,
  check,
} from 'drizzle-orm/pg-core';

import { users } from '../users.schema.js';

export const authAccounts = pgTable(
  'auth_accounts',
  {
    id: uuid('id').defaultRandom().primaryKey(),

    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, {
        onDelete: 'cascade',
      }),

    provider: varchar('provider', { length: 50 })
      .notNull(),

    providerUserId: varchar('provider_user_id', {
      length: 255,
    }),

    createdAt: timestamp('created_at', {
      withTimezone: true,
    })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    // An external provider identity can belong to only one user.
    uniqueIndex('auth_provider_identity_unique')
      .on(table.provider, table.providerUserId)
      .where(sql`${table.provider} <> 'local'`),

    // A user can have only one local authentication method.
    uniqueIndex('auth_one_local_per_user')
      .on(table.userId)
      .where(sql`${table.provider} = 'local'`),

    index('auth_accounts_user_id_idx').on(table.userId),

    // Local accounts have no external provider ID.
    // External accounts must have one.
    check(
      'auth_provider_identity_check',
      sql`(
        (${table.provider} = 'local'
          AND ${table.providerUserId} IS NULL)
        OR
        (${table.provider} <> 'local'
          AND ${table.providerUserId} IS NOT NULL)
      )`,
    ),
  ],
);

export type AuthAccount =
  typeof authAccounts.$inferSelect;

export type NewAuthAccount =
  typeof authAccounts.$inferInsert;