import {
  pgTable,
  uuid,
  varchar,
  timestamp,
  uniqueIndex,
  index,
} from 'drizzle-orm/pg-core';

import { users } from '../users.schema.js';

export const recoveryTokens = pgTable(
  'recovery_tokens',
  {
    id: uuid('id').defaultRandom().primaryKey(),

    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, {
        onDelete: 'cascade',
      }),

    tokenHash: varchar('token_hash', {
      length: 255,
    }).notNull(),

    expiresAt: timestamp('expires_at', {
      withTimezone: true,
    }).notNull(),

    usedAt: timestamp('used_at', {
      withTimezone: true,
    }),

    createdAt: timestamp('created_at', {
      withTimezone: true,
    })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex('recovery_token_hash_unique')
      .on(table.tokenHash),

    index('recovery_tokens_user_id_idx')
      .on(table.userId),

    index('recovery_tokens_expiry_idx')
      .on(table.expiresAt),
  ],
);

export type RecoveryToken =
  typeof recoveryTokens.$inferSelect;