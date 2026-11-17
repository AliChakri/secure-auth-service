import {
  pgTable,
  uuid,
  varchar,
  timestamp,
  index,
  uniqueIndex,
} from 'drizzle-orm/pg-core';

import { users } from '../users.schema.js';

export const twoFactorBackupCodes = pgTable(
  'two_factor_backup_codes',
  {
    id: uuid('id').defaultRandom().primaryKey(),

    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, {
        onDelete: 'cascade',
      }),

    codeHash: varchar('code_hash', {
      length: 255,
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
    index('backup_codes_user_id_idx').on(table.userId),

    uniqueIndex('backup_codes_hash_unique')
      .on(table.userId, table.codeHash),
  ],
);

export type TwoFactorBackupCode =
  typeof twoFactorBackupCodes.$inferSelect;