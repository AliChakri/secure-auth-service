import {
  pgTable,
  uuid,
  boolean,
  text,
  timestamp,
} from 'drizzle-orm/pg-core';

import { users } from '../users.schema.js';

export const userTwoFactor = pgTable(
  'user_two_factor',
  {
    userId: uuid('user_id')
      .primaryKey()
      .references(() => users.id, {
        onDelete: 'cascade',
      }),

    enabled: boolean('enabled')
      .notNull()
      .default(false),

    secretEncrypted: text('secret_encrypted'),

    tempSecretEncrypted: text('temp_secret_encrypted'),

    verifiedAt: timestamp('verified_at', {
      withTimezone: true,
    }),

    backupCodesGeneratedAt: timestamp(
      'backup_codes_generated_at',
      {
        withTimezone: true,
      },
    ),
  },
);

export type UserTwoFactor =
  typeof userTwoFactor.$inferSelect;

export type NewUserTwoFactor =
  typeof userTwoFactor.$inferInsert;