import { sql } from 'drizzle-orm';
import {
  pgTable,
  uuid,
  varchar,
  text,
  boolean,
  timestamp,
  uniqueIndex,
} from 'drizzle-orm/pg-core';
export const users = pgTable(
  'users',
  {
    id: uuid('id').defaultRandom().primaryKey(),

    name: varchar('name', { length: 120 }).notNull(),

    email: varchar('email', { length: 320 }).notNull(),

    passwordHash: varchar('password_hash', { length: 255 }),

    avatar: text('avatar').notNull().default(''),

    isVerified: boolean('is_verified')
      .notNull()
      .default(false),

    createdAt: timestamp('created_at', {
      withTimezone: true,
    })
      .notNull()
      .defaultNow(),

    updatedAt: timestamp('updated_at', {
      withTimezone: true,
    })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex('users_email_unique')
        .on(sql`lower(${table.email})`),
  ],
);

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;