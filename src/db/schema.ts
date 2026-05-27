import { relations } from "drizzle-orm";
import {
  boolean,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";

export const scanJobs = pgTable("scan_jobs", {
  id: uuid("id").defaultRandom().primaryKey(),
  repositoryUrl: text("repository_url").notNull(),
  owner: varchar("owner", { length: 255 }).notNull(),
  repo: varchar("repo", { length: 255 }).notNull(),
  branch: varchar("branch", { length: 255 }),
  status: varchar("status", { length: 32 }).notNull().default("queued"),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const scanFindings = pgTable("scan_findings", {
  id: uuid("id").defaultRandom().primaryKey(),
  scanJobId: uuid("scan_job_id")
    .notNull()
    .references(() => scanJobs.id, { onDelete: "cascade" }),
  packageName: text("package_name").notNull(),
  ecosystem: varchar("ecosystem", { length: 64 }).notNull(),
  vulnerabilityId: text("vulnerability_id").notNull(),
  cveId: text("cve_id"),
  kevStatus: boolean("kev_status").notNull().default(false),
  severity: varchar("severity", { length: 32 }).notNull(),
  summary: text("summary").notNull(),
  fix: text("fix").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const scanJobsRelations = relations(scanJobs, ({ many }) => ({
  findings: many(scanFindings),
}));

export const scanFindingsRelations = relations(scanFindings, ({ one }) => ({
  scanJob: one(scanJobs, {
    fields: [scanFindings.scanJobId],
    references: [scanJobs.id],
  }),
}));
