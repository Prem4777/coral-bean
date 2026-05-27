CREATE TABLE "scan_findings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scan_job_id" uuid NOT NULL,
	"package_name" text NOT NULL,
	"ecosystem" varchar(64) NOT NULL,
	"vulnerability_id" text NOT NULL,
	"cve_id" text,
	"kev_status" boolean DEFAULT false NOT NULL,
	"severity" varchar(32) NOT NULL,
	"summary" text NOT NULL,
	"fix" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scan_jobs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"repository_url" text NOT NULL,
	"owner" varchar(255) NOT NULL,
	"repo" varchar(255) NOT NULL,
	"branch" varchar(255),
	"status" varchar(32) DEFAULT 'queued' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "scan_findings" ADD CONSTRAINT "scan_findings_scan_job_id_scan_jobs_id_fk" FOREIGN KEY ("scan_job_id") REFERENCES "public"."scan_jobs"("id") ON DELETE cascade ON UPDATE no action;