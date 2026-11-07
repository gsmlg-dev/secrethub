-- Legacy fixture based on Oban 2.24.2 PostgreSQL migrations 1 through 14.
-- Keep this legacy fixture independent of Styx's migration implementation.
CREATE TYPE __PREFIX__.oban_job_state AS ENUM (
  'available', 'suspended', 'scheduled', 'executing', 'retryable',
  'completed', 'discarded', 'cancelled'
);
CREATE TABLE __PREFIX__.oban_jobs (
  id bigserial PRIMARY KEY,
  state __PREFIX__.oban_job_state DEFAULT 'available' NOT NULL,
  queue text DEFAULT 'default' NOT NULL,
  worker text NOT NULL,
  args jsonb DEFAULT '{}'::jsonb NOT NULL,
  errors jsonb[] DEFAULT ARRAY[]::jsonb[] NOT NULL,
  attempt integer DEFAULT 0 NOT NULL,
  max_attempts integer DEFAULT 20 NOT NULL,
  inserted_at timestamp(6) without time zone DEFAULT timezone('UTC', now()) NOT NULL,
  scheduled_at timestamp(6) without time zone DEFAULT timezone('UTC', now()) NOT NULL,
  attempted_at timestamp(6) without time zone,
  completed_at timestamp(6) without time zone,
  attempted_by text[],
  discarded_at timestamp(6) without time zone,
  priority integer DEFAULT 0 NOT NULL,
  tags text[] DEFAULT ARRAY[]::text[],
  meta jsonb DEFAULT '{}'::jsonb,
  cancelled_at timestamp(6) without time zone,
  CONSTRAINT worker_length CHECK (char_length(worker) > 0 AND char_length(worker) < 128),
  CONSTRAINT queue_length CHECK (char_length(queue) > 0 AND char_length(queue) < 128),
  CONSTRAINT positive_max_attempts CHECK (max_attempts > 0),
  CONSTRAINT attempt_range CHECK (attempt BETWEEN 0 AND max_attempts),
  CONSTRAINT non_negative_priority CHECK (priority >= 0) NOT VALID
);
CREATE INDEX oban_jobs_state_queue_priority_scheduled_at_id_index
  ON __PREFIX__.oban_jobs (state, queue, priority, scheduled_at, id);
CREATE INDEX oban_jobs_args_index ON __PREFIX__.oban_jobs USING gin (args);
CREATE INDEX oban_jobs_meta_index ON __PREFIX__.oban_jobs USING gin (meta);
CREATE INDEX oban_jobs_state_cancelled_at_index ON __PREFIX__.oban_jobs (state, cancelled_at);
CREATE INDEX oban_jobs_state_discarded_at_index ON __PREFIX__.oban_jobs (state, discarded_at);
CREATE UNLOGGED TABLE __PREFIX__.oban_peers (
  name text PRIMARY KEY,
  node text NOT NULL,
  started_at timestamp(6) without time zone NOT NULL,
  expires_at timestamp(6) without time zone NOT NULL
);
COMMENT ON TABLE __PREFIX__.oban_jobs IS '14';
