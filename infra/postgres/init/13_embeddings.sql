-- ============================================================
-- 13_embeddings.sql
-- M3 behavioral embeddings — learned vectors for hosts & destinations.
-- ============================================================
--
-- Hosts and destinations are represented as 32-dim vectors learned from
-- their per-(host, hour) behavior over the last 7 days. The reputation
-- scorer computes cosine distance between a log's source-host embedding
-- and the destination's "normal caller" centroid; unusual pairings
-- add risk weight, familiar pairings subtract.
--
-- pgvector is not installed on this cluster, so vectors are stored as
-- native FLOAT[] (double precision[]). Distance math happens in Python
-- inside the correlation service — at this scale (~100 hosts,
-- ~10k destinations) that's dramatically cheaper than running a nightly
-- schema migration to add the extension.
-- ============================================================

CREATE TABLE IF NOT EXISTS entity_embedding (
  entity_type   VARCHAR(32)       NOT NULL,  -- 'host' | 'destination'
  entity_value  VARCHAR(255)      NOT NULL,  -- IP for host; IP for destination
  vector        DOUBLE PRECISION[] NOT NULL,  -- 32-dim L2-normalized
  feature_stats JSONB,                        -- raw feature means used to build this embedding
  sample_count  INTEGER           NOT NULL DEFAULT 0,
  updated_at    TIMESTAMPTZ       NOT NULL DEFAULT NOW(),
  PRIMARY KEY (entity_type, entity_value)
);

CREATE INDEX IF NOT EXISTS idx_entity_embedding_updated
  ON entity_embedding (updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_entity_embedding_type
  ON entity_embedding (entity_type);

-- Model metadata — stores the autoencoder weights and feature-normalization
-- statistics so the learner can train incrementally and the scorer knows
-- when a retrain happened.
CREATE TABLE IF NOT EXISTS embedding_model (
  model_name    VARCHAR(64) PRIMARY KEY,
  dim_in        INTEGER     NOT NULL,
  dim_hidden    INTEGER     NOT NULL,
  feature_means DOUBLE PRECISION[],
  feature_stds  DOUBLE PRECISION[],
  w1            DOUBLE PRECISION[],
  b1            DOUBLE PRECISION[],
  w2            DOUBLE PRECISION[],
  b2            DOUBLE PRECISION[],
  training_loss DOUBLE PRECISION,
  trained_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  sample_count  INTEGER     NOT NULL DEFAULT 0
);

-- Scorer hook settings — default weight for the learned_similarity factor.
-- Positive weight means "unusual pairing adds risk"; negative weight on the
-- similar end means "familiar pairing suppresses risk". We ship with two
-- bounds: near/far thresholds and a max contribution of +/-1.0 to the sum.
INSERT INTO platform_settings (key, value, description) VALUES
  ('learned_similarity_weight',   '+1.0', 'Max positive contribution when host embedding is far from destination normal-caller centroid (unfamiliar pairing)'),
  ('learned_familiarity_weight',  '-0.8', 'Max negative contribution when host embedding is close to destination normal-caller centroid (familiar pairing)'),
  ('learned_similarity_far_cos',  '0.3',  'Cosine similarity below this counts as "far" (risk bump applied at full strength)'),
  ('learned_similarity_near_cos', '0.85', 'Cosine similarity above this counts as "near" (familiarity discount applied at full strength)')
ON CONFLICT (key) DO NOTHING;
