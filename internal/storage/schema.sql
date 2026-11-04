-- Openness Linux vulnerability resolver: PostgreSQL schema for normalized rules
-- and resolver metadata.
--
-- Raw feed payloads are NOT stored here: they live as immutable snapshots in
-- object storage / filesystem (data/raw/<vendor>/<date>/). PostgreSQL keeps
-- source, snapshot id, checksum, parser version, object path and
-- normalization status.
--
-- The CLI currently uses the filesystem store (data/normalized/...); this
-- schema is the target for the service deployment and mirrors the Go models
-- in internal/rules.

CREATE TABLE IF NOT EXISTS advisory_sources (
    id               TEXT PRIMARY KEY,          -- e.g. ubuntu-oval-usn-jammy
    name             TEXT NOT NULL,
    ecosystem        TEXT NOT NULL,             -- dpkg | apk | rpm | multi
    vendor           TEXT NOT NULL,
    url              TEXT NOT NULL,
    format           TEXT NOT NULL,
    priority         INTEGER NOT NULL,          -- 1 = distro vendor advisory
    enabled          BOOLEAN NOT NULL DEFAULT true,
    parser           TEXT NOT NULL,
    refresh_interval_seconds INTEGER NOT NULL,
    notes            TEXT
);

CREATE TABLE IF NOT EXISTS feed_snapshots (
    snapshot_id      BIGSERIAL PRIMARY KEY,
    source_id        TEXT NOT NULL REFERENCES advisory_sources(id),
    downloaded_at    TIMESTAMPTZ NOT NULL,
    source_updated_at TIMESTAMPTZ,
    sha256           TEXT NOT NULL,
    etag             TEXT,
    size_bytes       BIGINT NOT NULL,
    parser_version   TEXT NOT NULL,
    raw_object_path  TEXT NOT NULL,             -- object storage / fs path
    normalization_status TEXT NOT NULL DEFAULT 'pending', -- pending|ok|failed
    UNIQUE (source_id, sha256)
);

CREATE TABLE IF NOT EXISTS raw_advisory_objects (
    raw_object_id    TEXT PRIMARY KEY,          -- vendor/date/file
    snapshot_id      BIGINT NOT NULL REFERENCES feed_snapshots(snapshot_id),
    object_path      TEXT NOT NULL,
    sha256           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS normalized_advisories (
    advisory_id      TEXT PRIMARY KEY,          -- USN-xxxx-x / CVE id
    vendor           TEXT NOT NULL,
    title            TEXT,
    severity         TEXT,
    published_at     TIMESTAMPTZ,
    snapshot_id      BIGINT REFERENCES feed_snapshots(snapshot_id)
);

CREATE TABLE IF NOT EXISTS package_rules (
    rule_id          TEXT PRIMARY KEY,
    ecosystem        TEXT NOT NULL,
    vendor           TEXT NOT NULL,
    distribution     TEXT NOT NULL,
    release          TEXT NOT NULL,             -- codename (jammy) / branch (v3.18)
    architecture     TEXT NOT NULL DEFAULT '',  -- '' = all
    package_name     TEXT NOT NULL,
    source_package   TEXT NOT NULL,
    status           TEXT NOT NULL,             -- normalized status
    raw_status       TEXT NOT NULL,             -- vendor wording, preserved
    fixed_version    TEXT,
    comparator       TEXT NOT NULL,             -- dpkg | apk
    cve_id           TEXT NOT NULL,
    advisory_ids     TEXT[],
    urgency          TEXT,
    support_tier     TEXT,
    vendor_notes     TEXT,
    source_priority  INTEGER NOT NULL,
    published_at     TIMESTAMPTZ,
    updated_at       TIMESTAMPTZ,
    snapshot_id      BIGINT REFERENCES feed_snapshots(snapshot_id),
    raw_object_id    TEXT
);

-- Resolver lookup path: ecosystem + distribution + release + package name.
-- Idempotent index creation (drop if exists, create if not exists).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_package_rules_lookup') THEN
        CREATE INDEX idx_package_rules_lookup
            ON package_rules (ecosystem, distribution, release, package_name);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_package_rules_source_lookup') THEN
        CREATE INDEX idx_package_rules_source_lookup
            ON package_rules (ecosystem, distribution, release, source_package);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_package_rules_cve') THEN
        CREATE INDEX idx_package_rules_cve ON package_rules (cve_id);
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS rule_revisions (
    revision_id      BIGSERIAL PRIMARY KEY,
    rule_id          TEXT NOT NULL REFERENCES package_rules(rule_id),
    snapshot_id      BIGINT NOT NULL REFERENCES feed_snapshots(snapshot_id),
    change_type      TEXT NOT NULL,             -- created|updated|withdrawn
    changed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    previous_value   JSONB
);

CREATE TABLE IF NOT EXISTS rule_conflicts (
    conflict_id      BIGSERIAL PRIMARY KEY,
    cve_id           TEXT NOT NULL,
    package_name     TEXT NOT NULL,
    release          TEXT NOT NULL,
    winning_rule_id  TEXT REFERENCES package_rules(rule_id),
    losing_rule_id   TEXT REFERENCES package_rules(rule_id),
    reason           TEXT NOT NULL,
    detected_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS resolver_runs (
    run_id           BIGSERIAL PRIMARY KEY,
    asset_id         TEXT NOT NULL,
    evidence_file    TEXT NOT NULL,
    started_at       TIMESTAMPTZ NOT NULL,
    duration_ms      BIGINT NOT NULL,
    platform         JSONB NOT NULL,
    metrics          JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id       TEXT PRIMARY KEY,
    run_id           BIGINT NOT NULL REFERENCES resolver_runs(run_id),
    asset_id         TEXT NOT NULL,
    scope            TEXT NOT NULL,             -- host | container
    image_digest     TEXT,
    cve_id           TEXT NOT NULL,
    state            TEXT NOT NULL,
    confidence       TEXT NOT NULL,
    detection_method TEXT NOT NULL,
    binary_package   TEXT NOT NULL,
    source_package   TEXT,
    installed_version TEXT NOT NULL,
    fixed_version    TEXT,
    payload          JSONB NOT NULL             -- full explainable finding
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_findings_asset_state') THEN
        CREATE INDEX idx_findings_asset_state ON findings (asset_id, state);
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id       TEXT NOT NULL REFERENCES findings(finding_id),
    evidence_id      TEXT NOT NULL,
    PRIMARY KEY (finding_id, evidence_id)
);
