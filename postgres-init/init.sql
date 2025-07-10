-- Arquivo: postgres-init/init.sql (Versão Corrigida)

CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    file_hash_sha256 VARCHAR(64) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    threat_score INTEGER DEFAULT 0,
    analysis_findings JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS process_events (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    process_id INTEGER NOT NULL,
    parent_id INTEGER NOT NULL,
    command TEXT,
    username VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    threat_score INTEGER DEFAULT 0 -- <-- A COLUNA QUE FALTAVA
);