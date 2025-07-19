-- Criação da tabela para eventos de arquivo
CREATE TABLE file_events (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) NOT NULL,
    -- ADIÇÃO: Coluna hostname que estava faltando
    hostname VARCHAR(255),
    file_path TEXT NOT NULL,
    file_hash_sha256 VARCHAR(64),
    file_content TEXT,
    threat_score INTEGER,
    analysis_findings JSONB,
    is_whitelisted BOOLEAN DEFAULT FALSE,
    quarantined_path TEXT,
    timestamp TIMESTAMPTZ NOT NULL
);

-- Índices para otimizar buscas
CREATE INDEX idx_file_events_agent_id ON file_events(agent_id);
CREATE INDEX idx_file_events_timestamp ON file_events(timestamp);

-- Criação da tabela para eventos de processo
CREATE TABLE process_events (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) NOT NULL,
    hostname VARCHAR(255),
    process_id INTEGER,
    parent_id INTEGER,
    command TEXT,
    username VARCHAR(255),
    threat_score INTEGER,
    timestamp TIMESTAMPTZ NOT NULL
);

-- Índices para otimizar buscas
CREATE INDEX idx_process_events_agent_id ON process_events(agent_id);
CREATE INDEX idx_process_events_timestamp ON process_events(timestamp);

-- Criação da tabela para hashes conhecidos (whitelist)
CREATE TABLE known_good_hashes (
    id SERIAL PRIMARY KEY,
    file_hash_sha256 VARCHAR(64) UNIQUE NOT NULL,
    description TEXT,
    added_on TIMESTAMPTZ DEFAULT NOW()
);

-- Índices para otimizar buscas
CREATE INDEX idx_known_good_hashes_hash ON known_good_hashes(file_hash_sha256);