-- Banco de Dados: imunno_db
-- Este script inicializa as tabelas essenciais do Imunno-System

-- ============================
-- 1. Tabela: event_files
-- ============================
CREATE TABLE IF NOT EXISTS event_files (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) NOT NULL,
    path TEXT NOT NULL,
    hash VARCHAR(128) NOT NULL,
    threat_score FLOAT NOT NULL,
    quarantine BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Índices úteis
CREATE INDEX IF NOT EXISTS idx_event_files_agent_id ON event_files(agent_id);
CREATE INDEX IF NOT EXISTS idx_event_files_hash ON event_files(hash);

-- ============================
-- 2. Tabela: event_processes
-- ============================
CREATE TABLE IF NOT EXISTS event_processes (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) NOT NULL,
    command TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Índices úteis
CREATE INDEX IF NOT EXISTS idx_event_processes_agent_id ON event_processes(agent_id);
CREATE INDEX IF NOT EXISTS idx_event_processes_timestamp ON event_processes(timestamp);

-- ============================
-- 3. Tabela: known_good_hashes
-- ============================
CREATE TABLE IF NOT EXISTS known_good_hashes (
    id SERIAL PRIMARY KEY,
    file_path TEXT NOT NULL,
    file_hash VARCHAR(128) NOT NULL,
    description TEXT,
    source TEXT DEFAULT 'wordpress',  -- wordpress, plugin, theme, etc
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Evita duplicações
CREATE UNIQUE INDEX IF NOT EXISTS idx_known_good_hashes_path_hash ON known_good_hashes(file_path, file_hash);
CREATE INDEX IF NOT EXISTS idx_known_good_hashes_hash ON known_good_hashes(file_hash);
