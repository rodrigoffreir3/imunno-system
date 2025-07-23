-- Arquivo: postgres-init/init.sql (Corrigido e Completo)

-- Criação da tabela para eventos de arquivo
CREATE TABLE IF NOT EXISTS file_events (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    file_hash_sha256 VARCHAR(64),
    file_content TEXT,
    threat_score INT,
    analysis_findings JSONB,
    is_whitelisted BOOLEAN DEFAULT FALSE,
    quarantined_path TEXT,
    timestamp TIMESTAMPTZ NOT NULL
);

-- Criação da tabela para eventos de processo
CREATE TABLE IF NOT EXISTS process_events (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    process_id INT NOT NULL,
    parent_id INT,
    command TEXT,
    username VARCHAR(255),
    threat_score INT DEFAULT 0,
    timestamp TIMESTAMPTZ NOT NULL
);

-- --- CORREÇÃO APLICADA AQUI ---
-- Criação da tabela para hashes conhecidos (whitelist) com a estrutura correta
CREATE TABLE IF NOT EXISTS known_good_hashes (
    id SERIAL PRIMARY KEY,
    file_hash_sha256 VARCHAR(64) NOT NULL UNIQUE,
    file_name VARCHAR(255), -- Coluna que estava faltando
    software_source VARCHAR(100), -- Coluna que estava faltando
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Criação do índice para a whitelist
CREATE INDEX IF NOT EXISTS idx_known_good_hashes_hash ON known_good_hashes(file_hash_sha256);

-- Mensagem de sucesso para os logs
SELECT 'Banco de dados imunno_db e todas as tabelas iniciais criados com sucesso!' as "Status";