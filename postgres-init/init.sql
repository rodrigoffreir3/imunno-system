-- Este script é executado automaticamente na primeira vez que o contêiner do PostgreSQL é criado.
-- Ele define o esquema inicial completo e correto do nosso banco de dados 'imunno_db'.

-- Tabela para armazenar eventos de arquivo detectados pelo agente.
CREATE TABLE IF NOT EXISTS file_events (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    file_hash_sha256 VARCHAR(64) NOT NULL,
    threat_score INT DEFAULT 0,
    analysis_findings JSONB,
    is_whitelisted BOOLEAN DEFAULT FALSE,
    quarantined_path TEXT,
    timestamp TIMESTAMPTZ NOT NULL
);

-- Tabela para armazenar eventos de processo detectados pelo agente.
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

-- Tabela para armazenar hashes de arquivos conhecidos e seguros (Whitelist).
-- Adicionando a criação desta tabela ao script de inicialização para garantir que ela sempre exista.
CREATE TABLE IF NOT EXISTS known_good_hashes (
    id SERIAL PRIMARY KEY,
    file_hash_sha256 VARCHAR(64) NOT NULL UNIQUE,
    file_name VARCHAR(255),
    software_source VARCHAR(100), -- Ex: 'WordPress 6.5.5', 'Joomla 5.2.1'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Cria índices para buscas ultra-rápidas.
CREATE INDEX IF NOT EXISTS idx_known_good_hashes_hash ON known_good_hashes(file_hash_sha256);

-- Garante que nosso usuário 'imunno_user' seja o dono das tabelas.
ALTER TABLE file_events OWNER TO imunno_user;
ALTER TABLE process_events OWNER TO imunno_user;
ALTER TABLE known_good_hashes OWNER TO imunno_user;

-- Mensagem de sucesso para o log do Docker.
SELECT 'Banco de dados imunno_db e todas as tabelas iniciais criados com sucesso!';
