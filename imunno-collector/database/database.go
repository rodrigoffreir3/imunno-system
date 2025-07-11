// Arquivo: imunno-collector/database/database.go
package database

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

// New cria uma nova pool de conexões com o banco de dados.
func New(connStr string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(context.Background()); err != nil {
		return nil, err
	}
	log.Println("Conectado ao banco de dados PostgreSQL com sucesso!")
	return pool, nil
}

// >>>>>>>>>>>>>>>> INÍCIO DA NOVA FUNÇÃO <<<<<<<<<<<<<<<<
// IsHashWhitelisted verifica se um determinado hash SHA256 existe na tabela known_good_hashes.
// Retorna true se o hash for encontrado, false caso contrário.
func IsHashWhitelisted(ctx context.Context, pool *pgxpool.Pool, hash string) (bool, error) {
	var exists bool
	sql := `SELECT EXISTS(SELECT 1 FROM known_good_hashes WHERE file_hash_sha256 = $1)`

	err := pool.QueryRow(ctx, sql, hash).Scan(&exists)
	if err != nil {
		// Se não for um erro de "nenhuma linha encontrada", registramos o erro.
		log.Printf("!!! Erro ao verificar a whitelist para o hash %s: %v", hash, err)
		return false, err
	}

	return exists, nil
}
