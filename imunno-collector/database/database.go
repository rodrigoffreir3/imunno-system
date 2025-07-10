// Arquivo: imunno-collector/database/database.go
package database

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

// As structs dos eventos não vivem mais aqui.

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
