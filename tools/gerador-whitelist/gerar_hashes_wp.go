// Arquivo: tools/gerador-whitelist/gerar_hashes_wp.go (Corrigido)
package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	log.Println("--- Iniciando Gerador de Whitelist Dinâmica para WordPress ---")

	// --- CORREÇÃO APLICADA AQUI ---
	// Os caminhos agora são relativos à pasta raiz do projeto, onde o comando é executado.
	wpPath := "./wordpress"
	outputSQLPath := "./postgres-init/insert_wordpress_hashes.sql"

	outputFile, err := os.Create(outputSQLPath)
	if err != nil {
		log.Fatalf("Erro ao criar arquivo de saída SQL: %v", err)
	}
	defer outputFile.Close()

	outputFile.WriteString("-- Script SQL gerado dinamicamente para a whitelist do WordPress\n\n")

	count := 0
	err = filepath.Walk(wpPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			hash, err := calcularHash(path)
			if err != nil {
				log.Printf("AVISO: Falha ao calcular hash para %s: %v", path, err)
				return nil
			}

			cleanPath := strings.TrimPrefix(path, wpPath)

			sqlCmd := fmt.Sprintf(
				"INSERT INTO known_good_hashes (file_hash_sha256, file_name, software_source) VALUES ('%s', '%s', 'WordPress Core') ON CONFLICT (file_hash_sha256) DO NOTHING;\n",
				hash,
				cleanPath,
			)
			outputFile.WriteString(sqlCmd)
			count++
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Erro ao percorrer o diretório do WordPress: %v", err)
	}

	log.Printf("--- Geração Concluída: %d hashes foram gerados e salvos em %s ---", count, outputSQLPath)
}

func calcularHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
