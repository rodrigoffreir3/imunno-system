// Arquivo: imunno-postgres/populate_whitelist.go
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	// Abre o arquivo de hashes. Este script espera que o wordpress_hashes.txt
	// esteja na pasta raiz do projeto, um nível acima de onde este script está.
	hashesFile, err := os.Open("../wordpress_hashes.txt")
	if err != nil {
		log.Fatalf("Erro ao abrir o arquivo wordpress_hashes.txt: %v. Certifique-se de que ele está na pasta raiz do projeto.", err)
	}
	defer hashesFile.Close()

	// Cria o arquivo de saída SQL.
	outputFile, err := os.Create("insert_hashes.sql")
	if err != nil {
		log.Fatalf("Erro ao criar o arquivo insert_hashes.sql: %v", err)
	}
	defer outputFile.Close()

	// Escreve o cabeçalho do arquivo SQL.
	header := "-- Script SQL gerado para popular a whitelist do WordPress Core\n"
	header += "-- Execute este script no seu banco de dados imunno_db.\n\n"
	outputFile.WriteString(header)

	scanner := bufio.NewScanner(hashesFile)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			hash := parts[0]
			filePath := strings.Join(parts[1:], " ")

			// Gera o comando INSERT para a linha atual e escreve no arquivo.
			sql_command := fmt.Sprintf(
				"INSERT INTO known_good_hashes (file_hash_sha256, file_name, software_source) VALUES ('%s', '%s', 'WordPress Core') ON CONFLICT (file_hash_sha256) DO NOTHING;\n",
				hash,
				filePath,
			)
			outputFile.WriteString(sql_command)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Erro ao ler o arquivo de hashes: %v", err)
	}

	fmt.Println("Arquivo 'insert_hashes.sql' gerado com sucesso dentro da pasta 'imunno-postgres'!")
}
