package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	// Abre o arquivo de hashes que copiamos do container.
	file, err := os.Open("wordpress_hashes.txt")
	if err != nil {
		log.Fatalf("Erro ao abrir o arquivo wordpress_hashes.txt: %v", err)
	}
	defer file.Close()

	fmt.Println("-- Script SQL gerado para popular a whitelist do WordPress Core")
	fmt.Println("-- Copie e cole este conteúdo no DBeaver para executar.")
	fmt.Println()

	// Lê o arquivo linha por linha.
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Cada linha tem o formato: "hash  /caminho/do/arquivo"
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			hash := parts[0]
			// O caminho pode conter espaços, então juntamos todo o resto.
			filePath := strings.Join(parts[1:], " ")

			// Gera o comando INSERT para a linha atual.
			// ON CONFLICT... garante que não teremos erros se tentarmos inserir um hash duplicado.
			fmt.Printf(
				"INSERT INTO known_good_hashes (file_hash_sha256, software_source, file_name) VALUES ('%s', 'WordPress Core', '%s') ON CONFLICT (file_hash_sha256) DO NOTHING;\n",
				hash,
				filePath,
			)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Erro ao ler o arquivo: %v", err)
	}

	fmt.Println("\n-- Geração de script SQL concluída.")
}