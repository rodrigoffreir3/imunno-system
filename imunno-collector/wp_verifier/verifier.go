// Arquivo: imunno-collector/wp_verifier/verifier.go
package wp_verifier

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WpChecksums armazena o cache dos checksums para uma versão específica.
type WpChecksums struct {
	Checksums  map[string]interface{}
	LastUpdate time.Time
}

var (
	// Usamos um sync.Map para guardar os caches de forma segura em um ambiente com múltiplas threads.
	cache = &sync.Map{}
	// Duração do cache para evitar muitas chamadas à API.
	cacheDuration = 12 * time.Hour
)

// IsOfficialFile é a função principal que usaremos. Ela verifica se um arquivo/hash é oficial.
func IsOfficialFile(filePath, fileHash, wpVersion, locale string) bool {
	// Primeiro, tentamos pegar a lista de checksums do nosso cache.
	checksums, found := getChecksumsFromCache(wpVersion, locale)
	if !found {
		// Se não estiver no cache, buscamos na API do WordPress.
		var err error
		checksums, err = fetchAndCacheChecksums(wpVersion, locale)
		if err != nil {
			log.Printf("[WP Verifier] ERRO ao buscar checksums para a versão %s: %v", wpVersion, err)
			return false // Em caso de erro, consideramos o arquivo como não oficial por segurança.
		}
	}

	// Agora que temos a lista, verificamos se o nosso arquivo está nela.
	// Removemos os diretórios iniciais do WordPress para bater com o formato da API.
	cleanPath := removeWpPathPrefix(filePath)

	officialHash, exists := checksums[cleanPath]
	if !exists {
		return false // O arquivo não está na lista oficial.
	}

	// Comparamos o hash do nosso arquivo com o hash oficial.
	return officialHash == fileHash
}

// fetchAndCacheChecksums busca os checksums na API e os guarda no cache.
func fetchAndCacheChecksums(version, locale string) (map[string]interface{}, error) {
	log.Printf("[WP Verifier] Cache para a versão %s não encontrado. Buscando na API do WordPress.org...", version)
	url := fmt.Sprintf("https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s", version, locale)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data struct {
		Checksums map[string]interface{} `json:"checksums"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	// Guarda os novos checksums no cache com a data de atualização.
	cache.Store(version+"_"+locale, WpChecksums{
		Checksums:  data.Checksums,
		LastUpdate: time.Now(),
	})

	log.Printf("[WP Verifier] Checksums para a versão %s carregados e guardados em cache.", version)
	return data.Checksums, nil
}

// getChecksumsFromCache tenta recuperar os checksums do cache.
func getChecksumsFromCache(version, locale string) (map[string]interface{}, bool) {
	cached, found := cache.Load(version + "_" + locale)
	if !found {
		return nil, false
	}

	wpChecksums := cached.(WpChecksums)
	// Se o cache tiver mais de 12 horas, consideramos ele expirado.
	if time.Since(wpChecksums.LastUpdate) > cacheDuration {
		return nil, false
	}

	return wpChecksums.Checksums, true
}

// removeWpPathPrefix limpa o caminho do arquivo para bater com o da API.
func removeWpPathPrefix(filePath string) string {
	// A API não inclui "wp-admin/", "wp-content/", "wp-includes/" no início de alguns caminhos.
	// Esta função é uma simplificação e pode precisar de ajustes finos.
	path := strings.Replace(filePath, "wp-admin/", "", 1)
	path = strings.Replace(path, "wp-content/", "", 1)
	path = strings.Replace(path, "wp-includes/", "", 1)
	return path
}
