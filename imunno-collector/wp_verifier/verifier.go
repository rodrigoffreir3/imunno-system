// Arquivo: imunno-collector/wp_verifier/verifier.go (Corrigido para usar MD5)
package wp_verifier

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type WpChecksums struct {
	Checksums  map[string]interface{}
	LastUpdate time.Time
}

var (
	cache         = &sync.Map{}
	cacheDuration = 12 * time.Hour
)

// IsOfficialFile agora recebe o CONTEÚDO do arquivo para calcular o MD5 internamente.
func IsOfficialFile(filePath, fileContent, wpVersion, locale string) bool {
	checksums, found := getChecksumsFromCache(wpVersion, locale)
	if !found {
		var err error
		checksums, err = fetchAndCacheChecksums(wpVersion, locale)
		if err != nil {
			log.Printf("[WP Verifier] ERRO ao buscar checksums: %v", err)
			return false
		}
	}

	cleanPath := removeWpPathPrefix(filePath)
	officialHash, exists := checksums[cleanPath]
	if !exists {
		return false // O arquivo não está na lista oficial.
	}

	// Calcula o hash MD5 do conteúdo que recebemos.
	currentMd5Hash := calculateMd5(fileContent)

	// Compara o nosso MD5 com o MD5 oficial.
	return officialHash == currentMd5Hash
}

// calculateMd5 é uma nova função para gerar o hash MD5.
func calculateMd5(content string) string {
	hash := md5.New()
	io.WriteString(hash, content)
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func fetchAndCacheChecksums(version, locale string) (map[string]interface{}, error) {
	log.Printf("[WP Verifier] Cache para a versão %s não encontrado. Buscando na API...", version)
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

	cache.Store(version+"_"+locale, WpChecksums{
		Checksums:  data.Checksums,
		LastUpdate: time.Now(),
	})
	log.Printf("[WP Verifier] Checksums para a versão %s carregados e em cache.", version)
	return data.Checksums, nil
}

func getChecksumsFromCache(version, locale string) (map[string]interface{}, bool) {
	cached, found := cache.Load(version + "_" + locale)
	if !found {
		return nil, false
	}
	wpChecksums := cached.(WpChecksums)
	if time.Since(wpChecksums.LastUpdate) > cacheDuration {
		return nil, false
	}
	return wpChecksums.Checksums, true
}

func removeWpPathPrefix(filePath string) string {
	// Limpa o caminho para bater com o formato da API.
	// Ex: /app/wordpress/wp-admin/about.php -> wp-admin/about.php
	if index := strings.Index(filePath, "wp-admin"); index != -1 {
		return filePath[index:]
	}
	if index := strings.Index(filePath, "wp-content"); index != -1 {
		return filePath[index:]
	}
	if index := strings.Index(filePath, "wp-includes"); index != -1 {
		return filePath[index:]
	}
	// Para arquivos na raiz
	return filepath.Base(filePath)
}
