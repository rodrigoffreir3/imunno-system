package analyzer

import (
	"imunno-collector/events"
	"strings"
	"sync"
	"time"
)

// causalityCache armazena eventos de arquivo recentes para correlação.
var causalityCache = struct {
	sync.RWMutex
	files map[string]events.FileEvent // Mapeia file_path para o evento de arquivo
}{
	files: make(map[string]events.FileEvent),
}

const cacheTTL = 20 * time.Second // Tempo que um evento de arquivo fica no cache

// StoreFileEvent adiciona um evento de arquivo ao cache.
func StoreFileEvent(event events.FileEvent) {
	causalityCache.Lock()
	defer causalityCache.Unlock()

	causalityCache.files[event.FilePath] = event

	// Limpa a entrada do cache após o TTL
	time.AfterFunc(cacheTTL, func() {
		causalityCache.Lock()
		defer causalityCache.Unlock()
		delete(causalityCache.files, event.FilePath)
	})
}

// FindCausality verifica se um comando de processo corresponde a um evento de arquivo no cache.
func FindCausality(processCmd string) (string, bool) {
	causalityCache.RLock()
	defer causalityCache.RUnlock()

	for filePath, fileEvent := range causalityCache.files {
		// A heurística de correlação: o caminho do arquivo está contido no comando do processo.
		if strings.Contains(processCmd, filePath) {
			return fileEvent.FileHashSHA256, true // Encontrou!
		}
	}

	return "", false // Nenhuma correspondência encontrada
}
