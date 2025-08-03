// Arquivo: imunno-collector/analyzer/heuristic.go

package analyzer

import (
	"encoding/json"
	"regexp"
)

// RegraHeuristica define uma regra com padrão, descrição e pontuação.
type RegraHeuristica struct {
	Descricao string
	Padrao    *regexp.Regexp
	Pontuacao int
}

// >>>>>>>>>>>>>>>> REGRAS DE ARQUIVO <<<<<<<<<<<<<<<<
var regrasDeArquivo = []RegraHeuristica{
	{
		Descricao: "Função perigosa 'eval' detectada",
		Padrao:    regexp.MustCompile(`eval\s*\(`),
		Pontuacao: 50,
	},
	// --- NOVA REGRA CORRIGIDA AQUI ---
	{
		Descricao: "Execução de função a partir de variável de input (Variable Function)",
		// Este regex mais simples e correto procura pelo padrão de uma variável
		// sendo usada como função, que é altamente suspeito.
		Padrao:    regexp.MustCompile(`\$\w+\s*\(`),
		Pontuacao: 45,
	},
	// --- FIM DA CORREÇÃO ---
	{
		Descricao: "Funções de execução de comando detectadas",
		Padrao:    regexp.MustCompile(`(shell_exec|passthru|system|exec|popen|proc_open)\s*\(`),
		Pontuacao: 40,
	},
	{
		Descricao: "Uso de 'base64_decode' detectado",
		Padrao:    regexp.MustCompile(`base64_decode\s*\(`),
		Pontuacao: 20,
	},
	{
		Descricao: "Uso de 'gzuncompress' ou 'str_rot13' detectado",
		Padrao:    regexp.MustCompile(`(gzuncompress|str_rot13)\s*\(`),
		Pontuacao: 15,
	},
	{
		Descricao: "Uso de variáveis superglobais ($_POST, $_GET etc.)",
		Padrao:    regexp.MustCompile(`\$_(POST|GET|REQUEST|COOKIE)\s*\[`),
		Pontuacao: 10,
	},
	{
		Descricao: "Inclusão de arquivos com 'include' ou 'require'",
		Padrao:    regexp.MustCompile(`(include|require)(_once)?\s*\(`),
		Pontuacao: 5,
	},
}

// >>>>>>>>>>>>>>>> REGRAS DE PROCESSO <<<<<<<<<<<<<<<<
var regrasDeProcesso = []RegraHeuristica{
	// Suas regras de processo permanecem intactas
	{
		Descricao: "Download de arquivos (curl/wget)",
		Padrao:    regexp.MustCompile(`(curl|wget)\s`),
		Pontuacao: 30,
	},
	{
		Descricao: "Conexão de rede reversa (netcat/nc)",
		Padrao:    regexp.MustCompile(`\s(nc|netcat)\s`),
		Pontuacao: 50,
	},
	{
		Descricao: "Coleta de informações (whoami/id/uname)",
		Padrao:    regexp.MustCompile(`(whoami|id|uname)`),
		Pontuacao: 10,
	},
	{
		Descricao: "Alteração de permissões (chmod)",
		Padrao:    regexp.MustCompile(`chmod\s+[67]{3}`),
		Pontuacao: 25,
	},
	{
		Descricao: "Execução de interpretadores (sh/bash/python/perl)",
		Padrao:    regexp.MustCompile(`\s(sh|bash|python|perl)\s`),
		Pontuacao: 20,
	},
}

// AnalyzeContent é a função esperada pelo main.go — ela analisa e retorna o score e os achados em JSON.
func AnalyzeContent(content []byte) (int, []byte) {
	scoreTotal := 0
	var findings []string

	conteudoStr := string(content)

	for _, regra := range regrasDeArquivo {
		if regra.Padrao.MatchString(conteudoStr) {
			scoreTotal += regra.Pontuacao
			findings = append(findings, regra.Descricao)
		}
	}

	analysisResult := struct {
		RegrasAcionadas []string `json:"regras_acionadas"`
	}{
		RegrasAcionadas: findings,
	}

	jsonFindings, _ := json.Marshal(analysisResult)
	return scoreTotal, jsonFindings
}

// AnalisarProcesso permanece como está no seu código original
func AnalisarProcesso(comando string) (int, []string) {
	scoreTotal := 0
	var findings []string
	for _, regra := range regrasDeProcesso {
		if regra.Padrao.MatchString(comando) {
			scoreTotal += regra.Pontuacao
			findings = append(findings, regra.Descricao)
		}
	}
	return scoreTotal, findings
}
