// Arquivo: imunno-collector/analyzer/heuristic.go

package analyzer

import (
	"regexp"
	"strings"
)

// AnalysisResult representa o resultado de uma análise heurística.
type AnalysisResult struct {
	ThreatScore int
	Findings    []string
}

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

// AnalisarConteudo analisa um conteúdo de arquivo como string.
func AnalisarConteudo(conteudo string) AnalysisResult {
	var resultado AnalysisResult
	for _, regra := range regrasDeArquivo {
		if regra.Padrao.MatchString(conteudo) {
			resultado.ThreatScore += regra.Pontuacao
			resultado.Findings = append(resultado.Findings, regra.Descricao)
		}
	}
	return resultado
}

// AnalisarProcesso analisa um comando de processo.
func AnalisarProcesso(comando string) AnalysisResult {
	var resultado AnalysisResult
	for _, regra := range regrasDeProcesso {
		if regra.Padrao.MatchString(comando) {
			resultado.ThreatScore += regra.Pontuacao
			resultado.Findings = append(resultado.Findings, regra.Descricao)
		}
	}
	return resultado
}

// AnalyzeContent é a função esperada pelo main.go — ela converte []byte em análise.
func AnalyzeContent(content []byte) (int, []byte) {
	resultado := AnalisarConteudo(string(content))
	findingsJSON := []byte(`["` + strings.Join(resultado.Findings, `","`) + `"]`)
	return resultado.ThreatScore, findingsJSON
}
