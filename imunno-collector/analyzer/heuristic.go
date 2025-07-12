package analyzer

import (
	"regexp"
)

type AnalysisResult struct {
	ThreatScore int
	Findings    []string
}

type RegraHeuristica struct {
	Descricao string
	Padrao    *regexp.Regexp
	Pontuacao int
}

var regrasDeArquivo = []RegraHeuristica{
	{
		Descricao: "Funcao perigosa 'eval'",
		Padrao:    regexp.MustCompile(`eval\s*\(`),
		Pontuacao: 50,
	},
	{
		// >>>>>>>>>>>>>>>> REGRA CORRIGIDA <<<<<<<<<<<<<<<<
		Descricao: "Funcao perigosa de execucao de comando",
		Padrao:    regexp.MustCompile(`(shell_exec|passthru|system)\s*\(`),
		Pontuacao: 40,
	},
	{
		Descricao: "Funcao de ofuscacao 'base64_decode'",
		Padrao:    regexp.MustCompile(`base64_decode\s*\(`),
		Pontuacao: 20,
	},
	{
		Descricao: "Funcao de ofuscacao 'gzuncompress' ou 'str_rot13'",
		Padrao:    regexp.MustCompile(`(gzuncompress|str_rot13)\s*\(`),
		Pontuacao: 15,
	},
	{
		Descricao: "Uso de variaveis superglobais 'POST' ou 'GET'",
		Padrao:    regexp.MustCompile(`\$_(POST|GET|REQUEST)\s*\[`),
		Pontuacao: 10,
	},
	{
		Descricao: "Funcao de inclusao de arquivos 'include' ou 'require'",
		Padrao:    regexp.MustCompile(`(include|require)(_once)?\s*\(`),
		Pontuacao: 5,
	},
}

var regrasDeProcesso = []RegraHeuristica{
	{
		Descricao: "Download de arquivos (curl/wget)",
		Padrao:    regexp.MustCompile(`(curl|wget)\s`),
		Pontuacao: 30,
	},
	{
		Descricao: "Conexao de rede reversa (netcat/nc)",
		Padrao:    regexp.MustCompile(`\s(nc|netcat)\s`),
		Pontuacao: 50,
	},
	{
		Descricao: "Coleta de informacoes (whoami/id)",
		Padrao:    regexp.MustCompile(`(whoami|id|uname)`),
		Pontuacao: 10,
	},
	{
		Descricao: "Alteracao de permissoes (chmod)",
		Padrao:    regexp.MustCompile(`chmod\s+[67]{3}`),
		Pontuacao: 25,
	},
	{
		Descricao: "Execucao de interpretador (sh/bash/py)",
		Padrao:    regexp.MustCompile(`\s(sh|bash|python|perl)\s`),
		Pontuacao: 20,
	},
}

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
