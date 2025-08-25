package analyzer

import (
	"encoding/json"
	"log"
	"regexp"
	"strings"
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
	{
		Descricao: "Execução de função a partir de variável de input (Variable Function)",
		Padrao:    regexp.MustCompile(`\$\w+\s*\(`),
		Pontuacao: 45,
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

	// Detecta a leitura de arquivos de sistema sensíveis.
	{
		Descricao: "Leitura de arquivos de configuração ou sistema",
		Padrao:    regexp.MustCompile(`file_get_contents\s*\(\s*['"].*(\/etc\/passwd|wp-config\.php)['"]`),
		Pontuacao: 30, // Score médio, pois pode haver falsos positivos em plugins de backup.
	},

	// Detecta o padrão de compressão + codificação, típico de exfiltração de dados.
	{
		Descricao: "Padrão de exfiltração de dados (compressão + codificação)",
		Padrao:    regexp.MustCompile(`(gzcompress|gzdeflate)\s*\(.*base64_encode`), // Procura por gzcompress seguido de base64_encode
		Pontuacao: 40,                                                               // Score alto, essa combinação é muito suspeita.
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

// AnalyzeContent é a função esperada pelo main.go — agora ela recebe o caminho do arquivo para ter contexto.
func AnalyzeContent(content []byte, filePath string) (int, []byte) {
	// 1. INTELIGÊNCIA DE CONTEXTO: Verificamos se é um arquivo conhecido que PODE ter código suspeito.
	if strings.HasSuffix(filePath, "wp-config.php") || strings.HasSuffix(filePath, "wp-activate.php") {
		log.Printf("[CONTEXTO] Arquivo %s identificado como um arquivo de núcleo do WP com funções sensíveis. Ignorando análise heurística.", filePath)

		analysisResult := struct {
			RegrasAcionadas []string `json:"regras_acionadas"`
		}{
			RegrasAcionadas: []string{"Arquivo de configuração/ativação do WordPress"},
		}
		jsonFindings, _ := json.Marshal(analysisResult)
		return 0, jsonFindings // Retornamos score 0, resolvendo o falso positivo.
	}

	// 2. Se não for uma exceção, a análise padrão continua.
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

// AnalisarProcesso permanece como está no seu código original.
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
