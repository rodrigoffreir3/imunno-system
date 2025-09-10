<?php
// Amostra de teste "Matriosca" - Múltiplas Camadas de Evasão
// 1. O atacante quebra o nome da função 'base64_decode'
$parte_b = 'base64';
$parte_d = '_decode';
$funcao_decodificadora = $parte_b . $parte_d;

// 2. A carga maliciosa ('system("ls -la");') é codificada em base64
$carga_oculta = 'c3lzdGVtKCJscyAtbGEiKTs=';

// 3. A função montada dinamicamente é usada para decodificar a carga
$codigo_final = $funcao_decodificadora($carga_oculta);

// 4. O resultado é executado
eval($codigo_final);
?>
