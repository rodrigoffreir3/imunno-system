<?php
// Amostra de teste JS avançado para o Imunno System
// Injeta um script que usa a técnica String.fromCharCode para ofuscar o código malicioso.
?>
<script>
// O atacante constrói a palavra 'eval' e o comando malicioso
// usando os códigos dos caracteres para não ser detectado.
var codigoMalicioso = String.fromCharCode(101, 118, 97, 108); // eval
var comando = "document.body.innerHTML = 'Site Invadido!'";

// Executa o código ofuscado
window[codigoMalicioso](comando);
</script>