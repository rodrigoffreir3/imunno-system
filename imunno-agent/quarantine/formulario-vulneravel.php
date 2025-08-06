<?php
// Plugin de formulário de contato simples e PROPOSITALMENTE VULNERÁVEL para a demo do Imunno.
if (isset($_POST['mensagem'])) {
    $mensagem = $_POST['mensagem'];
    // FALHA DE SEGURANÇA GRAVÍSSIMA: Executa o conteúdo da mensagem como um comando de sistema!
    $output = shell_exec($mensagem); 
    echo "<h1>Obrigado pelo contato!</h1><pre>{$output}</pre>";
}
?>
<form method="POST">
    <label for="mensagem">Deixe sua mensagem:</label><br>
    <textarea name="mensagem" rows="5" cols="40"></textarea><br>
    <input type="submit" value="Enviar">
</form>