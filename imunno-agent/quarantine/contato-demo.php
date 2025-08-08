<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Formulário de Contato - Demo</title>
    <style>
        body { font-family: sans-serif; background-color: #f0f0f0; padding: 20px; }
        form { max-width: 500px; margin: auto; padding: 20px; background-color: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        textarea { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; }
        input[type="submit"] { background-color: #0073aa; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <form method="POST">
        <h1>Contato (Demo Imunno System)</h1>
        <p>Deixe sua mensagem abaixo:</p>
        <textarea name="mensagem" rows="8" cols="50" placeholder="Digite sua mensagem aqui..."></textarea><br><br>
        <input type="submit" value="Enviar">
    </form>
    <?php
    // Plugin de formulário de contato simples e PROPOSITALMENTE VULNERÁVEL.
    if (isset($_POST['mensagem'])) {
        $mensagem = $_POST['mensagem'];
        // FALHA DE SEGURANÇA GRAVÍSSIMA: Executa o conteúdo da mensagem como um comando de sistema!
        echo "<h3>Resposta do Servidor:</h3><pre>";
        $output = shell_exec($mensagem); 
        echo htmlspecialchars($output);
        echo "</pre>";
    }
    ?>
</body>
</html>