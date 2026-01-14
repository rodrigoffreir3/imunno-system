<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Formulário de Contato - Demo</title>
    <style>
        body { font-family: sans-serif; background-color: #f0f0f0; padding: 20px; }
        form { max-width: 600px; margin: auto; padding: 20px; background-color: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        input, textarea { width: 100%; padding: 8px; margin-bottom: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        input[type="submit"] { background-color: #0073aa; color: white; padding: 10px 15px; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <form method="POST">
        <h1>Injeção de Arquivo (Demo Imunno System)</h1>
        <p>Simula uma falha de upload que permite ao atacante criar um arquivo no servidor.</p>
        
        <label for="caminho">Caminho do Arquivo (ex: wp-content/uploads/ataque.php):</label>
        <input type="text" name="caminho" id="caminho">

        <label for="conteudo">Conteúdo do Arquivo Malicioso:</label>
        <textarea name="conteudo" id="conteudo" rows="8"></textarea><br><br>
        
        <input type="submit" value="Injetar Arquivo">
    </form>
    <?php
    if (!empty($_POST['caminho']) && !empty($_POST['conteudo'])) {
        $caminho = $_POST['caminho'];
        $conteudo = $_POST['conteudo'];
        
        // FALHA DE SEGURANÇA: Salva o conteúdo enviado em um arquivo no servidor.
        // Usa file_put_contents, uma função muito mais comum e raramente desabilitada.
        if (file_put_contents($caminho, $conteudo)) {
            echo "<h3>Arquivo supostamente criado com sucesso em '{$caminho}'!</h3>";
        } else {
            echo "<h3>Falha ao criar o arquivo. Verifique as permissões.</h3>";
        }
    }
    ?>
</body>
</html>