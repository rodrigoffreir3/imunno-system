# Arquivo: .idx/dev.nix
# Configuração do ambiente de desenvolvimento para o Imunno System no Firebase Studio

{ pkgs, ... }: {

  # Define qual versão do repositório de pacotes Nix usar.
  # "stable-23.11" é uma boa escolha, mas pode ser atualizado no futuro.
  channel = "stable-23.11";

  # Lista de pacotes e ferramentas de linha de comando que queremos ter instalados
  # na nossa "oficina".
  packages = [
    pkgs.go              # Essencial para compilar e rodar scripts Go, como o populate_whitelist.
    pkgs.python3         # Necessário para gerenciar a venv e treinar o modelo de IA.
    pkgs.docker-compose  # A ferramenta principal para orquestrar nossa stack.
  ];

  # Habilita os serviços que queremos que rodem em segundo plano no ambiente.
  services.docker.enable = true; # Esta é a linha mais importante: ela liga o motor do Docker.

}