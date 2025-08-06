# Arquivo: .idx/dev.nix
# Configuração do ambiente de desenvolvimento para o Imunno System no Firebase Studio

{ pkgs, ... }: {

  # Define qual versão do repositório de pacotes Nix usar.
  channel = "stable-23.11";

  # Lista de pacotes e ferramentas de linha de comando que queremos ter instalados.
  packages = [
    pkgs.go
    pkgs.python3
    pkgs.docker-compose
  ];

  # Habilita o serviço do Docker, que é o coração da nossa stack.
  services.docker.enable = true;
}