# Usa a imagem oficial do WordPress como base
FROM wordpress:latest

# ETAPA 1: Instala as dependências de desenvolvimento do PostgreSQL que estão faltando.
# O apt-get update atualiza a lista de pacotes.
# O apt-get install -y libpq-dev instala as "ferramentas de construção" necessárias.
RUN apt-get update && apt-get install -y \
    libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ETAPA 2: Agora que as ferramentas estão instaladas, instala as extensões PHP.
RUN docker-php-ext-install pdo pdo_pgsql pgsql
