# Arquivo: imunno-web-server/Dockerfile (Versão Final e Corrigida)

# Usamos a mesma imagem leve que já tínhamos escolhido
FROM php:apache

# --- A NOVA LINHA ESTÁ AQUI ---
# Este comando habilita o módulo 'rewrite' do Apache, que é essencial para o WordPress.
RUN a2enmod rewrite

# Este é o comando que já tínhamos, que corrige as permissões de escrita.
RUN chown -R www-data:www-data /var/www/html