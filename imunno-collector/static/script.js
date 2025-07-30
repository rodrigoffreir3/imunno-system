// Arquivo: imunno-collector/static/script.js (Com a Lógica de Causalidade Visual)

document.addEventListener('DOMContentLoaded', () => {
    // Referências aos elementos da página
    const fileEventsBody = document.getElementById('file-events-body');
    const processEventsBody = document.getElementById('process-events-body');
    const statusText = document.getElementById('status-text');
    const statusLight = document.getElementById('status-light');
    const eventsTodayEl = document.getElementById('events-today');
    const threatsNeutralizedEl = document.getElementById('threats-neutralized');
    const lastThreatEl = document.getElementById('last-threat');

    // Variáveis para contar as métricas
    let totalEvents = 0;
    let totalThreats = 0;

    // Função para determinar a classe de cor com base na pontuação de ameaça
    const getThreatLevelClass = (score) => {
        if (score >= 70) return 'threat-high';
        if (score >= 40) return 'threat-medium';
        if (score > 0) return 'threat-low';
        return '';
    };

    // Função genérica para adicionar um evento a uma tabela e atualizar métricas
    const addEventToTable = (event, tableBody, createRowHTML) => {
        totalEvents++;
        eventsTodayEl.textContent = totalEvents;

        const score = event.threat_score || 0;
        if (score > 0) {
            totalThreats++;
            threatsNeutralizedEl.textContent = totalThreats;
            // Atualiza a última ameaça com o caminho do arquivo ou o comando
            const threatIdentifier = event.file_path || event.command;
            lastThreatEl.textContent = threatIdentifier.split('/').pop(); // Mostra apenas o nome do arquivo/comando
        }

        const row = document.createElement('tr');
        row.className = getThreatLevelClass(score);
        row.innerHTML = createRowHTML(event);
        tableBody.prepend(row);
    };

    // --- CONEXÃO WEBSOCKET EM TEMPO REAL ---
    const connectWebSocket = () => {
        const isSecure = window.location.protocol === 'https:';
        const socketProtocol = isSecure ? 'wss://' : 'ws://';
        const socketURL = `${socketProtocol}${window.location.host}/ws`;

        const socket = new WebSocket(socketURL);

        socket.onopen = () => {
            console.log('Conexão WebSocket estabelecida.');
            statusText.textContent = 'SISTEMA OPERACIONAL';
            statusLight.className = 'w-4 h-4 rounded-full bg-green-500 shadow-[0_0_10px_#39ff14]';
        };

        socket.onmessage = (message) => {
            try {
                const event = JSON.parse(message.data);
                const timestamp = new Date(event.timestamp).toLocaleString('pt-BR');

                if (event.file_path) { // É um evento de arquivo
                    addEventToTable(event, fileEventsBody, (e) => `
                        <td>${timestamp}</td>
                        <td>${e.hostname || 'N/A'}</td>
                        <td>${e.file_path || 'N/A'}</td>
                        <td>${e.threat_score || 0}</td>
                        <td><span class="details-json">${JSON.stringify(e.analysis_findings || {})}</span></td>
                    `);
                } else if (event.process_id) { // É um evento de processo
                    addEventToTable(event, processEventsBody, (e) => {
                        let causalityInfo = 'N/A';
                        // --- LÓGICA DE CAUSALIDADE VISUAL ADICIONADA AQUI ---
                        // Se o score for alto, presumimos que a causalidade foi detectada no backend.
                        if ((e.threat_score || 0) >= 70) {
                            const parts = (e.command || '').split(' ');
                            if (parts.length > 1) {
                                // Pega o nome do arquivo do comando e o exibe.
                                causalityInfo = `<span class="text-yellow-400 font-bold">${parts[1].split('/').pop()}</span>`;
                            }
                        }
                        return `
                            <td>${timestamp}</td>
                            <td>${e.hostname || 'N/A'}</td>
                            <td>${e.process_id || 'N/A'}</td>
                            <td>${e.command || 'N/A'}</td>
                            <td>${e.username || 'N/A'}</td>
                            <td>${e.threat_score || 0}</td>
                            <td>${causalityInfo}</td>
                        `;
                    });
                }
            } catch (error) {
                console.error('Erro ao processar mensagem do WebSocket:', error);
            }
        };

        socket.onclose = () => {
            console.log('Conexão WebSocket perdida. Tentando reconectar em 5 segundos...');
            statusText.textContent = 'DESCONECTADO';
            statusLight.className = 'w-4 h-4 rounded-full bg-red-500 shadow-[0_0_10px_#ff3b3b]';
            setTimeout(connectWebSocket, 5000);
        };

        socket.onerror = (error) => {
            console.error('Erro no WebSocket:', error);
            socket.close();
        };
    };

    // Inicia a conexão
    connectWebSocket();
});