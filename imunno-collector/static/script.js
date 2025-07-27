// Arquivo: imunno-collector/static/script.js (Corrigido para Firebase Studio)

document.addEventListener('DOMContentLoaded', () => {
    const fileEventsBody = document.getElementById('file-events-body');
    const processEventsBody = document.getElementById('process-events-body');
    const statusText = document.getElementById('status-text');
    const statusLight = document.getElementById('status-light');
    const eventsTodayEl = document.getElementById('events-today');
    const threatsNeutralizedEl = document.getElementById('threats-neutralized');
    const lastThreatEl = document.getElementById('last-threat');

    let totalEvents = 0;
    let totalThreats = 0;

    const getThreatLevelClass = (score) => {
        if (score >= 70) return 'threat-high';
        if (score >= 40) return 'threat-medium';
        if (score > 0) return 'threat-low';
        return '';
    };

    const addEventToTable = (event, tableBody, createRowHTML) => {
        totalEvents++;
        eventsTodayEl.textContent = totalEvents;
        const score = event.threat_score || 0;
        if (score > 0) {
            totalThreats++;
            threatsNeutralizedEl.textContent = totalThreats;
            lastThreatEl.textContent = event.file_path || event.command;
        }
        const row = document.createElement('tr');
        row.className = getThreatLevelClass(score);
        row.innerHTML = createRowHTML(event);
        tableBody.prepend(row);
    };

    const connectWebSocket = () => {
        // --- CORREÇÃO APLICADA AQUI ---
        // Verifica se a página foi carregada com HTTPS.
        const isSecure = window.location.protocol === 'https:';
        // Usa 'wss://' para conexões seguras, ou 'ws://' para conexões locais.
        const socketProtocol = isSecure ? 'wss://' : 'ws://';
        const socketURL = `${socketProtocol}${window.location.host}/ws`;
        // --- FIM DA CORREÇÃO ---

        console.log(`Tentando conectar ao WebSocket em: ${socketURL}`);
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

                if (event.file_path) {
                    addEventToTable(event, fileEventsBody, (e) => `
                        <td>${timestamp}</td>
                        <td>${e.hostname || 'N/A'}</td>
                        <td>${e.file_path || 'N/A'}</td>
                        <td>${e.threat_score || 0}</td>
                        <td><span class="details-json">${JSON.stringify(e.analysis_findings || {})}</span></td>
                    `);
                } else if (event.process_id) {
                    addEventToTable(event, processEventsBody, (e) => `
                        <td>${timestamp}</td>
                        <td>${e.hostname || 'N/A'}</td>
                        <td>${e.process_id || 'N/A'}</td>
                        <td>${e.command || 'N/A'}</td>
                        <td>${e.username || 'N/A'}</td>
                        <td>${e.threat_score || 0}</td>
                    `);
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

    connectWebSocket();
});