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

    // Mapa para rastrear as linhas da tabela de processos pelo ID do evento do banco de dados
    const processEventRows = new Map();

    // Variáveis para contar as métricas
    let totalEvents = 0;
    let totalThreats = 0;

    const getThreatLevelClass = (score) => {
        if (score >= 70) return 'threat-high';
        if (score >= 40) return 'threat-medium';
        if (score > 0) return 'threat-low';
        return '';
    };
    
    const updateMetrics = (event, isNewThreat) => {
        totalEvents++;
        eventsTodayEl.textContent = totalEvents;

        const score = event.threat_score || 0;
        if (isNewThreat && score > 0) {
            totalThreats++;
            threatsNeutralizedEl.textContent = totalThreats;
            const threatIdentifier = event.file_path || event.command;
            lastThreatEl.textContent = threatIdentifier.split('/').pop();
        }
    };

    const handleFileEvent = (event) => {
        updateMetrics(event, true);
        const row = document.createElement('tr');
        row.className = getThreatLevelClass(event.threat_score || 0);
        const timestamp = new Date(event.timestamp).toLocaleString('pt-BR');
        row.innerHTML = `
            <td>${timestamp}</td>
            <td>${event.hostname || 'N/A'}</td>
            <td>${event.file_path || 'N/A'}</td>
            <td>${event.threat_score || 0}</td>
            <td><span class="details-json">${JSON.stringify(event.analysis_findings || {})}</span></td>
        `;
        fileEventsBody.prepend(row);
    };

    const handleProcessEvent = (event) => {
        const timestamp = new Date(event.timestamp).toLocaleString('pt-BR');
        const score = event.threat_score || 0;
        let causalityInfo = 'N/A';
        
        // Se o score for alto, presumimos que a causalidade foi detectada no backend.
        if (score >= 70) {
            const parts = (event.command || '').split(' ');
            if (parts.length > 1) {
                // Pega o nome do arquivo do comando e o exibe.
                causalityInfo = `<span class="text-yellow-400 font-bold">${parts[1].split('/').pop()}</span>`;
            }
        }

        // Verifica se já existe uma linha para este evento (pelo ID do evento no DB)
        if (processEventRows.has(event.id)) {
            // Se já existe, apenas atualiza a linha
            const row = processEventRows.get(event.id);
            const oldThreatScore = parseInt(row.cells[5].textContent);

            row.className = getThreatLevelClass(score);
            row.cells[5].textContent = score;
            row.cells[6].innerHTML = causalityInfo;

            // Se o score aumentou e antes era 0, consideramos uma nova ameaça
            if (score > oldThreatScore && oldThreatScore === 0) {
                updateMetrics(event, true);
            }
        } else {
            // Se não existe, cria uma nova linha e a adiciona
            updateMetrics(event, score > 0);
            const row = document.createElement('tr');
            row.className = getThreatLevelClass(score);
            row.innerHTML = `
                <td>${timestamp}</td>
                <td>${event.hostname || 'N/A'}</td>
                <td>${event.process_id || 'N/A'}</td>
                <td>${event.command || 'N/A'}</td>
                <td>${event.username || 'N/A'}</td>
                <td>${score}</td>
                <td>${causalityInfo}</td>
            `;
            processEventsBody.prepend(row);
            // Armazena a referência da linha no mapa usando o ID único do banco
            processEventRows.set(event.id, row);
        }
    };

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
                if (event.file_path) {
                    handleFileEvent(event);
                } else if (event.process_id) {
                    handleProcessEvent(event);
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