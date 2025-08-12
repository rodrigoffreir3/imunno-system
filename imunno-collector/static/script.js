// Arquivo: imunno-collector/static/script.js (Versão Simplificada e Robusta)

document.addEventListener('DOMContentLoaded', () => {
    // Referências aos elementos
    const fileEventsBody = document.getElementById('file-events-body');
    const processEventsBody = document.getElementById('process-events-body');
    const statusText = document.getElementById('status-text');
    const statusLight = document.getElementById('status-light');
    const eventsTodayEl = document.getElementById('events-today');
    const threatsNeutralizedEl = document.getElementById('threats-neutralized');
    const threatsTableBody = document.getElementById('threats-table-body');

    // Estado da sessão
    let totalEvents = 0;
    let totalThreats = 0;

    const getThreatLevelClass = (score) => {
        if (score >= 70) return 'threat-high';
        if (score >= 40) return 'threat-medium';
        if (score > 0) return 'threat-low';
        return '';
    };

    const updateMetricsAndThreats = (event) => {
        totalEvents++;
        eventsTodayEl.textContent = totalEvents;

        const score = event.threat_score || 0;
        if (score >= 70) {
            totalThreats++;
            threatsNeutralizedEl.textContent = totalThreats;

            const threatRow = document.createElement('tr');
            threatRow.className = getThreatLevelClass(score);
            const timestamp = new Date(event.timestamp).toLocaleString('pt-BR');
            const type = event.file_path ? 'Arquivo' : 'Processo';
            const detail = event.file_path || event.command;
            
            let actions = 'N/A';
            if (event.file_path) {
                actions = `<button class="action-button" onclick="authorizeHash('${event.file_hash_sha256}', '${event.file_path}')">Autorizar</button>`;
            }

            threatRow.innerHTML = `
                <td>${timestamp}</td>
                <td>${type}</td>
                <td>${detail}</td>
                <td>${score}</td>
                <td>${actions}</td>
            `;
            threatsTableBody.prepend(threatRow);
        }
    };
    
    window.authorizeHash = async (hash, filePath) => {
        if (!confirm(`Tem certeza que deseja adicionar o arquivo ${filePath} à whitelist?`)) return;
        try {
            const response = await fetch('/v1/whitelist/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ file_hash: hash, file_path: filePath }),
            });
            if (response.ok) {
                alert('Arquivo adicionado à whitelist com sucesso!');
                document.getElementById(`threat-${hash}`).remove();
            } else {
                alert('Falha ao adicionar à whitelist.');
            }
        } catch (error) {
            console.error('Erro ao autorizar hash:', error);
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
                updateMetricsAndThreats(event);
                const score = event.threat_score || 0;
                const timestamp = new Date(event.timestamp).toLocaleString('pt-BR');
                const row = document.createElement('tr');
                row.className = getThreatLevelClass(score);

                if (event.file_path) {
                    row.innerHTML = `
                        <td>${timestamp}</td>
                        <td>${event.hostname || 'N/A'}</td>
                        <td>${event.file_path || 'N/A'}</td>
                        <td>${score}</td>
                        <td><span class="details-json">${JSON.stringify(event.analysis_findings || {})}</span></td>
                    `;
                    fileEventsBody.prepend(row);
                } else if (event.process_id) {
                    let causalityInfo = 'N/A';
                    if (score >= 70) {
                        const parts = (event.command || '').split(' ');
                        if (parts.length > 1) {
                            causalityInfo = `<span class="text-yellow-400 font-bold">${parts[1].split('/').pop()}</span>`;
                        }
                    }
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

    // Funcionalidade do Accordion
    document.querySelectorAll('.accordion-header').forEach(header => {
        header.addEventListener('click', () => {
            const content = header.nextElementSibling;
            content.style.display = content.style.display === 'block' ? 'none' : 'block';
        });
    });

    connectWebSocket();
});