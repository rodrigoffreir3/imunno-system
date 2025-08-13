// Arquivo: imunno-collector/static/script.js (Versão Final "Demo Diamante")

document.addEventListener('DOMContentLoaded', () => {
    // Referências aos elementos
    const statusText = document.getElementById('status-text');
    const statusLight = document.getElementById('status-light');
    const eventsTodayEl = document.getElementById('events-today');
    const threatsNeutralizedEl = document.getElementById('threats-neutralized');
    const threatsTableBody = document.getElementById('threats-table-body');
    const fileEventsBody = document.getElementById('file-events-body');
    const processEventsBody = document.getElementById('process-events-body');

    // Estado da sessão
    const eventRows = new Map();
    let totalEvents = 0;
    let totalThreats = 0;

    const getThreatLevelClass = (score) => {
        if (score >= 70) return 'threat-high';
        if (score >= 40) return 'threat-medium';
        if (score > 0) return 'threat-low';
        return '';
    };

    const updateMetrics = (isNewThreat) => {
        totalEvents++;
        eventsTodayEl.textContent = totalEvents;
        if (isNewThreat) {
            totalThreats++;
            threatsNeutralizedEl.textContent = totalThreats;
        }
    };
    
    window.authorizeHash = async (hash, filePath) => {
        if (!confirm(`Tem certeza que deseja adicionar o arquivo ${filePath} à whitelist? Esta ação é irreversível nesta sessão.`)) {
            return;
        }
        try {
            const response = await fetch('/v1/whitelist/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ file_hash: hash, file_path: filePath }),
            });
            if (response.ok) {
                alert('Arquivo adicionado à whitelist com sucesso! Ele não será mais detectado como ameaça.');
                document.getElementById(`threat-${hash}`).remove();
            } else {
                alert('Falha ao adicionar à whitelist.');
            }
        } catch (error) {
            console.error('Erro ao autorizar hash:', error);
            alert('Erro de comunicação ao autorizar hash.');
        }
    };

    const handleEvent = (event) => {
        const score = event.threat_score || 0;
        const eventId = event.id;
        const timestamp = new Date(event.timestamp).toLocaleString('pt-BR');
        
        let isNewThreat = false;

        if (eventRows.has(eventId)) {
            const rowElements = eventRows.get(eventId);
            const oldThreatScore = parseInt(rowElements.logRow.cells[5].textContent);
            if (score > oldThreatScore && oldThreatScore === 0) isNewThreat = true;

            rowElements.logRow.className = getThreatLevelClass(score);
            rowElements.logRow.cells[5].textContent = score;
            
            // Lógica de causalidade visual
            if (event.command && score >= 70) {
                const parts = (event.command || '').split(' ');
                if (parts.length > 1) {
                    const originFile = parts.find(p => p.includes('.php') || p.includes('.js'));
                    if (originFile) {
                        rowElements.logRow.cells[6].innerHTML = `<span class="text-yellow-400 font-bold">${originFile.split('/').pop()}</span>`;
                    }
                }
            }
            if (isNewThreat && rowElements.threatRow) {
                rowElements.threatRow.className = getThreatLevelClass(score);
                rowElements.threatRow.cells[3].textContent = score;
            }
        } else {
            isNewThreat = score >= 70;
            const logRow = createLogRow(event, timestamp);
            eventRows.set(eventId, { logRow });

            if (event.file_path) {
                fileEventsBody.prepend(logRow);
            } else {
                processEventsBody.prepend(logRow);
            }
            
            if (isNewThreat) {
                addThreatRow(event, timestamp, logRow);
            }
        }
        
        updateMetrics(isNewThreat);
    };

    const addThreatRow = (event, timestamp, logRow) => {
        const score = event.threat_score || 0;
        const threatRow = document.createElement('tr');
        threatRow.className = getThreatLevelClass(score);
        threatRow.id = `threat-${event.file_hash_sha256 || event.id}`;
        
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
        
        const eventData = eventRows.get(event.id) || { logRow: null };
        eventData.threatRow = threatRow;
        eventRows.set(event.id, eventData);
    };
    
    const createLogRow = (event, timestamp) => {
        const score = event.threat_score || 0;
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
        } else {
             row.innerHTML = `
                <td>${timestamp}</td>
                <td>${event.hostname || 'N/A'}</td>
                <td>${event.process_id || 'N/A'}</td>
                <td>${event.command || 'N/A'}</td>
                <td>${event.username || 'N/A'}</td>
                <td>${score}</td>
                <td>N/A</td>
            `;
        }
        return row;
    };

    const connectWebSocket = () => {
        const isSecure = window.location.protocol === 'https:';
        const socketProtocol = isSecure ? 'wss://' : 'ws://';
        const socketURL = `${socketProtocol}${window.location.host}/ws`;
        const socket = new WebSocket(socketURL);

        socket.onopen = () => {
            console.log('Conexão WebSocket estabelecida.');
            statusText.textContent = 'SISTEMA OPERACIONAL';
            statusLight.className = 'w-4 h-4 rounded-full bg-green-500 shadow-[0_0_10px_#39ff14] status-connected';
            statusLight.classList.remove('animate-pulse');
        };

        socket.onmessage = (message) => {
            try {
                const event = JSON.parse(message.data);
                handleEvent(event);
            } catch (error) {
                console.error('Erro ao processar mensagem do WebSocket:', error);
            }
        };

        socket.onclose = () => {
            console.log('Conexão WebSocket perdida. Tentando reconectar em 5 segundos...');
            statusText.textContent = 'DESCONECTADO';
            statusLight.className = 'w-4 h-4 rounded-full bg-red-500 shadow-[0_0_10px_#f87171] animate-pulse status-disconnected';
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
            header.classList.toggle('active');
            const content = header.nextElementSibling;
            if (content.style.display === "block") {
                content.style.display = "none";
            } else {
                content.style.display = "block";
            }
        });
    });

    connectWebSocket();
});