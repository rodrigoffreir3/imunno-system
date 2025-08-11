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
    
    // Função para o botão "Autorizar"
    window.authorizeHash = async (hash, filePath) => {
        if (!confirm(`Tem certeza que deseja adicionar o arquivo ${filePath} à whitelist? Esta ação é irreversível.`)) {
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
                // Remove a linha da tabela de ameaças
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

        if (eventRows.has(eventId)) { // Atualiza um evento existente (ex: causalidade)
            const rowElements = eventRows.get(eventId);
            const oldThreatScore = parseInt(rowElements.logRow.cells[5].textContent);
            if (score > oldThreatScore) isNewThreat = true;

            // Atualiza a linha no log completo
            rowElements.logRow.className = getThreatLevelClass(score);
            rowElements.logRow.cells[5].textContent = score;

            // Se for uma nova ameaça, adiciona ou atualiza na tabela de ameaças
            if (isNewThreat) {
                if (rowElements.threatRow) { // Atualiza a linha na tabela de ameaças
                    rowElements.threatRow.className = getThreatLevelClass(score);
                    rowElements.threatRow.cells[3].textContent = score;
                } else { // Adiciona na tabela de ameaças
                    addThreatRow(event, timestamp);
                }
            }
        } else { // Novo evento
            isNewThreat = score > 0;
            const logRow = createLogRow(event, timestamp);
            eventRows.set(eventId, { logRow });

            if (event.file_path) {
                fileEventsBody.prepend(logRow);
            } else {
                processEventsBody.prepend(logRow);
            }
            
            if (score >= 70) {
                addThreatRow(event, timestamp);
            }
        }
        
        updateMetrics(isNewThreat);
    };

    const addThreatRow = (event, timestamp) => {
        const score = event.threat_score || 0;
        const threatRow = document.createElement('tr');
        threatRow.className = getThreatLevelClass(score);
        threatRow.id = `threat-${event.file_hash_sha256 || event.process_id}`;
        
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

        if(eventRows.has(event.id)) {
            eventRows.get(event.id).threatRow = threatRow;
        } else {
             eventRows.set(event.id, { threatRow });
        }
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
        // ... (seu código de conexão WebSocket, sem alterações)
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