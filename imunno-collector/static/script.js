document.addEventListener('DOMContentLoaded', () => {
    const fileEventsBody = document.getElementById('file-events-body');
    const processEventsBody = document.getElementById('process-events-body');
    const statusText = document.getElementById('status-text');
    const statusLight = document.getElementById('status-light');
    const eventsTodayEl = document.getElementById('events-today');
    const threatsNeutralizedEl = document.getElementById('threats-neutralized');
    const lastThreatEl = document.getElementById('last-threat');
    const threatsTableBody = document.getElementById('threats-table-body');
    const processEventRows = new Map();
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

    const addThreatRow = (event) => {
        const timestamp = new Date(event.timestamp).toLocaleString('pt-BR');
        const score = event.threat_score || 0;
        const type = event.file_path ? 'Arquivo' : 'Processo';
        const detail = event.file_path || event.command;
        let actions = 'N/A';
        if (event.file_path) {
            actions = `<button class="action-button" onclick="authorizeHash('${event.file_hash_sha256}', '${event.file_path}')">Autorizar</button>`;
        }
        const threatRow = document.createElement('tr');
        threatRow.className = getThreatLevelClass(score);
        threatRow.id = `threat-${event.file_hash_sha256 || event.id}`;
        threatRow.innerHTML = `<td>${timestamp}</td><td>${type}</td><td>${detail}</td><td>${score}</td><td>${actions}</td>`;
        threatsTableBody.prepend(threatRow);
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
            } else { alert('Falha ao adicionar à whitelist.'); }
        } catch (error) { console.error('Erro ao autorizar hash:', error); }
    };

    const handleFileEvent = (event) => {
        updateMetrics(event, true);
        const score = event.threat_score || 0;
        const row = document.createElement('tr');
        row.className = getThreatLevelClass(score);
        const timestamp = new Date(event.timestamp).toLocaleString('pt-BR');
        row.innerHTML = `<td>${timestamp}</td><td>${event.hostname || 'N/A'}</td><td>${event.file_path || 'N/A'}</td><td>${score}</td><td><span class="details-json">${JSON.stringify(event.analysis_findings || {})}</span></td>`;
        fileEventsBody.prepend(row);
        if (score >= 70) { addThreatRow(event); }
    };

    const handleProcessEvent = (event) => {
        const score = event.threat_score || 0;
        const eventId = event.id;
        if (processEventRows.has(eventId)) {
            const row = processEventRows.get(eventId);
            const oldThreatScore = parseInt(row.cells[5].textContent);
            row.className = getThreatLevelClass(score);
            row.cells[5].textContent = score;
            const commandParts = (event.command || '').split(' [Origem: ');
            if (commandParts.length > 1) {
                const originFile = commandParts[1].replace(']', '');
                row.cells[6].innerHTML = `<span style="color: #facc15; font-weight: bold;">${originFile}</span>`;
            }
            if (score > oldThreatScore && oldThreatScore === 0) {
                updateMetrics(event, true);
                if (score >= 70) { addThreatRow(event); }
            }
        } else {
            updateMetrics(event, score > 0);
            const row = document.createElement('tr');
            row.className = getThreatLevelClass(score);
            const timestamp = new Date(event.timestamp).toLocaleString('pt-BR');
            row.innerHTML = `<td>${timestamp}</td><td>${event.hostname || 'N/A'}</td><td>${event.process_id || 'N/A'}</td><td>${event.command || 'N/A'}</td><td>${event.username || 'N/A'}</td><td>${score}</td><td>N/A</td>`;
            processEventsBody.prepend(row);
            processEventRows.set(eventId, row);
            if (score >= 70) { addThreatRow(event); }
        }
    };

    const connectWebSocket = () => {
        const isSecure = window.location.protocol === 'https:';
        const socketProtocol = isSecure ? 'wss://' : 'ws://';
        const socketURL = `${socketProtocol}${window.location.host}/ws`;
        const socket = new WebSocket(socketURL);
        socket.onopen = () => { statusText.textContent = 'SISTEMA OPERACIONAL'; statusLight.style.backgroundColor = 'green'; };
        socket.onmessage = (message) => {
            try {
                const event = JSON.parse(message.data);
                if (event.file_path) { handleFileEvent(event); } else if (event.process_id) { handleProcessEvent(event); }
            } catch (error) { console.error('Erro ao processar mensagem:', error); }
        };
        socket.onclose = () => { statusText.textContent = 'DESCONECTADO'; statusLight.style.backgroundColor = 'red'; setTimeout(connectWebSocket, 5000); };
        socket.onerror = (error) => { console.error('Erro no WebSocket:', error); socket.close(); };
    };

    document.querySelectorAll('.accordion-header').forEach(header => {
        header.addEventListener('click', () => {
            const content = header.nextElementSibling;
            if (content.style.display === 'block') { content.style.display = 'none'; } else { content.style.display = 'block'; }
        });
    });

    connectWebSocket();
});