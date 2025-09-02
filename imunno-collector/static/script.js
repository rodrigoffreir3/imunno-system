document.addEventListener('DOMContentLoaded', () => {
    // Mapeamento de elementos da UI
    const elements = {
        fileEventsBody: document.getElementById('file-events-body'),
        processEventsBody: document.getElementById('process-events-body'),
        statusText: document.getElementById('status-text'),
        statusLight: document.getElementById('status-light'),
        eventsTodayEl: document.getElementById('events-today'),
        threatsNeutralizedEl: document.getElementById('threats-neutralized'),
        lastThreatEl: document.getElementById('last-threat'),
        threatsTableBody: document.getElementById('threats-table-body'),
    };

    let totalEvents = 0;
    let totalThreats = 0;

    const getThreatLevelClass = (score) => {
        if (score >= 70) return 'threat-high';
        if (score >= 40) return 'threat-medium';
        if (score > 0) return 'threat-low';
        return 'threat-none';
    };

    const updateMetrics = (score) => {
        totalEvents++;
        elements.eventsTodayEl.textContent = totalEvents;
        if (score > 0) {
            totalThreats++;
            elements.threatsNeutralizedEl.textContent = totalThreats;
        }
    };

    const addCriticalThreatRow = (event) => {
        const score = event.threat_score || 0;
        if (score < 70) return;

        const timestamp = new Date(event.timestamp).toLocaleString('pt-BR');
        const type = event.file_path ? 'Arquivo' : 'Processo';
        const detail = event.file_path || event.command;
        elements.lastThreatEl.textContent = detail.split('/').pop();

        const actions = event.file_path && event.file_hash_sha256 
            ? `<button class="action-button" onclick="authorizeHash('${event.file_hash_sha256}', '${event.file_path}')">AUTORIZAR</button>`
            : 'N/A';

        const threatRow = document.createElement('tr');
        threatRow.className = getThreatLevelClass(score);
        threatRow.innerHTML = `<td>${timestamp}</td><td>${type}</td><td class="truncate">${detail}</td><td>${score}</td><td>${actions}</td>`;
        elements.threatsTableBody.prepend(threatRow);
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
            } else {
                alert('Falha ao adicionar à whitelist.');
            }
        } catch (error) {
            console.error('Erro ao autorizar hash:', error);
        }
    };

    const handleEvent = (event) => {
        updateMetrics(event.threat_score || 0);
        addCriticalThreatRow(event);

        const row = document.createElement('tr');
        row.className = getThreatLevelClass(event.threat_score || 0);
        const timestamp = new Date(event.timestamp).toLocaleString('pt-BR');

        if (event.file_path) { // É um evento de arquivo
            row.innerHTML = `<td>${timestamp}</td><td>${event.hostname || 'N/A'}</td><td class="truncate">${event.file_path}</td><td>${event.threat_score || 0}</td><td><span class="details-json">${JSON.stringify(event.analysis_findings || {})}</span></td>`;
            elements.fileEventsBody.prepend(row);
        } else if (event.process_id) { // É um evento de processo
            const origin = event.origin_hash ? `<span class="causality-link">${event.origin_hash.substring(0, 12)}...</span>` : 'N/A';
            row.innerHTML = `<td>${timestamp}</td><td>${event.hostname || 'N/A'}</td><td>${event.process_id}</td><td class="truncate">${event.command}</td><td>${event.username || 'N/A'}</td><td>${event.threat_score || 0}</td><td>${origin}</td>`;
            elements.processEventsBody.prepend(row);
        }
    };

    const connectWebSocket = () => {
        const socket = new WebSocket(`${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws`);
        
        socket.onopen = () => {
            elements.statusText.textContent = 'SISTEMA OPERACIONAL';
            elements.statusLight.className = 'status-light status-ok';
        };

        socket.onmessage = (message) => {
            try {
                handleEvent(JSON.parse(message.data));
            } catch (error) {
                console.error('Erro ao processar mensagem do WebSocket:', error);
            }
        };

        socket.onclose = () => {
            elements.statusText.textContent = 'DESCONECTADO';
            elements.statusLight.className = 'status-light status-error';
            setTimeout(connectWebSocket, 5000);
        };

        socket.onerror = (error) => {
            console.error('Erro no WebSocket:', error);
            socket.close();
        };
    };

    document.querySelectorAll('.accordion-header').forEach(header => {
        header.addEventListener('click', () => {
            header.classList.toggle('active');
            const content = header.nextElementSibling;
            content.style.maxHeight = content.style.maxHeight ? null : content.scrollHeight + "px";
        });
    });

    connectWebSocket();
});