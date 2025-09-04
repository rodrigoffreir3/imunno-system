document.addEventListener('DOMContentLoaded', () => {
    // --- SETUP INICIAL ---
    const elements = {
        eye: document.getElementById('eye-container'),
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

    // --- LÓGICA DAS JANELAS ARRASTÁVEIS ---
    const makeDraggable = (windowEl) => {
        const header = windowEl.querySelector('.window-header');
        let offsetX, offsetY;

        const onMouseMove = (e) => {
            windowEl.style.left = `${e.clientX - offsetX}px`;
            windowEl.style.top = `${e.clientY - offsetY}px`;
        };

        const onMouseUp = () => {
            windowEl.classList.remove('dragging');
            document.removeEventListener('mousemove', onMouseMove);
            document.removeEventListener('mouseup', onMouseUp);
        };

        header.addEventListener('mousedown', (e) => {
            offsetX = e.clientX - windowEl.offsetLeft;
            offsetY = e.clientY - windowEl.offsetTop;
            windowEl.classList.add('dragging');
            document.addEventListener('mousemove', onMouseMove);
            document.addEventListener('mouseup', onMouseUp);
        });
    };

    document.querySelectorAll('.window').forEach(makeDraggable);

    // --- LÓGICA DE MANIPULAÇÃO DE EVENTOS ---
    const getThreatLevelClass = (score) => {
        if (score >= 70) return 'threat-high';
        if (score >= 40) return 'threat-medium';
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

    const triggerEyeAlert = () => {
        elements.eye.classList.add('alert');
        setTimeout(() => {
            elements.eye.classList.remove('alert');
        }, 2000); // Duração do pulso de alerta
    };

    const addCriticalThreatRow = (event) => {
        const score = event.threat_score || 0;
        if (score < 70) return;

        triggerEyeAlert(); // Ativa o alerta visual do olho

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

    const formatJsonForTooltip = (data) => {
        const jsonString = JSON.stringify(data, null, 2);
        return jsonString.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    };

    window.authorizeHash = async (hash, filePath) => {
        if (!confirm(`Tem certeza que deseja adicionar o arquivo ${filePath} à whitelist?`)) return;
        try {
            const response = await fetch('/v1/whitelist/add', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ file_hash: hash, file_path: filePath }),
            });
            alert(response.ok ? 'Arquivo adicionado à whitelist com sucesso!' : 'Falha ao adicionar à whitelist.');
        } catch (error) { console.error('Erro ao autorizar hash:', error); }
    };

    window.highlightFileEvent = (event, hash) => {
        event.preventDefault();
        const fileRow = document.querySelector(`#file-events-body tr[data-hash="${hash}"]`);
        if (!fileRow) return;

        fileRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
        fileRow.classList.add('highlight');
        setTimeout(() => fileRow.classList.remove('highlight'), 1500);
    };

    const handleEvent = (event) => {
        updateMetrics(event.threat_score || 0);
        addCriticalThreatRow(event);

        const row = document.createElement('tr');
        row.className = getThreatLevelClass(event.threat_score || 0);
        const timestamp = new Date(event.timestamp).toLocaleString('pt-BR');

        if (event.file_path) {
            if (event.file_hash_sha256) row.dataset.hash = event.file_hash_sha256;
            const findings = event.analysis_findings || {};
            const detailsHtml = Object.keys(findings).length > 0
                ? `<div class="details-container">
                       <span class="details-trigger">[ Detalhes ]</span>
                       <div class="details-tooltip"><pre>${formatJsonForTooltip(findings)}</pre></div>
                   </div>`
                : 'N/A';
            row.innerHTML = `<td>${timestamp}</td><td>${event.hostname || 'N/A'}</td><td class="truncate" title="${event.file_path}">${event.file_path}</td><td>${event.threat_score || 0}</td><td>${detailsHtml}</td>`;
            elements.fileEventsBody.prepend(row);
        } else if (event.process_id) {
            const origin = event.origin_hash 
                ? `<a href="#" class="causality-link" onclick="highlightFileEvent(event, '${event.origin_hash}')">${event.origin_hash.substring(0, 12)}...</a>`
                : 'N/A';
            row.innerHTML = `<td>${timestamp}</td><td>${event.hostname || 'N/A'}</td><td>${event.process_id}</td><td class="truncate" title="${event.command}">${event.command}</td><td>${event.username || 'N/A'}</td><td>${event.threat_score || 0}</td><td>${origin}</td>`;
            elements.processEventsBody.prepend(row);
        }
    };

    // --- CONEXÃO WEBSOCKET ---
    const connectWebSocket = () => {
        const socket = new WebSocket(`${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws`);
        
        socket.onopen = () => {
            elements.statusText.textContent = 'SISTEMA OPERACIONAL';
            elements.statusLight.className = 'status-light status-ok';
        };

        socket.onmessage = (message) => {
            try { handleEvent(JSON.parse(message.data)); } 
            catch (error) { console.error('Erro ao processar mensagem:', error); }
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

    connectWebSocket();
});
