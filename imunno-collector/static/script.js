document.addEventListener('DOMContentLoaded', () => {
    // --- MAPEAMENTO DOS ELEMENTOS DA DOM ---
    const elements = {
        statusLight: document.getElementById('status-light'),
        statusText: document.getElementById('status-text'),
        totalEvents: document.getElementById('total-events'),
        threatsNeutralized: document.getElementById('threats-neutralized'),
        threatsTable: document.getElementById('threats-table-content'),
        eventsTable: document.getElementById('events-table-content'),
    };

    let eventCounter = 0;
    let threatCounter = 0;

    // --- FUNÇÕES DE ATUALIZAÇÃO DA UI ---

    const getThreatLevelClass = (score) => {
        if (score >= 70) return 'threat-high';
        if (score >= 40) return 'threat-medium';
        return 'threat-none';
    };

    const getOrCreateTable = (parent) => {
        let table = parent.querySelector('table');
        if (!table) {
            const newTable = document.createElement('table');
            parent.appendChild(newTable);
            return newTable;
        }
        return table;
    };

    const handleEvent = (event) => {
        eventCounter++;
        elements.totalEvents.textContent = eventCounter;

        const score = event.threat_score || 0;
        const timestamp = new Date(event.timestamp).toLocaleTimeString('pt-BR');
        const type = event.file_path ? 'FILE' : 'PROC';
        const detail = event.file_path || event.command;

        // Adiciona ao log geral de eventos
        const eventsTable = getOrCreateTable(elements.eventsTable);
        const eventRow = eventsTable.insertRow(0);
        eventRow.className = getThreatLevelClass(score);
        eventRow.innerHTML = `<td>${timestamp}</td><td>${type}</td><td>${detail}</td><td>${score}</td>`;
        if (eventsTable.rows.length > 200) eventsTable.deleteRow(200);

        // Se for ameaça, atualiza métricas e adiciona ao card de ameaças
        if (score >= 70) { // Ameaça Crítica
            threatCounter++;
            elements.threatsNeutralized.textContent = threatCounter;
            
            const threatsTable = getOrCreateTable(elements.threatsTable);
            const threatRow = threatsTable.insertRow(0);
            threatRow.className = getThreatLevelClass(score);
            threatRow.innerHTML = `<td>${timestamp}</td><td>${detail}</td><td>${score}</td>`;
            if (threatsTable.rows.length > 100) threatsTable.deleteRow(100);
        }
    };

    // --- CONEXÃO WEBSOCKET ---
    const connectWebSocket = () => {
        const socket = new WebSocket(`${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws`);

        socket.onopen = () => {
            elements.statusLight.className = 'status-light status-ok';
            elements.statusText.textContent = 'ONLINE';
        };

        socket.onmessage = (message) => {
            try {
                handleEvent(JSON.parse(message.data));
            } catch (error) {
                console.error('Erro ao processar mensagem:', error);
            }
        };

        socket.onclose = () => {
            elements.statusLight.className = 'status-light status-error';
            elements.statusText.textContent = 'OFFLINE';
            setTimeout(connectWebSocket, 5000);
        };

        socket.onerror = (error) => {
            console.error('Erro no WebSocket:', error);
            socket.close();
        };
    };

    // --- INICIALIZAÇÃO ---
    connectWebSocket();
});