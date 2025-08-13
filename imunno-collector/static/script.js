// Arquivo: imunno-collector/static/script.js (Versão FUI "Cérbero 2.0")

document.addEventListener('DOMContentLoaded', () => {
    // Referências aos elementos
    const loadingScreen = document.getElementById('loading-screen');
    const bootText = document.getElementById('boot-text');
    const dashboardContent = document.getElementById('dashboard-content');
    const statusText = document.getElementById('status-text');
    const statusLight = document.getElementById('status-light');
    const eventsTotalEl = document.getElementById('events-total');
    const threatsNeutralizedEl = document.getElementById('threats-neutralized');
    const logTableBody = document.getElementById('log-table-body');
    const threatsTableBody = document.getElementById('threats-table-body');
    const threatsTableHeader = document.getElementById('threats-table-header');

    // Estado da sessão
    let totalEvents = 0;
    let totalThreats = 0;

    // --- SEQUÊNCIA DE BOOT ---
    const bootSequence = [
        { text: "INICIALIZANDO NÚCLEO...", delay: 800 },
        { text: "CARREGANDO ANALISADOR...", delay: 1200 },
        { text: "CONECTANDO À IA...", delay: 800 },
        { text: "ESTABELECENDO WEBSOCKET...", delay: 1500 },
        { text: "SISTEMA ONLINE", delay: 500 }
    ];

    async function startBootSequence() {
        for (const step of bootSequence) {
            bootText.textContent = step.text;
            await new Promise(resolve => setTimeout(resolve, step.delay));
        }
        loadingScreen.style.opacity = 0;
        setTimeout(() => {
            loadingScreen.style.display = 'none';
            dashboardContent.style.display = 'block';
            connectWebSocket();
        }, 500);
    }

    startBootSequence();

    // --- LÓGICA DO DASHBOARD ---
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

    const handleEvent = (event) => {
        totalEvents++;
        eventsTotalEl.textContent = totalEvents;
        
        const score = event.threat_score || 0;
        const timestamp = new Date(event.timestamp).toLocaleString('pt-BR');
        
        const logRow = document.createElement('tr');
        logRow.className = getThreatLevelClass(score);
        const eventType = event.file_path ? 'ARQUIVO' : 'PROCESSO';
        const detail = event.file_path || event.command;
        logRow.innerHTML = `<td>${timestamp}</td><td>${eventType}</td><td>${detail}</td><td>${score}</td>`;
        logTableBody.prepend(logRow);

        if (score >= 70) {
            totalThreats++;
            threatsNeutralizedEl.textContent = totalThreats;
            threatsTableHeader.style.display = 'table-header-group';

            const threatRow = document.createElement('tr');
            threatRow.className = 'threat-high';
            let actions = 'N/A';
            if (event.file_path) {
                threatRow.id = `threat-${event.file_hash_sha256}`;
                actions = `<button class="action-button" onclick="authorizeHash('${event.file_hash_sha256}', '${event.file_path}')">Autorizar</button>`;
            } else {
                 threatRow.id = `threat-proc-${event.id}`;
            }

            threatRow.innerHTML = `
                <td>${timestamp}</td>
                <td>${eventType}</td>
                <td>${detail}</td>
                <td>${score}</td>
                <td>${actions}</td>
            `;
            threatsTableBody.prepend(threatRow);
        }
    };

    const connectWebSocket = () => {
        const isSecure = window.location.protocol === 'https:';
        const socketProtocol = isSecure ? 'wss://' : 'ws://';
        const socketURL = `${socketProtocol}${window.location.host}/ws`;
        const socket = new WebSocket(socketURL);

        socket.onopen = () => {
            console.log('Conexão WebSocket estabelecida.');
            statusText.textContent = 'OPERACIONAL';
            statusLight.className = 'status-light-green';
        };

        socket.onmessage = (message) => {
            try {
                const event = JSON.parse(message.data);
                handleEvent(event);
            } catch (error) {
                console.error('Erro ao processar mensagem:', error);
            }
        };

        socket.onclose = () => {
            console.log('Conexão perdida. Tentando reconectar...');
            statusText.textContent = 'DESCONECTADO';
            statusLight.className = 'status-light-red';
            setTimeout(connectWebSocket, 5000);
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
});