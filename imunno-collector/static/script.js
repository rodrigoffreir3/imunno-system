// Arquivo: dashboard-frontend/script.js
const API_URL = '/api/v1/events';
const eventsLogBody = document.getElementById('events-log');
const statusLight = document.getElementById('status-light');

async function fetchEvents() {
    try {
        const response = await fetch(API_URL);
        if (!response.ok) {
            // Se a resposta não for OK (ex: 404, 500), joga um erro.
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const events = await response.json();
        updateStatusLight(true);
        renderEvents(events);
    } catch (error) {
        console.error('Erro ao buscar eventos:', error);
        updateStatusLight(false);
    }
}

function renderEvents(events) {
    eventsLogBody.innerHTML = '';
    if (!events) {
        return;
    }
    events.forEach(event => {
        const row = document.createElement('tr');
        
        let threatClass = 'threat-low';
        if (event.threat_score >= 50) {
            threatClass = 'threat-high';
        } else if (event.threat_score >= 40) {
            threatClass = 'threat-medium';
        }
        row.classList.add(threatClass);

        const timestamp = new Date(event.timestamp).toLocaleString('pt-BR');
        
        // Sanitiza os detalhes para evitar problemas de formatação
        const details = JSON.stringify(event.details) || "N/A";
        
        row.innerHTML = `
            <td>${timestamp}</td>
            <td>${event.source ? event.source.toUpperCase() : 'N/A'}</td>
            <td>${event.agent_id || 'N/A'}</td>
            <td><pre>${details}</pre></td>
            <td>${event.threat_score}</td>
        `;
        eventsLogBody.appendChild(row);
    });
}

function updateStatusLight(isOnline) {
    if (isOnline) {
        statusLight.style.backgroundColor = '#4dff4d';
        statusLight.style.boxShadow = '0 0 10px #4dff4d';
    } else {
        statusLight.style.backgroundColor = '#ff4d4d';
        statusLight.style.boxShadow = '0 0 10px #ff4d4d';
    }
}

// Inicia o processo
fetchEvents(); // Chama imediatamente
setInterval(fetchEvents, 5000); // E depois a cada 5 segundos