const alertsContainer = document.getElementById('alerts-container');
const totalAlertsEl = document.getElementById('total-alerts');
const latestIpEl = document.getElementById('latest-ip');

let lastAlertId = null;

async function fetchAlerts() {
    try {
        const response = await fetch('/logs/alerts.json');
        if (!response.ok) return;
        
        const text = await response.text();
        if (!text) return; // Empty file
        
        const alerts = JSON.parse(text);
        
        if (alerts && alerts.length > 0) {
            updateDashboard(alerts);
        }
    } catch (error) {
        console.log('Waiting for logs...', error);
    }
}

function updateDashboard(alerts) {
    // Update Stats
    totalAlertsEl.innerText = alerts.length;
    latestIpEl.innerText = alerts[0].source_ip;

    // Check if there are new alerts to avoid full re-render
    if (alerts[0].id === lastAlertId) return;
    lastAlertId = alerts[0].id;

    // Render Alerts
    alertsContainer.innerHTML = '';
    
    alerts.forEach(alert => {
        const card = document.createElement('div');
        card.className = 'alert-card';
        card.innerHTML = `
            <div class="alert-info">
                <h4>CRITICAL: ${alert.type}</h4>
                <div class="alert-details">Source IP: <strong>${alert.source_ip}</strong></div>
            </div>
            <div class="alert-meta">
                <span class="alert-time">${alert.timestamp}</span>
                <span class="alert-ports">${alert.ports_scanned} Ports Scanned</span>
            </div>
        `;
        alertsContainer.appendChild(card);
    });
}

// Poll every 2 seconds
setInterval(fetchAlerts, 2000);
fetchAlerts(); // Initial fetch
