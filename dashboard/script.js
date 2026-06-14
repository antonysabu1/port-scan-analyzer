const alertsContainer = document.getElementById('alerts-container');
const totalAlertsEl = document.getElementById('total-alerts');
const latestIpEl = document.getElementById('latest-ip');

let lastAlertId = null;
let activityChart = null;

// Initialize Chart.js
function initChart() {
    const ctx = document.getElementById('activityChart').getContext('2d');
    
    // Cyberpunk Gradient fill
    let gradient = ctx.createLinearGradient(0, 0, 0, 400);
    gradient.addColorStop(0, 'rgba(255, 42, 42, 0.5)');
    gradient.addColorStop(1, 'rgba(255, 42, 42, 0.0)');

    activityChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Ports Scanned',
                data: [],
                borderColor: '#ff2a2a',
                backgroundColor: gradient,
                borderWidth: 2,
                tension: 0.4,
                fill: true,
                pointBackgroundColor: '#00f0ff',
                pointBorderColor: '#00f0ff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#94a3b8' }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

async function fetchAlerts() {
    try {
        const response = await fetch('/logs/alerts.json?nocache=' + new Date().getTime());
        if (!response.ok) return;
        
        const text = await response.text();
        if (!text) return; 
        
        const alerts = JSON.parse(text);
        
        if (alerts && alerts.length > 0) {
            updateDashboard(alerts);
        }
    } catch (error) {
        console.log('Waiting for logs...', error);
    }
}

function updateDashboard(alerts) {
    totalAlertsEl.innerText = alerts.length;
    latestIpEl.innerText = alerts[0].source_ip;

    if (alerts[0].id === lastAlertId) return;
    lastAlertId = alerts[0].id;

    alertsContainer.innerHTML = '';
    
    // Reverse alerts for chronological chart (oldest to newest)
    let chartLabels = [];
    let chartData = [];

    alerts.slice(0, 15).reverse().forEach(alert => {
        let timeOnly = alert.timestamp.split(' ')[1];
        chartLabels.push(timeOnly);
        chartData.push(alert.ports_scanned);
    });

    // Update Live Chart
    activityChart.data.labels = chartLabels;
    activityChart.data.datasets[0].data = chartData;
    activityChart.update();

    // Render Alert Cards
    alerts.forEach(alert => {
        const card = document.createElement('div');
        card.className = 'alert-card';
        card.innerHTML = `
            <div class="alert-info">
                <h4>CRITICAL: ${alert.type}</h4>
                <div class="alert-details">
                    Source IP: <strong style="color: white;">${alert.source_ip}</strong><br>
                    Location: <span style="color: #00f0ff;">${alert.location || 'Unknown'}</span><br>
                    ISP: <span>${alert.isp || 'Unknown'}</span>
                </div>
            </div>
            <div class="alert-meta">
                <span class="alert-time">${alert.timestamp}</span>
                <span class="alert-ports">${alert.ports_scanned} Ports Scanned</span>
                <span class="alert-status">${alert.status || 'DETECTED'}</span>
            </div>
        `;
        alertsContainer.appendChild(card);
    });
}

// Start app
initChart();
setInterval(fetchAlerts, 2000);
fetchAlerts();
