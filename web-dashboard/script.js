const DELAY_MS = 2500;
let displayedIndex = 0;

let maliciousCount = 0;
let normalCount = 0;

const ctx = document.getElementById('flowChart').getContext('2d');
const flowChart = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: ['Malicious Flows', 'Normal Flows', 'Total Scanned'],
        datasets: [{
            label: 'Flow Count',
            data: [0, 0, 0],
            backgroundColor: [
                'rgba(255, 99, 132, 0.7)',
                'rgba(75, 192, 75, 0.7)',
                'rgba(54, 162, 235, 0.7)'
            ],
            borderColor: ['#ff4d4d', '#32cd32', '#36a2eb'],
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        scales: {
            y: { beginAtZero: true }
        },
        plugins: {
            legend: {
                labels: { color: '#000' }
            }
        }
    }
});

async function fetchFlows() {
    try {
        const response = await fetch('http://127.0.0.1:5000/get_flows');
        const data = await response.json();
        const flows = data.flows || [];

        const flowsTable = document.querySelector('#flows-table tbody');
        const alertsList = document.querySelector('#alerts-list');
        const alertsSummary = document.querySelector('#alerts-summary');

        for (let i = displayedIndex; i < flows.length; i++) {
            const flow = flows[i];

            const tr = document.createElement('tr');
            tr.className = flow.prediction === 1 ? 'malicious new-flow' : 'normal new-flow';
            tr.innerHTML = `
                <td>${flow.duration}</td>
                <td>${flow.total_pkts}</td>
                <td>${flow.total_bytes}</td>
                <td>${flow.mean_pkt_len}</td>
                <td>${flow.pkt_rate}</td>
                <td>${flow.protocol}</td>
                <td>${flow.prediction === 1 ? 'Malicious' : 'Normal'}</td>
            `;
            flowsTable.appendChild(tr);

            flowsTable.parentElement.scrollTop = flowsTable.parentElement.scrollHeight;

            if (flow.prediction === 1) {
                maliciousCount++;
                const li = document.createElement('li');
                li.textContent = `⚠️ Malicious flow detected: duration=${flow.duration}, pkts=${flow.total_pkts}, bytes=${flow.total_bytes}`;
                alertsList.appendChild(li);
            } else {
                normalCount++;
            }

            displayedIndex++;

            const totalFlows = maliciousCount + normalCount;
            alertsSummary.innerHTML = `
                <li>Total Flows Scanned: <strong>${totalFlows}</strong></li>
                <li style="color:#ff4d4d;">Malicious Flows: <strong>${maliciousCount}</strong></li>
                <li style="color:#32cd32;">Normal Flows: <strong>${normalCount}</strong></li>
            `;

            flowChart.data.datasets[0].data = [maliciousCount, normalCount, totalFlows];
            flowChart.update();

            await new Promise(resolve => setTimeout(resolve, DELAY_MS));
        }
    } catch (err) {
        console.error('Error fetching flows:', err);
    }
}

const themeToggle = document.getElementById('theme-toggle');
themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('dark-theme');
    document.body.classList.toggle('light-theme');
    themeToggle.textContent = document.body.classList.contains('dark-theme')
        ? '☀️ Light Mode'
        : '🌙 Dark Mode';

    const isDark = document.body.classList.contains('dark-theme');
    flowChart.options.plugins.legend.labels.color = isDark ? '#fff' : '#000';
    flowChart.options.scales.y.ticks.color = isDark ? '#fff' : '#000';
    flowChart.options.scales.x.ticks.color = isDark ? '#fff' : '#000';
    flowChart.update();
});

setInterval(fetchFlows, DELAY_MS);
fetchFlows();
