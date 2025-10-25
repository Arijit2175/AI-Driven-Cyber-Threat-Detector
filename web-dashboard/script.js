async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function fetchFlows() {
    try {
        const response = await fetch('http://127.0.0.1:5000/get_flows');
        const data = await response.json();

        const flowsTable = document.querySelector('#flows-table tbody');
        const alertsList = document.querySelector('#alerts-list');

        flowsTable.innerHTML = '';
        alertsList.innerHTML = '';

        for (let i = 0; i < data.length; i++) {
            const flow = data[i];

            const tr = document.createElement('tr');
            tr.className = flow.prediction === 1 ? 'malicious' : '';
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

            if (flow.prediction === 1) {
                const li = document.createElement('li');
                li.textContent = `Malicious flow detected: ${flow.duration}, ${flow.total_pkts}, ${flow.total_bytes}, ...`;
                alertsList.appendChild(li);
            }

            await sleep(200); 
        }
    } catch (err) {
        console.error('Error fetching flows:', err);
    }
}

setInterval(fetchFlows, 5000);
fetchFlows();
