const DELAY_MS = 500;
let displayedIndex = 0;
let maliciousCount = 0;
let normalCount = 0;
let allFlows = [];
let cumulativeData = [];
let dismissedAlerts = new Set(); 

const ctx = document.getElementById('flowChart').getContext('2d');
const lineCtx = document.getElementById('lineChart').getContext('2d');

const flowChart = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: ['Malicious Flows', 'Normal Flows', 'Total Scanned'],
        datasets: [{
            label: 'Flow Count',
            data: [0,0,0],
            backgroundColor:['rgba(255,99,132,0.8)','rgba(75,192,75,0.8)','rgba(54,162,235,0.8)'],
            borderColor:['#ff4d4d','#32cd32','#36a2eb'], borderWidth:1, borderRadius:6
        }]
    },
    options:{ responsive:true, animation:{duration:800,easing:'easeOutCubic'},
        scales:{ y:{beginAtZero:true,ticks:{color:'#000'},grid:{color:'rgba(0,0,0,0.1)'}},
                 x:{ticks:{color:'#000'},grid:{color:'rgba(0,0,0,0.05)'}} },
        plugins:{ legend:{labels:{color:'#000', font:{size:13, weight:'500'}}} }
    }
});

const lineChart = new Chart(lineCtx, {
    type: 'line',
    data:{ labels:[], datasets:[
        { label:'Malicious', data:[], borderColor:'#ff4d4d', backgroundColor:'rgba(255,99,132,0.2)', tension:0.3 },
        { label:'Normal', data:[], borderColor:'#32cd32', backgroundColor:'rgba(75,192,75,0.2)', tension:0.3 }
    ]},
    options:{ responsive:true, animation:{duration:800,easing:'easeOutCubic'}, scales:{y:{beginAtZero:true}}, plugins:{legend:{labels:{font:{size:12}}}} }
});

async function insertFlow(flow){
    const flowsTable = document.querySelector('#flows-table tbody');
    const alertsList = document.querySelector('#alerts-list');

    const severity = (flow.severity || '').toString().trim().toUpperCase();
    const isAlert = flow.is_alert === true || flow.is_alert === 'true';
    const highSeverity = severity === 'CRITICAL' || severity === 'HIGH';
    const mlHigh = (flow.prediction === 1) || (flow.score !== undefined && flow.score >= 0.5);
    const isMalicious = isAlert || highSeverity || mlHigh;
    const severityLabel = severity || (isAlert ? 'ALERT' : '');

    const tr = document.createElement('tr');
    tr.className = isMalicious ? 'malicious new-flow' : 'normal new-flow';
    tr.innerHTML = `
        <td>${flow.duration}</td>
        <td>${flow.total_pkts}</td>
        <td>${flow.total_bytes}</td>
        <td>${flow.mean_pkt_len}</td>
        <td>${flow.pkt_rate}</td>
        <td>${flow.protocol}</td>
        <td>${isMalicious ? (severityLabel || 'Malicious') : (severityLabel || 'Normal')}</td>
    `;
    flowsTable.appendChild(tr);
    flowsTable.parentElement.scrollTop = flowsTable.parentElement.scrollHeight;

    if(isMalicious){
        maliciousCount++;
        const li = document.createElement('li');
        li.textContent = `🔴 ${flow.severity} threat: duration=${flow.duration}, pkts=${flow.total_pkts}, rate=${flow.pkt_rate} pkt/s`;
        alertsList.appendChild(li);
        alertsList.scrollTop = alertsList.scrollHeight;
    } else normalCount++;

    cumulativeData.push({malicious:maliciousCount, normal:normalCount});
    updateSummary();
    updateCharts();

    await new Promise(resolve => setTimeout(resolve, 50)); 
}

async function processNewFlows(flows){
    for(let i=displayedIndex;i<flows.length;i++){
        await insertFlow(flows[i]);
        displayedIndex++;
    }
}

async function fetchFlows(){
    try{
        const response = await fetch('http://127.0.0.1:5000/get_flows');
        const data = await response.json();
        const newFlows = data.flows||[];
        
        for(const flow of newFlows) {
            const isDuplicate = allFlows.some(f => 
                f.duration === flow.duration && 
                f.total_pkts === flow.total_pkts && 
                f.total_bytes === flow.total_bytes &&
                f.pkt_rate === flow.pkt_rate
            );
            if (!isDuplicate) {
                allFlows.push(flow);
                await insertFlow(flow);
            }
        }
        applyFilter(currentFilter);
    }catch(err){ console.error('Error fetching flows:', err); }
}

function updateSummary(){
    const totalFlows = maliciousCount+normalCount;
    document.querySelector('#alerts-summary').innerHTML=`
        <li>Total Flows Scanned: <strong>${totalFlows}</strong></li>
        <li style="color:#ff4d4d;">Malicious Flows: <strong>${maliciousCount}</strong></li>
        <li style="color:#32cd32;">Normal Flows: <strong>${normalCount}</strong></li>
    `;
}

function updateCharts(){
    const totalFlows = maliciousCount+normalCount;
    flowChart.data.datasets[0].data=[maliciousCount, normalCount, totalFlows];
    flowChart.update();

    lineChart.data.labels = cumulativeData.map((_,i)=>i+1);
    lineChart.data.datasets[0].data = cumulativeData.map(d=>d.malicious);
    lineChart.data.datasets[1].data = cumulativeData.map(d=>d.normal);
    lineChart.update();
}

const themeToggle = document.getElementById('theme-toggle');
themeToggle.addEventListener('click',()=>{
    document.body.classList.toggle('dark-theme');
    document.body.classList.toggle('light-theme');
    themeToggle.textContent=document.body.classList.contains('dark-theme')?'☀️ Light Mode':'🌙 Dark Mode';
    const isDark=document.body.classList.contains('dark-theme');
    [flowChart,lineChart].forEach(c=>{
        c.options.plugins.legend.labels.color=isDark?'#fff':'#000';
        c.options.scales.y.ticks.color=isDark?'#fff':'#000';
        c.options.scales.x.ticks.color=isDark?'#fff':'#000';
        c.update();
    });
});

document.getElementById('clear-alerts').addEventListener('click',()=>{ 
    const alertsList = document.querySelector('#alerts-list');
    alertsList.querySelectorAll('li').forEach(li => {
        const alertText = li.getAttribute('data-alert-text');
        if(alertText) dismissedAlerts.add(alertText);
    });
    alertsList.innerHTML = ''; 
});

let currentFilter='all';
document.querySelectorAll('.filter-buttons button').forEach(btn=>{
    btn.addEventListener('click',()=>{
        currentFilter=btn.dataset.filter;
        document.querySelectorAll('.filter-buttons button').forEach(b=>b.classList.remove('active'));
        btn.classList.add('active');
        applyFilter(currentFilter);
    });
});

async function fetchAlerts(){
    try{
        const res = await fetch('http://127.0.0.1:5000/get_alerts');
        const data = await res.json();
        const alerts = data.alerts || [];
        const alertsList = document.querySelector('#alerts-list');
        alertsList.innerHTML = '';
        alerts.forEach(line=>{
            if(dismissedAlerts.has(line)) return;
            
            const upper = line.toUpperCase();
            if(upper.includes('CRITICAL') || upper.includes('HIGH')){
                const li = document.createElement('li');
                
                const timeMatch = line.match(/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/);
                const timestamp = timeMatch ? timeMatch[1].split('T')[1].substring(0,8) : '';
                
                let severity = 'HIGH';
                let icon = '🟠';
                let severityClass = 'high-alert';
                if(upper.includes('CRITICAL')){
                    severity = 'CRITICAL';
                    icon = '🔴';
                    severityClass = 'critical-alert';
                }
                
                let attackType = 'Suspicious Activity';
                if(upper.includes('SYN FLOOD')) attackType = 'SYN Flood Attack';
                else if(upper.includes('DDOS') || upper.includes('EXTREME PACKET RATE')) attackType = 'DDoS Attack';
                else if(upper.includes('SCAN') || upper.includes('BURST')) attackType = 'Port Scan';
                else if(upper.includes('UDP AMPLIFICATION')) attackType = 'UDP Amplification';
                else if(upper.includes('EXFILTRATION')) attackType = 'Data Exfiltration';
                
                const rateMatch = line.match(/([\d.]+),\s*([\d.]+)\]$/);
                const rate = rateMatch ? `${Math.round(parseFloat(rateMatch[2]))} pkt/s` : '';
                
                li.className = severityClass;
                li.setAttribute('data-alert-text', line); 
                li.innerHTML = `
                    <div class="alert-header">
                        <span class="alert-icon">${icon}</span>
                        <span class="alert-severity">${severity}</span>
                        <span class="alert-time">${timestamp}</span>
                    </div>
                    <div class="alert-body">
                        <div class="alert-type">${attackType}</div>
                        ${rate ? `<div class="alert-rate">${rate}</div>` : ''}
                    </div>
                `;
                
                alertsList.appendChild(li);
            }
        });
        alertsList.scrollTop = alertsList.scrollHeight;
    }catch(err){ console.error('Error fetching alerts:', err); }
}

function applyFilter(filter){
    document.querySelectorAll('#flows-table tbody tr').forEach(row=>{
        if(filter==='all') row.style.display='';
        else if(filter==='malicious') row.style.display=row.classList.contains('malicious')?'':'none';
        else if(filter==='normal') row.style.display=row.classList.contains('normal')?'':'none';
    });
}

document.getElementById('export-csv').addEventListener('click',()=>{
    let csv='Duration,Total Packets,Total Bytes,Mean Packet Length,Packet Rate,Protocol,Prediction\n';
    allFlows.forEach(f=>{
        csv+=`${f.duration},${f.total_pkts},${f.total_bytes},${f.mean_pkt_len},${f.pkt_rate},${f.protocol},${f.prediction===1?'Malicious':'Normal'}\n`;
    });
    const blob=new Blob([csv],{type:'text/csv'});
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');
    a.href=url; a.download='flows.csv';
    a.click();
    URL.revokeObjectURL(url);
});

document.getElementById('sidebar-toggle').addEventListener('click',()=>{
    document.querySelector('.sidebar').classList.toggle('collapsed');
});

fetchFlows();
fetchAlerts();
setInterval(fetchFlows, DELAY_MS);
setInterval(fetchAlerts, 1000);
