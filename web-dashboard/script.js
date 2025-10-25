const DELAY_MS = 2500;
let displayedIndex = 0;
let maliciousCount = 0;
let normalCount = 0;
let allFlows = [];
let cumulativeData = [];

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

    const tr = document.createElement('tr');
    tr.className = flow.prediction===1?'malicious new-flow':'normal new-flow';
    tr.innerHTML = `
        <td>${flow.duration}</td>
        <td>${flow.total_pkts}</td>
        <td>${flow.total_bytes}</td>
        <td>${flow.mean_pkt_len}</td>
        <td>${flow.pkt_rate}</td>
        <td>${flow.protocol}</td>
        <td>${flow.prediction===1?'Malicious':'Normal'}</td>
    `;
    flowsTable.appendChild(tr);
    flowsTable.parentElement.scrollTop = flowsTable.parentElement.scrollHeight;

    if(flow.prediction===1){
        maliciousCount++;
        const li = document.createElement('li');
        li.textContent = `⚠️ Malicious flow detected: duration=${flow.duration}, pkts=${flow.total_pkts}, bytes=${flow.total_bytes}`;
        alertsList.appendChild(li);
        alertsList.scrollTop = alertsList.scrollHeight;
    } else normalCount++;

    cumulativeData.push({malicious:maliciousCount, normal:normalCount});
    updateSummary();
    updateCharts();

    await new Promise(resolve => setTimeout(resolve, 200)); // simulate real-time flow
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
        const flows = data.flows||[];
        allFlows = allFlows.concat(flows.slice(displayedIndex));
        await processNewFlows(allFlows);
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

document.getElementById('clear-alerts').addEventListener('click',()=>{ document.getElementById('alerts-list').innerHTML=''; });

let currentFilter='all';
document.querySelectorAll('.filter-buttons button').forEach(btn=>{
    btn.addEventListener('click',()=>{
        currentFilter=btn.dataset.filter;
        document.querySelectorAll('.filter-buttons button').forEach(b=>b.classList.remove('active'));
        btn.classList.add('active');
        applyFilter(currentFilter);
    });
});

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

setInterval(fetchFlows, DELAY_MS);
fetchFlows();
