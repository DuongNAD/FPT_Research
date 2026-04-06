document.addEventListener('DOMContentLoaded', async () => {
    try {
        const response = await fetch('/api/threats');
        const data = await response.json();
        
        renderAlerts(data.summary);
        renderPackages(data.summary);
        renderGraph(data.graph);
        
        // Fetch Blacklist
        const blResponse = await fetch('/api/blacklist');
        const blData = await blResponse.json();
        renderBlacklist(blData);
        
    } catch (error) {
        console.error("Error fetching threat data:", error);
        document.getElementById('alerts-container').innerHTML = 
            `<div class="alert-item"><p>Lỗi kết nối tới Máy chủ Proxy API.</p></div>`;
    }
});

function renderAlerts(summary) {
    const container = document.getElementById('alerts-container');
    container.innerHTML = '';
    
    let delay = 0;
    let hasAlerts = false;
    
    summary.forEach(pkg => {
        if (pkg.risk_score > 0) {
            hasAlerts = true;
            pkg.alerts.forEach(alertText => {
                const item = document.createElement('div');
                item.className = 'alert-item';
                item.style.animationDelay = `${delay}ms`;
                item.innerHTML = `
                    <h3>Threat Detected in [${pkg.package_name}]</h3>
                    <p>${alertText}</p>
                `;
                container.appendChild(item);
                delay += 100;
            });
        }
    });
    
    if (!hasAlerts) {
        container.innerHTML = `<p style="color: var(--text-secondary); text-align: center; margin-top: 20px;">No threats detected.</p>`;
    }
}

function renderPackages(summary) {
    const container = document.getElementById('package-list');
    container.innerHTML = '';
    
    let delay = 0;
    
    // Sort high risk first
    summary.sort((a,b) => b.risk_score - a.risk_score).forEach(pkg => {
        const isHigh = pkg.risk_score > 0;
        const riskClass = isHigh ? 'risk-high' : 'risk-low';
        const riskText = isHigh ? `RỦI RO: ${pkg.risk_score}` : 'AN TOÀN';
        
        const tags = pkg.behaviors.map(b => `<span class="tag">${b}</span>`).join('');
        
        const card = document.createElement('div');
        card.className = 'package-card';
        card.style.animationDelay = `${delay}ms`;
        card.innerHTML = `
            <div class="package-header">
                <span class="package-name">${pkg.package_name}</span>
                <span class="risk-badge ${riskClass}">${riskText}</span>
            </div>
            ${tags ? `<div class="tag-list">${tags}</div>` : ''}
        `;
        container.appendChild(card);
        delay += 100;
    });
}

function renderBlacklist(blacklist) {
    const container = document.getElementById('blacklist-container');
    container.innerHTML = '';
    
    const entries = Object.entries(blacklist);
    if (entries.length === 0) {
        container.innerHTML = `<p style="font-size: 0.85rem; color: var(--text-secondary);">Danh sách đen đang trống (Sạch sẽ).</p>`;
        return;
    }
    
    entries.forEach(([pkg, data]) => {
        const item = document.createElement('div');
        item.style.padding = '10px';
        item.style.borderBottom = '1px solid rgba(255,255,255,0.05)';
        item.style.fontSize = '0.85rem';
        item.innerHTML = `<strong>${pkg}</strong><br/><span style="color: #ffb74d;">${data.reason}</span>`;
        container.appendChild(item);
    });
}

function renderGraph(graphData) {
    const container = document.getElementById('network-graph');
    
    // Customize Nodes for 4 Layers
    const nodes = new vis.DataSet(graphData.nodes.map(n => {
        let nData = { id: n.id, label: n.label, group: n.group };
        if (n.group === 'package') {
            nData.shape = 'hexagon';
            nData.size = 28;
            nData.color = '#ff4b4b';
            nData.font = { color: '#ffffff', size: 16, bold: true };
        } else if (n.group === 'indicator') {
            nData.shape = 'ellipse';
            nData.color = { background: '#2b2b2b', border: '#00ffcc' };
            nData.borderWidth = 2;
            nData.font = { color: '#00ffcc', size: 12 };
        } else if (n.group === 'behavior') {
            nData.shape = 'box';
            nData.color = { background: '#005f73', border: '#00ffcc' };
            nData.borderWidth = 2;
            nData.font = { color: '#ffffff', size: 13 };
        } else if (n.group === 'technique') {
            nData.shape = 'box';
            nData.color = '#ffb74d';
            nData.font = { color: '#000000', size: 14, bold: true };
        } else if (n.group === 'tactic') {
            nData.shape = 'diamond';
            nData.size = 20;
            nData.color = { background: '#6a11cb', border: '#ffffff' };
            nData.borderWidth = 2;
            nData.font = { color: '#ffffff', size: 15, bold: true };
        }
        return nData;
    }));
    
    // Customize Directed Edges
    const edges = new vis.DataSet(graphData.edges.map(e => ({
        from: e.from, 
        to: e.to,
        label: e.label,
        font: { size: 11, color: '#a0a0a0', align: 'middle', strokeWidth: 0 },
        color: { color: 'rgba(255,255,255,0.3)', highlight: '#00ffcc' },
        arrows: 'to',
        length: 120
    })));
    
    const data = { nodes, edges };
    const options = {
        interaction: { hover: true, tooltipDelay: 200 },
        layout: {
            hierarchical: {
                direction: 'LR',
                sortMethod: 'directed',
                levelSeparation: 300,
                nodeSpacing: 100
            }
        },
        physics: {
            hierarchicalRepulsion: {
                nodeDistance: 150
            }
        }
    };
    
    new vis.Network(container, data, options);
}
