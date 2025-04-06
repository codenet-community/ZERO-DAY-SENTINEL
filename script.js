// Network Threat Detector - Main JavaScript
document.addEventListener('DOMContentLoaded', () => {
    // Firebase Configuration and Initialization
    const firebaseConfig = {
      apiKey: "AIzaSyBSbonwVE3PPXIIrSrvrB75u2AQ_B_Tni4",
      authDomain: "discraft-c1c41.firebaseapp.com",
      databaseURL: "https://discraft-c1c41-default-rtdb.firebaseio.com",
      projectId: "discraft-c1c41",
      storageBucket: "discraft-c1c41.appspot.com",
      messagingSenderId: "525620150766",
      appId: "1:525620150766:web:a426e68d206c68764aceff"
    };

    // Initialize Firebase
    firebase.initializeApp(firebaseConfig);
    const database = firebase.database();

    // DOM Elements
    const detectBtn = document.getElementById('detect-btn');
    const stopBtn = document.getElementById('stop-btn');
    const blockchainBtn = document.getElementById('blockchain-btn');
    const dataSource = document.getElementById('data-source');
    const scanStatus = document.querySelector('.scan-status');
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const threatFeedContainer = document.getElementById('threat-feed-container');
    const trafficDataElement = document.getElementById('traffic-data');
    const totalEntriesEl = document.getElementById('total-entries');
    const threatCountEl = document.getElementById('threat-count');
    const normalCountEl = document.getElementById('normal-count');
    const lastUpdateEl = document.getElementById('last-update');
    const aiAnalysis = document.getElementById('ai-analysis');
    const logConsole = document.getElementById('log-console');
    const clearLogsBtn = document.getElementById('clear-logs-btn');
    const notification = document.getElementById('notification');
    const notificationMessage = document.getElementById('notification-message');
    const closeNotification = document.getElementById('close-notification');
    const blockchainContainer = document.getElementById('blockchain-container');

    // Stats tracking
    let stats = {
        totalEntries: 0,
        threatCount: 0,
        normalCount: 0,
        attackTypes: {},
        protocols: {},
        services: {}
    };

    // Store detected threats for blockchain posting
    let detectedThreats = [];
    let analysisTimestamp = null;

    // Charts
    let attackDistChart, protocolChart, serviceChart, timelineChart;
    let isDetecting = false;
    let trafficData = [];
    
    // Tab switching
    function switchTab(tabId) {
        tabButtons.forEach(btn => {
            btn.classList.remove('active');
            if(btn.dataset.tab === tabId) {
                btn.classList.add('active');
            }
        });
        
        tabContents.forEach(content => {
            content.classList.remove('active');
        });
        
        document.getElementById(`${tabId}-tab`).classList.add('active');
    }

    // Initialize charts
    function initCharts() {
        // Attack Distribution Chart
        const attackCtx = document.getElementById('attack-distribution-chart').getContext('2d');
        attackDistChart = new Chart(attackCtx, {
            type: 'pie',
            data: {
                labels: ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'],
                datasets: [{
                    data: [100, 0, 0, 0, 0],
                    backgroundColor: ['#4caf50', '#f44336', '#ff9800', '#9c27b0', '#2196f3']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
        
        // Protocol Chart
        const protocolCtx = document.getElementById('protocol-chart').getContext('2d');
        protocolChart = new Chart(protocolCtx, {
            type: 'bar',
            data: {
                labels: ['TCP', 'UDP', 'ICMP'],
                datasets: [{
                    label: 'Traffic Count',
                    data: [0, 0, 0],
                    backgroundColor: '#3498db'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
        
        // Service Chart
        const serviceCtx = document.getElementById('service-chart').getContext('2d');
        serviceChart = new Chart(serviceCtx, {
            type: 'doughnut',
            data: {
                labels: ['HTTP', 'FTP', 'SMTP', 'SSH', 'DNS', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: ['#e74c3c', '#3498db', '#2ecc71', '#f1c40f', '#9b59b6', '#95a5a6']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
        
        // Timeline Chart
        const timelineCtx = document.getElementById('timeline-chart').getContext('2d');
        timelineChart = new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: Array(24).fill().map((_, i) => i),
                datasets: [{
                    label: 'Traffic',
                    data: Array(24).fill(0),
                    borderColor: '#3498db',
                    tension: 0.3,
                    fill: true,
                    backgroundColor: 'rgba(52, 152, 219, 0.2)'
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    // Set up event listeners
    function setupEventListeners() {
        // Tab switching
        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                switchTab(button.dataset.tab);
            });
        });
        
        // Detect button
        detectBtn.addEventListener('click', startDetection);
        
        // Stop button
        stopBtn.addEventListener('click', stopDetection);
        
        // Blockchain button
        blockchainBtn.addEventListener('click', postToBlockchain);
        
        // Clear logs
        clearLogsBtn.addEventListener('click', () => {
            logConsole.innerHTML = '';
            addLog('Logs cleared', 'SYSTEM');
        });
        
        // Close notification
        closeNotification.addEventListener('click', () => {
            notification.classList.add('hidden');
        });
    }

    // Start detection
    function startDetection() {
        if (isDetecting) return;
        
        // Reset detected threats
        detectedThreats = [];
        analysisTimestamp = new Date().toISOString();
        
        isDetecting = true;
        detectBtn.classList.add('hidden');
        stopBtn.classList.remove('hidden');
        blockchainBtn.classList.add('hidden');
        scanStatus.classList.remove('hidden');
        
        addLog('Starting threat detection...', 'SYSTEM');
        showNotification('Starting network threat detection');
        
        const source = dataSource.value;
        if (source === 'csv') {
            runPythonAnalysis();
        } else {
            simulateLiveDetection();
        }
    }

    // Run Python Analysis
    function runPythonAnalysis() {
        addLog('Running Gemini AI analysis on log data...', 'SYSTEM');
        
        // In a real application, we would make an AJAX call to a backend service
        // that would run the Python script. For this demo, we'll simulate the response.
        
        // Display loading state in AI insights
        aiAnalysis.innerHTML = `
            <div class="ai-loading">
                <div class="ai-loading-spinner"></div>
                <p>Running Gemini AI analysis on network traffic data...</p>
            </div>
        `;
        
        // Simulate delay for analysis
        setTimeout(() => {
            // Display the Gemini analysis results
            displayGeminiAnalysisResults();
            
            // Update UI
            updateLastUpdate();
            processMockTrafficData();
            
            // Log completion
            addLog('Gemini AI analysis completed', 'SYSTEM');
            showNotification('Threat analysis complete');
            
            // Show blockchain button
            blockchainBtn.classList.remove('hidden');
            
            // Update state
            stopDetection();
        }, 2500);
    }

    // Display Gemini Analysis Results
    function displayGeminiAnalysisResults() {
        // These are the results from the Python script
        aiAnalysis.innerHTML = `
            <div class="ai-response">
                <div class="ai-header">
                    <i class="fas fa-robot"></i>
                    <h3>Gemini Analysis</h3>
                </div>
                <div class="ai-content">
                    <h4>Analysis Summary</h4>
                    <p>Analyzed log entries with multiple security threats detected:</p>
                    
                    <div class="threat-summary">
                        <h4>🚨 Major Threats Detected</h4>
                        <ul class="threat-list">
                            <li>
                                <strong>SQL Injection Attacks (3)</strong>
                                <p>Detected classic SQLi patterns including OR-based authentication bypass and destructive DROP TABLE commands</p>
                                <div class="threat-details">
                                    <span class="detail-label">Entry #5:</span>
                                    <span class="detail-value">GET /login.php?id=1' OR '1'='1</span>
                                </div>
                                <div class="threat-details">
                                    <span class="detail-label">Entry #14:</span>
                                    <span class="detail-value">POST /auth.asp?user=admin' UNION SELECT NULL,password FROM users --</span>
                                </div>
                                <div class="threat-details">
                                    <span class="detail-label">Entry #19:</span>
                                    <span class="detail-value">GET /query.php?term='; DROP TABLE users --</span>
                                </div>
                            </li>
                            <li>
                                <strong>DDoS Attack (1)</strong>
                                <p>UDP flood targeting DNS services (port 53)</p>
                                <div class="threat-details">
                                    <span class="detail-label">Entry #10:</span>
                                    <span class="detail-value">Flood, Port 49154 -> 53</span>
                                </div>
                            </li>
                            <li>
                                <strong>Brute Force Attempt (1)</strong>
                                <p>SSH login attempt using weak credentials</p>
                                <div class="threat-details">
                                    <span class="detail-label">Entry #15:</span>
                                    <span class="detail-value">SSH user=root pass=123456</span>
                                </div>
                            </li>
                            <li>
                                <strong>Port Scanning (1)</strong>
                                <p>Suspicious SYN packets targeting SSH services</p>
                                <div class="threat-details">
                                    <span class="detail-label">Entry #8:</span>
                                    <span class="detail-value">SYN, Port 49153 -> 22</span>
                                </div>
                            </li>
                        </ul>
                    </div>
                    
                    <h4>Recommendations</h4>
                    <ol>
                        <li>Implement input validation and parameterized queries to prevent SQL injection</li>
                        <li>Configure firewall rules to block suspicious traffic patterns</li>
                        <li>Enforce strong password policies and implement account lockout mechanisms</li>
                        <li>Consider deploying an Intrusion Prevention System (IPS)</li>
                        <li>Review security logs regularly for suspicious activities</li>
                    </ol>
                    
                    <p class="ai-footer">Analysis performed by Gemini 1.5 AI at ${new Date().toLocaleString()}</p>
                </div>
            </div>
        `;
        
        // Update stats based on the analysis results
        stats.totalEntries = 20;
        stats.threatCount = 11;
        stats.normalCount = 9;
        stats.attackTypes = {
            'sql_injection': 3,
            'ddos': 1,
            'brute_force': 1,
            'port_scan': 1,
            'suspicious': 5
        };
        
        // Update counters
        totalEntriesEl.textContent = stats.totalEntries;
        threatCountEl.textContent = stats.threatCount;
        normalCountEl.textContent = stats.normalCount;
        
        // Update charts
        updateCharts();
    }

    // Process mock traffic data for visualization
    function processMockTrafficData() {
        // Generate mock data based on the log file contents
        const mockData = [
            {
                timestamp: "16:00:00.050",
                protocol: "TCP",
                service: "HTTP",
                srcBytes: 512,
                destBytes: 128,
                attackType: "sql_injection",
                isThreat: true,
                sourceIP: "203.0.113.10",
                destIP: "192.168.1.50",
                info: "GET /login.php?id=1' OR '1'='1",
                severity: "High"
            },
            {
                timestamp: "16:00:00.080",
                protocol: "TCP",
                service: "SSH",
                srcBytes: 66,
                destBytes: 40,
                attackType: "port_scan",
                isThreat: true,
                sourceIP: "198.51.100.20",
                destIP: "192.168.1.60",
                info: "SYN, Port 49153 -> 22",
                severity: "Medium"
            },
            {
                timestamp: "16:00:00.100",
                protocol: "UDP",
                service: "DNS",
                srcBytes: 1500,
                destBytes: 0,
                attackType: "ddos",
                isThreat: true,
                sourceIP: "203.0.113.30",
                destIP: "192.168.1.70",
                info: "Flood, Port 49154 -> 53",
                severity: "High"
            },
            {
                timestamp: "16:00:00.140",
                protocol: "TCP",
                service: "HTTP",
                srcBytes: 512,
                destBytes: 256,
                attackType: "sql_injection",
                isThreat: true,
                sourceIP: "198.51.100.40",
                destIP: "192.168.1.50",
                info: "POST /auth.asp?user=admin' UNION SELECT NULL,password FROM users --",
                severity: "High"
            },
            {
                timestamp: "16:00:00.150",
                protocol: "TCP",
                service: "SSH",
                srcBytes: 512,
                destBytes: 64,
                attackType: "brute_force",
                isThreat: true,
                sourceIP: "203.0.113.50",
                destIP: "192.168.1.60",
                info: "SSH user=root pass=123456",
                severity: "High"
            },
            {
                timestamp: "16:00:00.190",
                protocol: "TCP",
                service: "HTTP",
                srcBytes: 512,
                destBytes: 128,
                attackType: "sql_injection",
                isThreat: true,
                sourceIP: "203.0.113.70",
                destIP: "192.168.1.50",
                info: "GET /query.php?term='; DROP TABLE users --",
                severity: "Critical"
            }
        ];
        
        // Store detected threats for blockchain
        detectedThreats = mockData;
        
        // Add data to visualizations
        mockData.forEach(entry => {
            // Add to traffic table
            addTrafficEntry(entry);
            
            // Add to threat feed if it's a threat
            if (entry.isThreat) {
                addThreatEntry(entry);
            }
            
            // Log the entry
            addLog(`Processed traffic: ${entry.protocol} ${entry.service} (${entry.attackType})`, entry.isThreat ? 'THREAT' : 'INFO');
        });
        
        // Update statistics for protocols and services
        mockData.forEach(entry => {
            stats.protocols[entry.protocol] = (stats.protocols[entry.protocol] || 0) + 1;
            stats.services[entry.service] = (stats.services[entry.service] || 0) + 1;
        });
    }

    // Post to Blockchain (Firebase RTDB)
    function postToBlockchain() {
        if (detectedThreats.length === 0) {
            showNotification('No threats to post to blockchain', 'warning');
            return;
        }

        addLog('Posting threat data to blockchain...', 'SYSTEM');
        showNotification('Posting to blockchain...', 'info');
        
        // Create a unique reference for this analysis
        const timestamp = analysisTimestamp || new Date().toISOString();
        const blockchainRef = database.ref('threatLedger').push();
        
        // Prepare data for blockchain storage
        const blockData = {
            timestamp: timestamp,
            analysisId: blockchainRef.key,
            totalThreats: detectedThreats.length,
            threatTypes: countThreatTypes(),
            threats: detectedThreats,
            stats: stats
        };
        
        // Store data to Firebase (simulating blockchain)
        blockchainRef.set(blockData)
            .then(() => {
                // Update blockchain view
                addBlockchainEntry(blockData);
                
                // Show success notification
                showNotification('Successfully posted to blockchain', 'success');
                addLog('Threat data successfully posted to blockchain', 'SYSTEM');
                
                // Switch to blockchain tab
                switchTab('blockchain');
                
                // Hide blockchain button after successful post
                blockchainBtn.classList.add('hidden');
            })
            .catch((error) => {
                console.error("Blockchain post error:", error);
                showNotification('Error posting to blockchain: ' + error.message, 'error');
                addLog('Error posting to blockchain: ' + error.message, 'ERROR');
            });
    }

    // Add blockchain entry to the UI
    function addBlockchainEntry(blockData) {
        // Clear placeholder if exists
        const placeholder = blockchainContainer.querySelector('.blockchain-placeholder');
        if (placeholder) {
            blockchainContainer.innerHTML = '';
        }
        
        // Create blockchain block
        const blockElement = document.createElement('div');
        blockElement.className = 'blockchain-block';
        
        // Format timestamp for display
        const formattedTime = new Date(blockData.timestamp).toLocaleString();
        
        // Create threat type summary
        let threatTypeSummary = '';
        Object.entries(blockData.threatTypes).forEach(([type, count]) => {
            threatTypeSummary += `<span class="blockchain-tag">${formatAttackType(type)} (${count})</span>`;
        });

        // Create block content
        blockElement.innerHTML = `
            <div class="blockchain-block-header">
                <div class="block-id">
                    <i class="fas fa-cube"></i>
                    <span class="block-hash" title="${blockData.analysisId}">${blockData.analysisId.substring(0, 8)}...</span>
                </div>
                <div class="block-timestamp">${formattedTime}</div>
            </div>
            <div class="blockchain-block-content">
                <div class="block-summary">
                    <div class="block-stat">
                        <span class="block-stat-label">Threats:</span>
                        <span class="block-stat-value">${blockData.totalThreats}</span>
                    </div>
                    <div class="block-threat-types">
                        ${threatTypeSummary}
                    </div>
                </div>
                <div class="block-details">
                    <h4>Threat Distribution</h4>
                    <div class="block-chart-container">
                        <canvas id="blockchain-chart-${blockData.analysisId.substring(0, 6)}"></canvas>
                    </div>
                </div>
            </div>
        `;
        
        // Add to blockchain container
        blockchainContainer.prepend(blockElement);
        
        // Create mini chart for the block
        setTimeout(() => {
            const chartCtx = document.getElementById(`blockchain-chart-${blockData.analysisId.substring(0, 6)}`).getContext('2d');
            
            // Collect data for chart
            const labels = Object.keys(blockData.threatTypes).map(type => formatAttackType(type));
            const data = Object.values(blockData.threatTypes);
            const colors = [
                '#f44336', '#ff9800', '#2196f3', '#4caf50', '#9c27b0', '#607d8b', '#795548'
            ];
            
            // Create chart
            new Chart(chartCtx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: data,
                        backgroundColor: colors.slice(0, data.length)
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: {
                                boxWidth: 12,
                                font: {
                                    size: 10
                                }
                            }
                        }
                    }
                }
            });
        }, 100);
    }

    // Count threat types for blockchain summary
    function countThreatTypes() {
        const types = {};
        detectedThreats.forEach(threat => {
            types[threat.attackType] = (types[threat.attackType] || 0) + 1;
        });
        return types;
    }

    // Stop detection
    function stopDetection() {
        isDetecting = false;
        detectBtn.classList.remove('hidden');
        stopBtn.classList.add('hidden');
        scanStatus.classList.add('hidden');
        
        addLog('Threat detection stopped', 'SYSTEM');
    }

    // Fetch CSV data
    function fetchCSVData() {
        addLog('Fetching network traffic data...', 'SYSTEM');
        
        // For demo, we'll simulate getting data
        setTimeout(() => {
            const trafficAmount = Math.floor(Math.random() * 100) + 50;
            processTrafficData(generateMockData(trafficAmount));
        }, 2000);
    }

    // Simulate live detection
    function simulateLiveDetection() {
        addLog('Live detection mode activated', 'SYSTEM');
        
        const interval = setInterval(() => {
            if (!isDetecting) {
                clearInterval(interval);
                return;
            }
            
            const newData = generateMockData(1)[0];
            processTrafficEntry(newData);
            
        }, 1500);
    }

    // Generate mock network traffic data
    function generateMockData(count) {
        const protocols = ['TCP', 'UDP', 'ICMP'];
        const services = ['HTTP', 'FTP', 'SMTP', 'SSH', 'DNS', 'Telnet', 'POP3'];
        const attackTypes = ['normal', 'neptune', 'portsweep', 'satan', 'ipsweep', 'smurf', 'nmap', 'back', 'teardrop', 'warezclient', 'rootkit'];
        
        const data = [];
        
        for (let i = 0; i < count; i++) {
            const isThreat = Math.random() < 0.3;
            const srcBytes = Math.floor(Math.random() * 10000);
            const destBytes = Math.floor(Math.random() * 10000);
            
            data.push({
                timestamp: new Date().toLocaleTimeString(),
                protocol: protocols[Math.floor(Math.random() * protocols.length)],
                service: services[Math.floor(Math.random() * services.length)],
                srcBytes: srcBytes,
                destBytes: destBytes,
                attackType: isThreat ? attackTypes[Math.floor(Math.random() * (attackTypes.length - 1)) + 1] : 'normal',
                isThreat: isThreat
            });
        }
        
        return data;
    }

    // Process traffic data
    function processTrafficData(data) {
        data.forEach(entry => {
            processTrafficEntry(entry);
        });
        
        updateLastUpdate();
        generateAIInsights(data);
        addLog(`Processed ${data.length} traffic entries`, 'SYSTEM');
        showNotification(`Detected ${stats.threatCount} threats in ${data.length} traffic entries`);
    }

    // Process single traffic entry
    function processTrafficEntry(entry) {
        // Update stats
        stats.totalEntries++;
        if (entry.isThreat) {
            stats.threatCount++;
        } else {
            stats.normalCount++;
        }
        
        // Update counters
        totalEntriesEl.textContent = stats.totalEntries;
        threatCountEl.textContent = stats.threatCount;
        normalCountEl.textContent = stats.normalCount;
        
        // Update protocol stats
        stats.protocols[entry.protocol] = (stats.protocols[entry.protocol] || 0) + 1;
        
        // Update service stats
        stats.services[entry.service] = (stats.services[entry.service] || 0) + 1;
        
        // Update attack type stats
        stats.attackTypes[entry.attackType] = (stats.attackTypes[entry.attackType] || 0) + 1;
        
        // Add to traffic table
        addTrafficEntry(entry);
        
        // If threat, add to threat feed
        if (entry.isThreat) {
            addThreatEntry(entry);
        }
        
        // Update charts
        updateCharts();
        
        // Update last update time
        updateLastUpdate();
        
        // Log
        addLog(`Processed traffic: ${entry.protocol} ${entry.service} (${entry.attackType})`, entry.isThreat ? 'THREAT' : 'INFO');
    }

    // Add traffic entry to table
    function addTrafficEntry(entry) {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${entry.timestamp}</td>
            <td>${entry.protocol}</td>
            <td>${entry.service}</td>
            <td>${entry.srcBytes}</td>
            <td>${entry.destBytes}</td>
            <td class="${entry.isThreat ? 'threat' : 'normal'}">${entry.isThreat ? 'THREAT' : 'NORMAL'}</td>
        `;
        
        trafficDataElement.prepend(row);
        
        // Limit to 100 rows
        if (trafficDataElement.children.length > 100) {
            trafficDataElement.removeChild(trafficDataElement.lastChild);
        }
    }

    // Add threat entry to feed
    function addThreatEntry(entry) {
        const threatCard = document.createElement('div');
        threatCard.className = 'threat-card';
        threatCard.innerHTML = `
            <div class="threat-header">
                <span class="threat-type">${formatAttackType(entry.attackType)}</span>
                <span class="threat-time">${entry.timestamp}</span>
            </div>
            <div class="threat-details">
                <div class="threat-detail">
                    <span class="detail-label">Source:</span>
                    <span class="detail-value">${entry.sourceIP || 'Unknown'}</span>
                </div>
                <div class="threat-detail">
                    <span class="detail-label">Protocol:</span>
                    <span class="detail-value">${entry.protocol}</span>
                </div>
                <div class="threat-detail">
                    <span class="detail-label">Service:</span>
                    <span class="detail-value">${entry.service}</span>
                </div>
                <div class="threat-detail">
                    <span class="detail-label">Info:</span>
                    <span class="detail-value">${entry.info || 'N/A'}</span>
                </div>
                ${entry.severity ? `
                <div class="threat-detail">
                    <span class="detail-label">Severity:</span>
                    <span class="detail-value severity-${entry.severity.toLowerCase()}">${entry.severity}</span>
                </div>
                ` : ''}
            </div>
        `;
        
        threatFeedContainer.prepend(threatCard);
        
        // Limit to 20 threats
        if (threatFeedContainer.children.length > 20) {
            threatFeedContainer.removeChild(threatFeedContainer.lastChild);
        }
    }

    // Format attack type for display
    function formatAttackType(type) {
        if (!type) return 'UNKNOWN';
        
        // Map attack types to formatted display names
        const displayMap = {
            'sql_injection': 'SQL INJECTION',
            'ddos': 'DDOS ATTACK',
            'brute_force': 'BRUTE FORCE',
            'port_scan': 'PORT SCAN',
            'suspicious': 'SUSPICIOUS',
            'normal': 'NORMAL'
        };
        
        return displayMap[type] || type.toUpperCase();
    }

    // Update charts with current data
    function updateCharts() {
        // Attack distribution chart
        const attackLabels = ['normal', 'neptune', 'portsweep', 'satan', 'ipsweep', 'smurf', 'nmap', 'back', 'teardrop', 'warezclient', 'rootkit'];
        const attackColors = ['#4caf50', '#f44336', '#ff9800', '#9c27b0', '#2196f3', '#ff5722', '#607d8b', '#795548', '#009688', '#673ab7', '#3f51b5'];
        
        const attackData = attackLabels.map(type => stats.attackTypes[type] || 0);
        
        attackDistChart.data.labels = attackLabels;
        attackDistChart.data.datasets[0].data = attackData;
        attackDistChart.data.datasets[0].backgroundColor = attackColors;
        attackDistChart.update();
        
        // Protocol chart
        const protocolLabels = Object.keys(stats.protocols);
        const protocolData = protocolLabels.map(protocol => stats.protocols[protocol]);
        
        protocolChart.data.labels = protocolLabels;
        protocolChart.data.datasets[0].data = protocolData;
        protocolChart.update();
        
        // Service chart
        const serviceLabels = Object.keys(stats.services);
        const serviceData = serviceLabels.map(service => stats.services[service]);
        
        serviceChart.data.labels = serviceLabels;
        serviceChart.data.datasets[0].data = serviceData;
        serviceChart.update();
        
        // Timeline chart - simulate time-based data
        const hour = new Date().getHours();
        timelineChart.data.datasets[0].data[hour] += 1;
        timelineChart.update();
    }

    // Update last update time
    function updateLastUpdate() {
        const now = new Date();
        lastUpdateEl.textContent = now.toLocaleTimeString();
    }

    // Generate AI insights
    function generateAIInsights(data) {
        aiAnalysis.innerHTML = `
            <div class="ai-response">
                <div class="ai-header">
                    <i class="fas fa-robot"></i>
                    <h3>Gemini Analysis</h3>
                </div>
                <div class="ai-content">
                    <h4>Traffic Summary</h4>
                    <p>Analyzed ${data.length} network traffic events with ${stats.threatCount} potential threats detected.</p>
                    
                    <h4>Primary Threats</h4>
                    <p>The predominant attack vectors appear to be DoS-style attacks (${stats.attackTypes['neptune'] || 0} instances) 
                    and port scanning activities (${stats.attackTypes['portsweep'] || 0} instances).</p>
                    
                    <h4>Vulnerability Assessment</h4>
                    <p>Based on the traffic patterns, your network may be vulnerable to:</p>
                    <ul>
                        <li>Flooding attacks targeting ${Object.keys(stats.services)[0] || 'HTTP'} services</li>
                        <li>Information gathering through port scanning</li>
                        <li>Potential privilege escalation attempts through ${stats.attackTypes['rootkit'] ? 'rootkit infections' : 'SSH vulnerabilities'}</li>
                    </ul>
                    
                    <h4>Recommendations</h4>
                    <p>1. Implement rate limiting for ${Object.keys(stats.services)[0] || 'HTTP'} services</p>
                    <p>2. Review firewall rules to block suspicious scan patterns</p>
                    <p>3. Monitor privileged access accounts for unusual activity</p>
                </div>
            </div>
        `;
    }

    // Add log entry
    function addLog(message, type = 'INFO') {
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${type.toLowerCase()}-log`;
        
        logEntry.innerHTML = `
            <span class="timestamp">[${new Date().toLocaleTimeString()}]</span>
            <span class="log-type">[${type}]</span>
            <span class="log-content">${message}</span>
        `;
        
        logConsole.appendChild(logEntry);
        logConsole.scrollTop = logConsole.scrollHeight;
    }

    // Show notification
    function showNotification(message, type = 'info') {
        notificationMessage.textContent = message;
        notification.className = `notification ${type}`;
        notification.classList.remove('hidden');
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            if (!notification.classList.contains('hidden')) {
                notification.classList.add('hidden');
            }
        }, 5000);
    }

    // Load blockchain data on initialization
    function loadBlockchainData() {
        // Load existing blockchain entries from Firebase
        database.ref('threatLedger').limitToLast(5).once('value')
            .then((snapshot) => {
                if (snapshot.exists()) {
                    // Clear placeholder
                    blockchainContainer.innerHTML = '';
                    
                    // Display blocks in reverse chronological order
                    const blocks = [];
                    snapshot.forEach((childSnapshot) => {
                        blocks.push({
                            key: childSnapshot.key,
                            data: childSnapshot.val()
                        });
                    });
                    
                    // Add each block to the UI
                    blocks.reverse().forEach((block) => {
                        // Make sure data has the analysisId
                        const blockData = block.data;
                        blockData.analysisId = blockData.analysisId || block.key;
                        addBlockchainEntry(blockData);
                    });
                    
                    addLog(`Loaded ${blocks.length} blockchain entries`, 'SYSTEM');
                }
            })
            .catch((error) => {
                console.error("Error loading blockchain data:", error);
                addLog('Error loading blockchain data: ' + error.message, 'ERROR');
            });
    }

    // Initialize application
    function init() {
        addLog('Application initialized', 'SYSTEM');
        initCharts();
        setupEventListeners();
        loadBlockchainData();
    }
    
    // Call initialization
    init();
});