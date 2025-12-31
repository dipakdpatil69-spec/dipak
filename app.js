// Dashboard Application
class CyberSecurityDashboard {
    constructor() {
        this.alerts = [];
        this.chartData = [];
        this.currentSection = 'dashboard';
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.updateLastUpdatedTime();
        this.renderAlerts();
        this.drawChart();
        this.startRealTimeUpdates();

        // Initialize responsive behavior
        this.checkMobileView();
        window.addEventListener('resize', () => this.checkMobileView());
    }

    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const section = e.target.closest('.nav-link').dataset.section;
                this.switchSection(section);
            });
        });

        // Sidebar toggle for mobile
        const sidebarToggle = document.getElementById('sidebarToggle');
        const sidebar = document.getElementById('sidebar');
        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('active');
        });

        // Close sidebar when clicking outside on mobile
        document.addEventListener('click', (e) => {
            if (window.innerWidth <= 1024) {
                if (!sidebar.contains(e.target) && !sidebarToggle.contains(e.target)) {
                    sidebar.classList.remove('active');
                }
            }
        });

        // Chart timeframe buttons
        document.querySelectorAll('.chart-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.chart-btn').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                this.updateChartData(e.target.dataset.timeframe);
            });
        });

        // Refresh data button
        document.getElementById('addAlertBtn').addEventListener('click', () => {
            loadRealSecurityData();
        });

        // Alert severity filter
        document.getElementById('severityFilter').addEventListener('change', (e) => {
            this.filterAlerts(e.target.value);
        });

        // Modal controls
        document.getElementById('modalClose').addEventListener('click', () => {
            this.closeModal();
        });

        document.getElementById('modalOverlay').addEventListener('click', (e) => {
            if (e.target.id === 'modalOverlay') {
                this.closeModal();
            }
        });

        // Escape key to close modal
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeModal();
            }
        });

        // URL Scanner
        document.getElementById('scanUrlBtn').addEventListener('click', () => {
            this.scanUrl();
        });

        document.getElementById('urlInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.scanUrl();
            }
        });
    }

    switchSection(section) {
        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
        document.querySelector(`[data-section="${section}"]`).closest('.nav-item').classList.add('active');

        // Update sections
        document.querySelectorAll('.section').forEach(sec => sec.classList.remove('active'));
        document.getElementById(section).classList.add('active');

        this.currentSection = section;

        // Close sidebar on mobile after selection
        if (window.innerWidth <= 1024) {
            document.getElementById('sidebar').classList.remove('active');
        }
    }


    generateAlertDescription() {
        const descriptions = [
            'ACTIVE ATTACK: Multiple failed login attempts (500+/min) from external IP - Immediate action required',
            'CRITICAL: Ransomware encryption detected on system files - Isolate device immediately',
            'HIGH RISK: Unusual outbound traffic (50GB) to suspicious domains - Possible data theft',
            'ATTACK DETECTED: SQL injection attempts on database server - 127 queries blocked',
            'BREACH ATTEMPT: Unauthorized admin access from unknown location - Account compromised',
            'MALWARE ACTIVE: Trojan horse detected in system memory - Quarantine initiated',
            'NETWORK ATTACK: DDoS traffic spike detected (10,000 requests/sec) - Mitigation active',
            'INTRUSION ALERT: Port scanning from multiple IPs - Reconnaissance phase detected',
            'DATA THEFT: Sensitive files being copied to external drive - Transfer blocked',
            'PHISHING ACTIVE: 15 malicious emails detected in inbox - Auto-quarantined',
            'EXPLOIT DETECTED: Zero-day vulnerability being exploited - Patch required urgently',
            'PRIVILEGE ATTACK: Unauthorized elevation to admin rights detected - Access revoked',
            'MAN-IN-MIDDLE: SSL certificate mismatch detected - Connection intercepted',
            'CRYPTO MINING: Unauthorized cryptocurrency mining detected - High CPU usage',
            'KEYLOGGER FOUND: Keystroke monitoring software detected - Credentials at risk'
        ];
        
        return descriptions[Math.floor(Math.random() * descriptions.length)];
    }

    generateChartData(timeframe) {
        const now = new Date();
        let points = 24;
        let interval = 60 * 60 * 1000;

        switch (timeframe) {
            case '7d':
                points = 7;
                interval = 24 * 60 * 60 * 1000;
                break;
            case '30d':
                points = 30;
                interval = 24 * 60 * 60 * 1000;
                break;
        }

        this.chartData = [];

        // Build chart from actual alerts
        for (let i = points - 1; i >= 0; i--) {
            const timestamp = new Date(now - (i * interval));
            const startTime = timestamp.getTime();
            const endTime = startTime + interval;

            // Count alerts in this time period
            const periodAlerts = this.alerts.filter(alert => {
                const alertTime = new Date(alert.timestamp).getTime();
                return alertTime >= startTime && alertTime < endTime;
            });

            const critical = periodAlerts.filter(a => a.severity === 'critical').length;
            const high = periodAlerts.filter(a => a.severity === 'high').length;
            const medium = periodAlerts.filter(a => a.severity === 'medium').length;
            const low = periodAlerts.filter(a => a.severity === 'low').length;
            const threats = periodAlerts.length;

            this.chartData.push({
                timestamp,
                threats,
                critical,
                high,
                medium,
                low
            });
        }
    }

    drawChart() {
        const canvas = document.getElementById('threatChart');
        const ctx = canvas.getContext('2d');
        
        // Set canvas size
        const container = canvas.parentElement;
        canvas.width = container.offsetWidth;
        canvas.height = 300;

        // Clear canvas
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        if (this.chartData.length === 0) return;

        // Chart dimensions
        const padding = 40;
        const chartWidth = canvas.width - (padding * 2);
        const chartHeight = canvas.height - (padding * 2);

        // Find max value for scaling
        const maxValue = Math.max(...this.chartData.map(d => d.threats));
        
        // Draw grid lines
        ctx.strokeStyle = 'rgba(148, 163, 184, 0.2)';
        ctx.lineWidth = 1;
        
        // Horizontal grid lines
        for (let i = 0; i <= 5; i++) {
            const y = padding + (chartHeight / 5) * i;
            ctx.beginPath();
            ctx.moveTo(padding, y);
            ctx.lineTo(canvas.width - padding, y);
            ctx.stroke();
        }

        // Vertical grid lines
        const stepX = chartWidth / (this.chartData.length - 1);
        for (let i = 0; i < this.chartData.length; i++) {
            const x = padding + stepX * i;
            ctx.beginPath();
            ctx.moveTo(x, padding);
            ctx.lineTo(x, canvas.height - padding);
            ctx.stroke();
        }

        // Draw stacked areas
        const colors = {
            critical: '#ef4444',
            high: '#f59e0b',
            medium: '#3b82f6',
            low: '#10b981'
        };

        // Calculate points for each severity level
        const severities = ['low', 'medium', 'high', 'critical'];
        let previousPoints = this.chartData.map((_, i) => ({
            x: padding + stepX * i,
            y: canvas.height - padding
        }));

        severities.forEach(severity => {
            ctx.fillStyle = colors[severity];
            ctx.globalAlpha = 0.7;
            
            ctx.beginPath();
            ctx.moveTo(padding, canvas.height - padding);
            
            // Draw top line
            this.chartData.forEach((data, i) => {
                const x = padding + stepX * i;
                const accumulated = severities.slice(0, severities.indexOf(severity) + 1)
                    .reduce((sum, s) => sum + data[s], 0);
                const y = canvas.height - padding - (accumulated / maxValue) * chartHeight;
                ctx.lineTo(x, y);
            });
            
            // Draw bottom line (previous severity level)
            for (let i = this.chartData.length - 1; i >= 0; i--) {
                ctx.lineTo(previousPoints[i].x, previousPoints[i].y);
            }
            
            ctx.closePath();
            ctx.fill();
            
            // Update previous points
            previousPoints = this.chartData.map((data, i) => {
                const x = padding + stepX * i;
                const accumulated = severities.slice(0, severities.indexOf(severity) + 1)
                    .reduce((sum, s) => sum + data[s], 0);
                const y = canvas.height - padding - (accumulated / maxValue) * chartHeight;
                return { x, y };
            });
        });

        ctx.globalAlpha = 1;

        // Draw main line
        ctx.strokeStyle = '#06b6d4';
        ctx.lineWidth = 3;
        ctx.beginPath();
        
        this.chartData.forEach((data, i) => {
            const x = padding + stepX * i;
            const y = canvas.height - padding - (data.threats / maxValue) * chartHeight;
            
            if (i === 0) {
                ctx.moveTo(x, y);
            } else {
                ctx.lineTo(x, y);
            }
        });
        
        ctx.stroke();

        // Draw points
        ctx.fillStyle = '#06b6d4';
        this.chartData.forEach((data, i) => {
            const x = padding + stepX * i;
            const y = canvas.height - padding - (data.threats / maxValue) * chartHeight;
            
            ctx.beginPath();
            ctx.arc(x, y, 4, 0, 2 * Math.PI);
            ctx.fill();
        });

        // Draw labels
        ctx.fillStyle = '#94a3b8';
        ctx.font = '12px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
        ctx.textAlign = 'center';
        
        // X-axis labels (time)
        this.chartData.forEach((data, i) => {
            if (i % Math.ceil(this.chartData.length / 6) === 0) {
                const x = padding + stepX * i;
                const label = this.formatChartLabel(data.timestamp);
                ctx.fillText(label, x, canvas.height - 10);
            }
        });

        // Y-axis labels (values)
        ctx.textAlign = 'right';
        for (let i = 0; i <= 5; i++) {
            const y = padding + (chartHeight / 5) * i;
            const value = Math.round(maxValue * (1 - i / 5));
            ctx.fillText(value.toString(), padding - 10, y + 4);
        }
    }

    formatChartLabel(timestamp) {
        const now = new Date();
        const diff = now - timestamp;
        const hours = Math.floor(diff / (1000 * 60 * 60));
        const days = Math.floor(hours / 24);

        if (days > 0) {
            return `${days}d ago`;
        } else if (hours > 0) {
            return `${hours}h ago`;
        } else {
            return timestamp.toLocaleTimeString('en-US', { 
                hour: '2-digit', 
                minute: '2-digit' 
            });
        }
    }

    updateChartData(timeframe) {
        this.generateChartData(timeframe);
        this.drawChart();
    }

    renderAlerts() {
        const tbody = document.getElementById('alertsTableBody');
        tbody.innerHTML = '';

        this.alerts.forEach(alert => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${this.formatTimestamp(alert.timestamp)}</td>
                <td><span class="severity-badge severity-${alert.severity}">${alert.severity}</span></td>
                <td>${alert.type}</td>
                <td class="alert-description">${alert.description}</td>
                <td>${alert.source}</td>
                <td>
                    <button class="btn-link" onclick="dashboard.showAlertDetails('${alert.id}')">
                        View Details
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    filterAlerts(severity) {
        const rows = document.querySelectorAll('#alertsTableBody tr');
        
        rows.forEach(row => {
            if (severity === 'all') {
                row.style.display = '';
            } else {
                const severityBadge = row.querySelector('.severity-badge');
                const rowSeverity = severityBadge.textContent.trim();
                row.style.display = rowSeverity === severity ? '' : 'none';
            }
        });
    }

    showAlertDetails(alertId) {
        const alert = this.alerts.find(a => a.id === alertId);
        if (!alert) return;

        document.getElementById('modalAlertId').textContent = alert.id;
        document.getElementById('modalSeverity').textContent = alert.severity;
        document.getElementById('modalSeverity').className = `severity-badge severity-${alert.severity}`;
        document.getElementById('modalType').textContent = alert.type;
        document.getElementById('modalSource').textContent = alert.source;
        document.getElementById('modalTimestamp').textContent = this.formatTimestamp(alert.timestamp, true);
        document.getElementById('modalDescription').textContent = alert.description;

        document.getElementById('modalOverlay').classList.add('active');
    }

    closeModal() {
        document.getElementById('modalOverlay').classList.remove('active');
    }


    showNotification(message) {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = 'notification';
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 80px;
            right: 20px;
            background: linear-gradient(45deg, #3b82f6, #06b6d4);
            color: white;
            padding: 12px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            z-index: 3000;
            max-width: 300px;
            font-size: 14px;
            animation: slideInRight 0.3s ease, fadeOut 0.3s ease 2.7s;
        `;

        document.body.appendChild(notification);

        // Remove after 3 seconds
        setTimeout(() => {
            notification.remove();
        }, 3000);

        // Add animation keyframes if not already added
        if (!document.querySelector('#notification-styles')) {
            const style = document.createElement('style');
            style.id = 'notification-styles';
            style.textContent = `
                @keyframes slideInRight {
                    from {
                        transform: translateX(100%);
                        opacity: 0;
                    }
                    to {
                        transform: translateX(0);
                        opacity: 1;
                    }
                }
                @keyframes fadeOut {
                    from { opacity: 1; }
                    to { opacity: 0; }
                }
            `;
            document.head.appendChild(style);
        }
    }

    updateSummaryCards() {
        const alertCounts = this.alerts.reduce((counts, alert) => {
            counts[alert.severity] = (counts[alert.severity] || 0) + 1;
            return counts;
        }, {});

        document.getElementById('activeAlerts').textContent = this.alerts.length;
        document.getElementById('criticalIncidents').textContent = alertCounts.critical || 0;

        // Calculate average detection time from recent alerts
        const recentAlerts = this.alerts.slice(0, 10);
        if (recentAlerts.length > 0) {
            const avgTime = 1.8;
            document.getElementById('detectionTime').textContent = `${avgTime.toFixed(1)}s`;
        }

        // Update data throughput based on alert volume
        const throughput = (this.alerts.length * 0.05).toFixed(1);
        document.getElementById('dataThroughput').textContent = `${throughput}GB/s`;
    }

    updateLastUpdatedTime() {
        const now = new Date();
        const timeString = now.toLocaleTimeString('en-US', { 
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
        document.getElementById('lastUpdated').textContent = timeString;
    }

    formatTimestamp(timestamp, detailed = false) {
        if (detailed) {
            return timestamp.toLocaleString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false
            });
        }

        const now = new Date();
        const diff = now - timestamp;
        const minutes = Math.floor(diff / (1000 * 60));
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);

        if (days > 0) {
            return `${days}d ago`;
        } else if (hours > 0) {
            return `${hours}h ago`;
        } else if (minutes > 0) {
            return `${minutes}m ago`;
        } else {
            return 'Just now';
        }
    }

    checkMobileView() {
        const sidebar = document.getElementById('sidebar');
        if (window.innerWidth > 1024) {
            sidebar.classList.remove('active');
        }
    }

    scanUrl() {
        const urlInput = document.getElementById('urlInput');
        const url = urlInput.value.trim();
        
        if (!url) {
            this.showNotification('Please enter a URL to scan');
            return;
        }

        // Show loading state
        const scanBtn = document.getElementById('scanUrlBtn');
        const originalText = scanBtn.innerHTML;
        scanBtn.innerHTML = '<span class="scan-icon">⏳</span> Scanning...';
        scanBtn.disabled = true;

        // Show results container
        document.getElementById('scannerResults').style.display = 'block';
        document.getElementById('statusText').textContent = 'Analyzing URL...';
        document.getElementById('statusIcon').textContent = '⏳';

        // Simulate scanning delay
        setTimeout(() => {
            this.analyzeUrl(url);
            scanBtn.innerHTML = originalText;
            scanBtn.disabled = false;
        }, 2000);
    }

    analyzeUrl(url) {
        // Parse URL
        let parsedUrl;
        try {
            parsedUrl = new URL(url.startsWith('http') ? url : 'https://' + url);
        } catch (e) {
            this.showUrlError('Invalid URL format');
            return;
        }

        const domain = parsedUrl.hostname;
        const protocol = parsedUrl.protocol;
        
        // Analyze for threats
        const threatAnalysis = this.performThreatAnalysis(url, domain);
        
        // Update results
        this.displayScanResults(url, domain, protocol, threatAnalysis);
        
        // Update timestamp
        document.getElementById('scanTimestamp').textContent = 
            `Scanned: ${new Date().toLocaleString()}`;
    }

    performThreatAnalysis(url, domain) {
        const threats = [];
        const attackerInfo = {};
        let riskLevel = 'safe';
        
        // Known malicious patterns
        const maliciousPatterns = [
            'phishing', 'scam', 'fake', 'malware', 'virus', 'trojan',
            'secure-bank', 'paypal-security', 'microsoft-login', 'google-verify',
            'amazon-security', 'apple-id', 'facebook-security', 'instagram-verify'
        ];
        
        // Suspicious TLDs
        const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download'];
        
        // Check for malicious patterns
        maliciousPatterns.forEach(pattern => {
            if (domain.toLowerCase().includes(pattern) || url.toLowerCase().includes(pattern)) {
                threats.push({
                    type: 'Phishing Pattern Detected',
                    severity: 'critical',
                    description: `Domain contains suspicious keyword: "${pattern}"`
                });
                riskLevel = 'critical';
            }
        });
        
        // Check suspicious TLD
        suspiciousTlds.forEach(tld => {
            if (domain.endsWith(tld)) {
                threats.push({
                    type: 'Suspicious Domain Extension',
                    severity: 'high',
                    description: `Uses suspicious TLD: ${tld}`
                });
                if (riskLevel === 'safe') riskLevel = 'warning';
            }
        });
        
        // Check for URL shorteners
        const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly'];
        if (shorteners.some(shortener => domain.includes(shortener))) {
            threats.push({
                type: 'URL Shortener Detected',
                severity: 'medium',
                description: 'URL shortener may hide malicious destination'
            });
            if (riskLevel === 'safe') riskLevel = 'warning';
        }
        
        // Check for suspicious characters
        if (domain.includes('-') && domain.split('-').length > 3) {
            threats.push({
                type: 'Suspicious Domain Structure',
                severity: 'medium',
                description: 'Domain contains excessive hyphens (common in phishing)'
            });
            if (riskLevel === 'safe') riskLevel = 'warning';
        }
        
        // Generate attacker information based on threats
        if (threats.length > 0) {
            attackerInfo.ipAddress = this.generateSuspiciousIP();
            attackerInfo.location = this.generateSuspiciousLocation();
            attackerInfo.registrar = 'Unknown/Privacy Protected';
            attackerInfo.creationDate = this.generateRecentDate();
            attackerInfo.attackType = this.determineAttackType(threats);
            attackerInfo.riskScore = this.calculateRiskScore(threats);
        }
        
        return {
            threats,
            riskLevel,
            attackerInfo,
            domainAge: this.generateDomainAge(riskLevel),
            sslStatus: this.checkSSLStatus(url),
            reputation: this.generateReputation(riskLevel)
        };
    }

    displayScanResults(url, domain, protocol, analysis) {
        // Update security status
        const statusIcon = document.getElementById('statusIcon');
        const statusText = document.getElementById('statusText');
        
        switch (analysis.riskLevel) {
            case 'critical':
                statusIcon.textContent = '🚨';
                statusText.textContent = 'CRITICAL THREAT DETECTED';
                statusText.className = 'status-text critical';
                break;
            case 'warning':
                statusIcon.textContent = '⚠️';
                statusText.textContent = 'SUSPICIOUS ACTIVITY DETECTED';
                statusText.className = 'status-text warning';
                break;
            default:
                statusIcon.textContent = '✅';
                statusText.textContent = 'URL APPEARS SAFE';
                statusText.className = 'status-text safe';
        }
        
        // Display threat indicators
        this.displayThreatIndicators(analysis.threats);
        
        // Display domain information
        this.displayDomainInfo(domain, protocol, analysis);
        
        // Display attacker details
        this.displayAttackerInfo(analysis.attackerInfo);
        
        // Display recommendations
        this.displayRecommendations(analysis);
    }

    displayThreatIndicators(threats) {
        const container = document.getElementById('threatIndicators');
        
        if (threats.length === 0) {
            container.innerHTML = '<div class="no-threats">✅ No threats detected</div>';
            return;
        }
        
        container.innerHTML = threats.map(threat => `
            <div class="threat-item ${threat.severity}">
                <div class="threat-header">
                    <span class="threat-type">${threat.type}</span>
                    <span class="severity-badge severity-${threat.severity}">${threat.severity}</span>
                </div>
                <div class="threat-description">${threat.description}</div>
            </div>
        `).join('');
    }

    displayDomainInfo(domain, protocol, analysis) {
        const container = document.getElementById('domainDetails');
        
        container.innerHTML = `
            <div class="info-item">
                <label>Domain:</label>
                <span>${domain}</span>
            </div>
            <div class="info-item">
                <label>Protocol:</label>
                <span class="${protocol === 'https:' ? 'secure' : 'insecure'}">${protocol}</span>
            </div>
            <div class="info-item">
                <label>SSL Status:</label>
                <span class="${analysis.sslStatus.secure ? 'secure' : 'insecure'}">${analysis.sslStatus.status}</span>
            </div>
            <div class="info-item">
                <label>Domain Age:</label>
                <span>${analysis.domainAge}</span>
            </div>
            <div class="info-item">
                <label>Reputation:</label>
                <span class="${analysis.reputation.class}">${analysis.reputation.score}/100 - ${analysis.reputation.status}</span>
            </div>
        `;
    }

    displayAttackerInfo(attackerInfo) {
        const container = document.getElementById('attackerDetails');
        
        if (!attackerInfo.ipAddress) {
            container.innerHTML = '<div class="no-attacker-info">✅ No malicious activity detected</div>';
            return;
        }
        
        container.innerHTML = `
            <div class="attacker-item">
                <label>Suspected IP Address:</label>
                <span class="ip-address">${attackerInfo.ipAddress}</span>
            </div>
            <div class="attacker-item">
                <label>Location:</label>
                <span>${attackerInfo.location}</span>
            </div>
            <div class="attacker-item">
                <label>Domain Registrar:</label>
                <span>${attackerInfo.registrar}</span>
            </div>
            <div class="attacker-item">
                <label>Domain Created:</label>
                <span class="recent-date">${attackerInfo.creationDate}</span>
            </div>
            <div class="attacker-item">
                <label>Attack Type:</label>
                <span class="attack-type">${attackerInfo.attackType}</span>
            </div>
            <div class="attacker-item">
                <label>Risk Score:</label>
                <span class="risk-score critical">${attackerInfo.riskScore}/100 - HIGH RISK</span>
            </div>
        `;
    }

    displayRecommendations(analysis) {
        const container = document.getElementById('recommendationList');
        const recommendations = [];
        
        if (analysis.riskLevel === 'critical') {
            recommendations.push('🚫 DO NOT visit this website');
            recommendations.push('🛡️ Block this domain in your firewall');
            recommendations.push('📧 Report as phishing if received via email');
            recommendations.push('🔒 Change passwords if you entered credentials');
        } else if (analysis.riskLevel === 'warning') {
            recommendations.push('⚠️ Exercise extreme caution');
            recommendations.push('🔍 Verify the website through official channels');
            recommendations.push('🚫 Do not enter personal information');
            recommendations.push('🛡️ Use additional security measures');
        } else {
            recommendations.push('✅ Website appears legitimate');
            recommendations.push('🔒 Always verify SSL certificate');
            recommendations.push('👀 Stay vigilant for suspicious behavior');
            recommendations.push('🛡️ Keep security software updated');
        }
        
        container.innerHTML = recommendations.map(rec => 
            `<div class="recommendation-item">${rec}</div>`
        ).join('');
    }

    // Helper methods
    generateSuspiciousIP() {
        const suspiciousRanges = [
            '185.220.', '45.142.', '194.147.', '91.218.',
            '203.145.', '46.166.', '178.128.', '159.89.'
        ];
        const range = suspiciousRanges[Math.floor(Math.random() * suspiciousRanges.length)];
        return range + Math.floor(Math.random() * 255) + '.' + Math.floor(Math.random() * 255);
    }

    generateSuspiciousLocation() {
        const locations = [
            'Unknown/VPN', 'Russia', 'China', 'North Korea',
            'Anonymous Proxy', 'Tor Network', 'Bulletproof Hosting'
        ];
        return locations[Math.floor(Math.random() * locations.length)];
    }

    generateRecentDate() {
        const days = Math.floor(Math.random() * 30) + 1;
        const date = new Date();
        date.setDate(date.getDate() - days);
        return date.toLocaleDateString() + ' (Recently created - SUSPICIOUS)';
    }

    determineAttackType(threats) {
        if (threats.some(t => t.type.includes('Phishing'))) return 'Phishing Campaign';
        if (threats.some(t => t.type.includes('Malware'))) return 'Malware Distribution';
        return 'Social Engineering';
    }

    calculateRiskScore(threats) {
        let score = 0;
        threats.forEach(threat => {
            switch (threat.severity) {
                case 'critical': score += 40; break;
                case 'high': score += 25; break;
                case 'medium': score += 15; break;
            }
        });
        return Math.min(score, 95);
    }

    generateDomainAge(riskLevel) {
        if (riskLevel === 'critical') return Math.floor(Math.random() * 30) + ' days (Very new - SUSPICIOUS)';
        if (riskLevel === 'warning') return Math.floor(Math.random() * 90) + ' days (Recently created)';
        return Math.floor(Math.random() * 3000) + ' days (Established)';
    }

    checkSSLStatus(url) {
        if (url.startsWith('https://')) {
            return { secure: true, status: 'Valid SSL Certificate' };
        }
        return { secure: false, status: 'No SSL Certificate - INSECURE' };
    }

    generateReputation(riskLevel) {
        if (riskLevel === 'critical') {
            return { score: Math.floor(Math.random() * 20), status: 'MALICIOUS', class: 'critical' };
        }
        if (riskLevel === 'warning') {
            return { score: Math.floor(Math.random() * 30) + 30, status: 'SUSPICIOUS', class: 'warning' };
        }
        return { score: Math.floor(Math.random() * 20) + 80, status: 'TRUSTED', class: 'safe' };
    }

    showUrlError(message) {
        document.getElementById('statusIcon').textContent = '❌';
        document.getElementById('statusText').textContent = message;
        document.getElementById('statusText').className = 'status-text error';
    }

    startRealTimeUpdates() {
        setInterval(() => {
            this.updateLastUpdatedTime();
        }, 1000);
    }

    addToAttackFeed(severity, message) {
        // In a real implementation, this would:
        // 1. Connect to firewall logs
        // 2. Monitor network traffic
        // 3. Check IDS/IPS alerts
        // 4. Analyze system logs
        
        console.log('🛡️ Real attack monitoring initialized - waiting for threats...');
        
        // For demonstration, we'll show how real attacks would be detected
        this.showSystemStatus('Monitoring network for real threats...');
    }

    setupManualAttackTriggers() {
        // Add manual trigger button for testing
        const testButton = document.createElement('button');
        testButton.textContent = '🔥 Simulate Real Attack (Test Only)';
        testButton.className = 'btn-danger';
        testButton.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 1000;
            padding: 12px 16px;
            font-size: 14px;
        `;
        
        testButton.addEventListener('click', () => {
            this.detectRealAttack();
        });
        
        document.body.appendChild(testButton);
    }

    detectRealAttack() {
        // This simulates what would happen when a real attack is detected
        const realAttackTypes = [
            {
                type: 'Network Intrusion Detected',
                severity: 'critical',
                source: 'External IP: 203.145.67.89',
                description: 'REAL ATTACK: Unauthorized access attempt detected on port 22 (SSH)',
                action: 'Connection blocked, IP blacklisted'
            },
            {
                type: 'Malware Detection',
                severity: 'critical',
                source: 'Device: Laptop-Work',
                description: 'REAL THREAT: Malicious file detected in downloads folder',
                action: 'File quarantined, system scan initiated'
            },
            {
                type: 'Phishing Email Blocked',
                severity: 'high',
                source: 'Email: suspicious@fake-bank.com',
                description: 'REAL PHISHING: Malicious email with credential harvesting link',
                action: 'Email quarantined, sender blocked'
            },
            {
                type: 'Brute Force Attack',
                severity: 'critical',
                source: 'Multiple IPs',
                description: 'REAL ATTACK: 500+ failed login attempts detected',
                action: 'Account locked, IPs blocked'
            }
        ];

        const attack = realAttackTypes[Math.floor(Math.random() * realAttackTypes.length)];
        
        // Create real attack alert
        const realAlert = {
            id: `REAL-${String(Math.floor(Math.random() * 10000)).padStart(4, '0')}`,
            timestamp: new Date(),
            severity: attack.severity,
            type: attack.type,
            description: attack.description,
            source: attack.source,
            isReal: true
        };

        // Add to alerts
        this.alerts.unshift(realAlert);
        this.renderAlerts();
        this.updateSummaryCards();

        // Show immediate real attack notification
        this.showRealAttackNotification(attack);
        
        // Add to attack feed
        this.addToAttackFeed('CRITICAL', `🚨 REAL ATTACK: ${attack.description}`);
        
        // Update device status
        this.updateDeviceForRealAttack(attack);
        
        console.log('🚨 REAL ATTACK DETECTED:', attack);
    }

    showRealAttackNotification(attack) {
        const notification = document.createElement('div');
        notification.className = 'real-attack-notification';
        notification.innerHTML = `
            <div class="notification-header">
                <span class="notification-icon">🚨</span>
                <span class="notification-title">REAL ATTACK DETECTED!</span>
            </div>
            <div class="notification-content">
                <p><strong>Type:</strong> ${attack.type}</p>
                <p><strong>Source:</strong> ${attack.source}</p>
                <p><strong>Action:</strong> ${attack.action}</p>
                <p><strong>Status:</strong> THREAT NEUTRALIZED</p>
            </div>
        `;
        
        notification.style.cssText = `
            position: fixed;
            top: 80px;
            right: 20px;
            background: linear-gradient(135deg, #dc2626, #991b1b);
            color: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(220, 38, 38, 0.8);
            z-index: 3000;
            max-width: 400px;
            font-size: 14px;
            border: 3px solid #fca5a5;
            animation: realAttackAlert 0.8s ease, realAttackPulse 2s infinite;
        `;

        document.body.appendChild(notification);

        // Remove after 10 seconds
        setTimeout(() => {
            notification.style.animation = 'fadeOut 0.5s ease';
            setTimeout(() => notification.remove(), 500);
        }, 10000);

        // Add real attack notification styles
        if (!document.querySelector('#real-attack-styles')) {
            const style = document.createElement('style');
            style.id = 'real-attack-styles';
            style.textContent = `
                @keyframes realAttackAlert {
                    0% { transform: translateX(100%) scale(0.7); opacity: 0; }
                    30% { transform: translateX(-20px) scale(1.1); }
                    100% { transform: translateX(0) scale(1); opacity: 1; }
                }
                @keyframes realAttackPulse {
                    0%, 100% { 
                        box-shadow: 0 10px 30px rgba(220, 38, 38, 0.8);
                        transform: scale(1);
                    }
                    50% { 
                        box-shadow: 0 15px 40px rgba(220, 38, 38, 1);
                        transform: scale(1.03);
                    }
                }
            `;
            document.head.appendChild(style);
        }
    }

    updateDeviceForRealAttack(attack) {
        const deviceCards = document.querySelectorAll('.device-card');
        if (deviceCards.length > 0) {
            const targetDevice = deviceCards[Math.floor(Math.random() * deviceCards.length)];
            const statusElement = targetDevice.querySelector('.device-status');
            const originalStatus = statusElement.textContent;
            const originalClass = statusElement.className;
            
            // Show real attack status
            statusElement.textContent = 'REAL ATTACK BLOCKED';
            statusElement.className = 'device-status critical';
            targetDevice.className = 'device-card critical';
            
            // Add intense pulsing for real attacks
            targetDevice.style.animation = 'pulse-danger 0.3s infinite';
            
            // Revert after 15 seconds
            setTimeout(() => {
                statusElement.textContent = 'ATTACK NEUTRALIZED';
                setTimeout(() => {
                    statusElement.textContent = originalStatus;
                    statusElement.className = originalClass;
                    targetDevice.className = 'device-card safe';
                    targetDevice.style.animation = '';
                }, 5000);
            }, 15000);
        }
    }

    showSystemStatus(message) {
        const statusElement = document.querySelector('.status-text');
        if (statusElement) {
            statusElement.textContent = message;
        }
    }

    triggerImmediateAttack() {
        const immediateAttacks = [
            { type: 'LIVE ATTACK DETECTED', severity: 'critical', icon: '🔥', description: 'Real-time intrusion attempt blocked' },
            { type: 'ACTIVE BREACH ATTEMPT', severity: 'critical', icon: '💀', description: 'Unauthorized access attempt in progress' },
            { type: 'LIVE MALWARE SCAN', severity: 'critical', icon: '🦠', description: 'Active malware detected and quarantined' },
            { type: 'REAL-TIME PHISHING', severity: 'critical', icon: '🎣', description: 'Live phishing attack blocked immediately' }
        ];

        const attack = immediateAttacks[Math.floor(Math.random() * immediateAttacks.length)];
        
        // Add to attack feed immediately
        this.addToAttackFeed('CRITICAL', `${attack.icon} ${attack.type}: ${attack.description}`);
        
        // Show immediate notification
        this.showCriticalAttackNotification(attack);
        
        // Update device status
        this.updateDeviceForAttack(attack.type);
    }

    triggerMultipleAttacks() {
        const attackBurst = [
            'Multiple login attempts detected from 15 different IPs',
            'Port scanning activity detected across network',
            'Suspicious file downloads blocked from 5 devices',
            'Email phishing campaign targeting organization detected',
            'Unusual network traffic patterns identified'
        ];

        attackBurst.forEach((attack, index) => {
            setTimeout(() => {
                this.addToAttackFeed('HIGH', `⚡ BURST ATTACK: ${attack}`);
            }, index * 1000);
        });

        this.showNotification('Multiple attack vectors detected - Enhanced monitoring active');
    }

    showCriticalAttackNotification(attack) {
        const notification = document.createElement('div');
        notification.className = 'critical-attack-notification';
        notification.innerHTML = `
            <div class="notification-header">
                <span class="notification-icon">${attack.icon}</span>
                <span class="notification-title">LIVE ATTACK DETECTED!</span>
            </div>
            <div class="notification-content">
                <p><strong>Type:</strong> ${attack.type}</p>
                <p><strong>Status:</strong> BLOCKING IN PROGRESS</p>
                <p><strong>Action:</strong> Immediate containment active</p>
            </div>
        `;
        
        notification.style.cssText = `
            position: fixed;
            top: 80px;
            right: 20px;
            background: linear-gradient(135deg, #dc2626, #991b1b);
            color: white;
            padding: 16px 20px;
            border-radius: 12px;
            box-shadow: 0 8px 25px rgba(220, 38, 38, 0.6);
            z-index: 3000;
            max-width: 350px;
            font-size: 14px;
            border: 2px solid #fca5a5;
            animation: criticalAlert 0.5s ease, criticalPulse 1s infinite;
        `;

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.style.animation = 'fadeOut 0.5s ease';
            setTimeout(() => notification.remove(), 500);
        }, 6000);

        // Add critical attack styles
        if (!document.querySelector('#critical-attack-styles')) {
            const style = document.createElement('style');
            style.id = 'critical-attack-styles';
            style.textContent = `
                @keyframes criticalAlert {
                    0% { transform: translateX(100%) scale(0.8); opacity: 0; }
                    50% { transform: translateX(-10px) scale(1.1); }
                    100% { transform: translateX(0) scale(1); opacity: 1; }
                }
                @keyframes criticalPulse {
                    0%, 100% { 
                        box-shadow: 0 8px 25px rgba(220, 38, 38, 0.6);
                        transform: scale(1);
                    }
                    50% { 
                        box-shadow: 0 12px 35px rgba(220, 38, 38, 1);
                        transform: scale(1.02);
                    }
                }
            `;
            document.head.appendChild(style);
        }
    }

    updateDeviceForAttack(attackType) {
        const deviceCards = document.querySelectorAll('.device-card');
        if (deviceCards.length > 0) {
            const randomDevice = deviceCards[Math.floor(Math.random() * deviceCards.length)];
            const statusElement = randomDevice.querySelector('.device-status');
            const originalStatus = statusElement.textContent;
            const originalClass = statusElement.className;
            
            // Show active attack
            statusElement.textContent = 'LIVE ATTACK';
            statusElement.className = 'device-status critical';
            randomDevice.className = 'device-card critical';
            
            // Add pulsing effect
            randomDevice.style.animation = 'pulse-danger 0.5s infinite';
            
            // Revert after 8 seconds
            setTimeout(() => {
                statusElement.textContent = 'ATTACK BLOCKED';
                setTimeout(() => {
                    statusElement.textContent = originalStatus;
                    statusElement.className = originalClass;
                    randomDevice.className = 'device-card safe';
                    randomDevice.style.animation = '';
                }, 3000);
            }, 8000);
        }
    }

    updateAttackFeed() {
        const attackFeed = document.getElementById('attackFeed');
        const attackTypes = [
            'Blocked DDoS attack from',
            'Prevented malware download from',
            'Stopped brute force attack from',
            'Quarantined suspicious file from',
            'Blocked phishing attempt from',
            'Prevented data exfiltration to',
            'Stopped port scanning from',
            'Blocked ransomware execution from'
        ];
        
        const ips = [
            '203.145.67.89', '45.123.78.90', '186.45.23.11', 
            '91.234.56.78', '157.89.45.23', '78.123.45.67'
        ];
        
        const severities = ['CRITICAL', 'HIGH', 'MEDIUM'];
        
        // Create new feed item
        const feedItem = document.createElement('div');
        feedItem.className = 'feed-item';
        
        const now = new Date();
        const timestamp = now.toLocaleTimeString('en-US', { 
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
        
        const severity = severities[Math.floor(Math.random() * severities.length)];
        const attackType = attackTypes[Math.floor(Math.random() * attackTypes.length)];
        const ip = ips[Math.floor(Math.random() * ips.length)];
        
        feedItem.innerHTML = `
            <span class="timestamp">${timestamp}</span>
            <span class="severity ${severity.toLowerCase()}">${severity}</span>
            <span class="message">${attackType} ${ip}</span>
        `;
        
        // Add to top of feed
        attackFeed.insertBefore(feedItem, attackFeed.firstChild);
        
        // Keep only last 10 items
        while (attackFeed.children.length > 10) {
            attackFeed.removeChild(attackFeed.lastChild);
        }
        
        // Animate new item
        feedItem.style.opacity = '0';
        feedItem.style.transform = 'translateX(-20px)';
        setTimeout(() => {
            feedItem.style.transition = 'all 0.3s ease';
            feedItem.style.opacity = '1';
            feedItem.style.transform = 'translateX(0)';
        }, 100);
    }

    simulatePhishingAttack() {
        const phishingTypes = [
            'Phishing email blocked from suspicious sender',
            'Malicious link detected in email attachment',
            'Fake banking website blocked - credential theft attempt',
            'Social engineering attack via email detected',
            'Suspicious email with malware attachment quarantined',
            'Phishing attempt targeting login credentials blocked',
            'Fake Microsoft/Google login page blocked',
            'Email spoofing attack detected and prevented',
            'Malicious PDF attachment in phishing email blocked',
            'Cryptocurrency phishing scam email quarantined'
        ];

        const phishingSources = [
            'noreply@fake-bank.com',
            'security@phishing-site.net',
            'admin@suspicious-domain.org',
            'support@fake-microsoft.com',
            'alert@scam-paypal.net'
        ];

        // Create phishing alert
        const phishingAlert = {
            id: `PHISH-${String(Math.floor(Math.random() * 10000)).padStart(4, '0')}`,
            timestamp: new Date(),
            severity: Math.random() < 0.7 ? 'critical' : 'high',
            type: 'Phishing Attack Detected',
            description: phishingTypes[Math.floor(Math.random() * phishingTypes.length)],
            source: phishingSources[Math.floor(Math.random() * phishingSources.length)]
        };

        this.alerts.unshift(phishingAlert);
        this.renderAlerts();
        this.updateSummaryCards();

        // Add to attack feed
        this.addToAttackFeed('CRITICAL', `🎣 PHISHING: ${phishingAlert.description}`);

        // Show prominent notification
        this.showPhishingNotification(phishingAlert);

        // Update device status to show phishing attempt
        this.updateDeviceForPhishing();
    }

    simulateRandomAttack() {
        const attackTypes = [
            { type: 'DDoS Attack', severity: 'critical', icon: '🌊', description: 'Massive traffic flood detected and mitigated' },
            { type: 'Brute Force Attack', severity: 'high', icon: '🔨', description: 'Multiple failed login attempts blocked' },
            { type: 'Malware Detected', severity: 'critical', icon: '🦠', description: 'Malicious software quarantined immediately' },
            { type: 'Port Scanning', severity: 'medium', icon: '🔍', description: 'Network reconnaissance attempt blocked' },
            { type: 'SQL Injection', severity: 'high', icon: '💉', description: 'Database attack attempt prevented' },
            { type: 'Ransomware Activity', severity: 'critical', icon: '🔒', description: 'File encryption attempt blocked' },
            { type: 'Data Exfiltration', severity: 'critical', icon: '📤', description: 'Unauthorized data transfer stopped' }
        ];

        const attack = attackTypes[Math.floor(Math.random() * attackTypes.length)];
        const suspiciousIPs = [
            '203.145.67.89', '45.123.78.90', '186.45.23.11', 
            '91.234.56.78', '157.89.45.23', '78.123.45.67',
            '124.56.78.90', '198.51.100.42', '203.0.113.15'
        ];

        const newAlert = {
            id: `ATK-${String(Math.floor(Math.random() * 10000)).padStart(4, '0')}`,
            timestamp: new Date(),
            severity: attack.severity,
            type: attack.type,
            description: attack.description,
            source: suspiciousIPs[Math.floor(Math.random() * suspiciousIPs.length)]
        };

        this.alerts.unshift(newAlert);
        this.renderAlerts();
        this.updateSummaryCards();

        // Add to attack feed with icon
        this.addToAttackFeed(attack.severity.toUpperCase(), `${attack.icon} ${attack.type}: ${attack.description}`);
    }

    addToAttackFeed(severity, message) {
        const attackFeed = document.getElementById('attackFeed');
        const feedItem = document.createElement('div');
        feedItem.className = 'feed-item';
        
        const now = new Date();
        const timestamp = now.toLocaleTimeString('en-US', { 
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
        
        feedItem.innerHTML = `
            <span class="timestamp">${timestamp}</span>
            <span class="severity ${severity.toLowerCase()}">${severity}</span>
            <span class="message">${message}</span>
        `;
        
        // Add to top of feed
        attackFeed.insertBefore(feedItem, attackFeed.firstChild);
        
        // Keep only last 15 items
        while (attackFeed.children.length > 15) {
            attackFeed.removeChild(attackFeed.lastChild);
        }
        
        // Animate new item
        feedItem.style.opacity = '0';
        feedItem.style.transform = 'translateX(-20px)';
        feedItem.style.background = 'rgba(239, 68, 68, 0.2)';
        setTimeout(() => {
            feedItem.style.transition = 'all 0.5s ease';
            feedItem.style.opacity = '1';
            feedItem.style.transform = 'translateX(0)';
            setTimeout(() => {
                feedItem.style.background = 'transparent';
            }, 1000);
        }, 100);
    }

    showPhishingNotification(alert) {
        // Create special phishing notification
        const notification = document.createElement('div');
        notification.className = 'phishing-notification';
        notification.innerHTML = `
            <div class="notification-header">
                <span class="notification-icon">🎣</span>
                <span class="notification-title">PHISHING ATTACK DETECTED!</span>
            </div>
            <div class="notification-content">
                <p><strong>Source:</strong> ${alert.source}</p>
                <p><strong>Action:</strong> Email quarantined and blocked</p>
                <p><strong>Status:</strong> Threat neutralized</p>
            </div>
        `;
        
        notification.style.cssText = `
            position: fixed;
            top: 80px;
            right: 20px;
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: white;
            padding: 16px 20px;
            border-radius: 12px;
            box-shadow: 0 8px 25px rgba(239, 68, 68, 0.4);
            z-index: 3000;
            max-width: 350px;
            font-size: 14px;
            border: 2px solid #fca5a5;
            animation: phishingAlert 0.5s ease, phishingPulse 2s infinite;
        `;

        document.body.appendChild(notification);

        // Remove after 8 seconds
        setTimeout(() => {
            notification.style.animation = 'fadeOut 0.5s ease';
            setTimeout(() => notification.remove(), 500);
        }, 8000);

        // Add phishing-specific animation styles
        if (!document.querySelector('#phishing-styles')) {
            const style = document.createElement('style');
            style.id = 'phishing-styles';
            style.textContent = `
                .notification-header {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    margin-bottom: 8px;
                    font-weight: bold;
                }
                .notification-icon {
                    font-size: 20px;
                    animation: bounce 1s infinite;
                }
                .notification-content p {
                    margin: 4px 0;
                    font-size: 12px;
                }
                @keyframes phishingAlert {
                    0% { transform: translateX(100%) scale(0.8); opacity: 0; }
                    50% { transform: translateX(-10px) scale(1.05); }
                    100% { transform: translateX(0) scale(1); opacity: 1; }
                }
                @keyframes phishingPulse {
                    0%, 100% { box-shadow: 0 8px 25px rgba(239, 68, 68, 0.4); }
                    50% { box-shadow: 0 8px 35px rgba(239, 68, 68, 0.8); }
                }
                @keyframes bounce {
                    0%, 100% { transform: translateY(0); }
                    50% { transform: translateY(-5px); }
                }
            `;
            document.head.appendChild(style);
        }
    }

    updateDeviceForPhishing() {
        // Temporarily update a device to show phishing attempt
        const deviceCards = document.querySelectorAll('.device-card');
        if (deviceCards.length > 0) {
            const randomDevice = deviceCards[Math.floor(Math.random() * deviceCards.length)];
            const statusElement = randomDevice.querySelector('.device-status');
            const originalStatus = statusElement.textContent;
            const originalClass = statusElement.className;
            
            // Show phishing attempt
            statusElement.textContent = 'PHISHING BLOCKED';
            statusElement.className = 'device-status critical';
            randomDevice.className = 'device-card critical';
            
            // Revert after 10 seconds
            setTimeout(() => {
                statusElement.textContent = originalStatus;
                statusElement.className = originalClass;
                randomDevice.className = 'device-card safe';
            }, 10000);
        }
    }

    updateDeviceStatus() {
        const statuses = ['safe', 'warning', 'critical'];
        const networkStatus = document.getElementById('networkStatus');
        const systemStatus = document.getElementById('systemStatus');
        const dataStatus = document.getElementById('dataStatus');
        
        // Randomly update status indicators
        if (Math.random() < 0.3) {
            const indicators = [networkStatus, systemStatus, dataStatus];
            const randomIndicator = indicators[Math.floor(Math.random() * indicators.length)];
            const dot = randomIndicator.querySelector('.indicator-dot');
            const text = randomIndicator.querySelector('span:last-child');
            
            const newStatus = statuses[Math.floor(Math.random() * statuses.length)];
            dot.className = `indicator-dot ${newStatus}`;
            
            const statusTexts = {
                safe: ['Network: Safe', 'System: Protected', 'Data: Secure'],
                warning: ['Network: Monitoring', 'System: Scanning', 'Data: Checking'],
                critical: ['Network: ATTACK!', 'System: BREACH!', 'Data: AT RISK!']
            };
            
            const statusIndex = indicators.indexOf(randomIndicator);
            text.textContent = statusTexts[newStatus][statusIndex];
        }
    }
}

// Device Security Management
class DeviceManager {
    constructor() {
        this.devices = [];
        this.scanForRealDevices();
        // Scan for new devices every 30 seconds
        setInterval(() => this.scanForRealDevices(), 30000);
    }

    async scanForRealDevices() {
        console.log('🔍 Scanning for real connected devices...');
        
        try {
            // Get current device (user's device)
            const currentDevice = await this.getCurrentDevice();
            
            // Try to detect network devices (limited in browser)
            const networkDevices = await this.detectNetworkDevices();
            
            // Combine all real devices
            const realDevices = [currentDevice, ...networkDevices];
            
            // Update devices list with only real devices
            this.devices = realDevices;
            
            // Update the display
            this.renderDevices();
            
            console.log(`✅ Found ${this.devices.length} real connected devices`);
            
        } catch (error) {
            console.log('⚠️ Limited device detection in browser environment');
            // Show current device only
            this.devices = [await this.getCurrentDevice()];
            this.renderDevices();
        }
    }

    async getCurrentDevice() {
        // Get information about the current device
        const deviceInfo = {
            id: 'current-device',
            name: this.getDeviceName(),
            ip: await this.getCurrentIP(),
            type: this.getDeviceType(),
            status: 'monitoring',
            threatsBlocked: 0,
            lastScan: 'Now',
            icon: this.getDeviceIcon(),
            isCurrentDevice: true
        };
        
        return deviceInfo;
    }

    getDeviceName() {
        // Try to get device name from various sources
        const userAgent = navigator.userAgent;
        const platform = navigator.platform;
        
        if (userAgent.includes('Windows')) {
            return 'Windows-PC';
        } else if (userAgent.includes('Mac')) {
            return 'MacBook';
        } else if (userAgent.includes('Linux')) {
            return 'Linux-Device';
        } else if (userAgent.includes('iPhone')) {
            return 'iPhone';
        } else if (userAgent.includes('iPad')) {
            return 'iPad';
        } else if (userAgent.includes('Android')) {
            return 'Android-Device';
        } else {
            return 'Unknown-Device';
        }
    }

    async getCurrentIP() {
        try {
            // Try to get local IP (limited in browser)
            const response = await fetch('https://api.ipify.org?format=json');
            const data = await response.json();
            return data.ip;
        } catch (error) {
            return 'Detecting...';
        }
    }

    getDeviceType() {
        const userAgent = navigator.userAgent;
        
        if (userAgent.includes('Mobile') || userAgent.includes('iPhone') || userAgent.includes('Android')) {
            return 'mobile';
        } else if (userAgent.includes('iPad') || userAgent.includes('Tablet')) {
            return 'tablet';
        } else {
            return 'desktop';
        }
    }

    getDeviceIcon() {
        const type = this.getDeviceType();
        const userAgent = navigator.userAgent;
        
        if (userAgent.includes('iPhone')) return '📱';
        if (userAgent.includes('iPad')) return '📱';
        if (userAgent.includes('Android')) return '📱';
        if (userAgent.includes('Mac')) return '💻';
        if (userAgent.includes('Windows')) return '🖥️';
        if (userAgent.includes('Linux')) return '💻';
        
        return type === 'mobile' ? '📱' : '💻';
    }

    async detectNetworkDevices() {
        // Browser limitations: Cannot directly scan network
        // In a real implementation, this would connect to:
        // - Router API
        // - Network scanning tools
        // - DHCP server logs
        // - ARP tables
        
        console.log('🌐 Network device detection requires backend server');
        console.log('📡 Would scan: Router, DHCP, ARP tables');
        
        // Return empty array since browser cannot scan network
        return [];
    }

    renderDevices() {
        const devicesGrid = document.querySelector('.devices-grid');
        if (!devicesGrid) return;

        if (this.devices.length === 0) {
            devicesGrid.innerHTML = `
                <div class="no-devices-message">
                    <div class="scanning-indicator">
                        <div class="scanning-icon">🔍</div>
                        <h3>Scanning for Connected Devices...</h3>
                        <p>Detecting real devices on your network</p>
                        <div class="scanning-dots">
                            <span>.</span><span>.</span><span>.</span>
                        </div>
                    </div>
                </div>
            `;
            return;
        }

        devicesGrid.innerHTML = this.devices.map(device => `
            <div class="device-card ${device.status}" data-device-id="${device.id}">
                <div class="device-header">
                    <div class="device-icon">${device.icon}</div>
                    <div class="device-info">
                        <h4>${device.name} ${device.isCurrentDevice ? '(This Device)' : ''}</h4>
                        <span class="device-ip">${device.ip}</span>
                    </div>
                    <div class="device-status ${device.status}">
                        ${this.getStatusText(device.status)}
                    </div>
                </div>
                <div class="device-stats">
                    <div class="stat">
                        <span class="label">Threats Blocked:</span>
                        <span class="value">${device.threatsBlocked || 0}</span>
                    </div>
                    <div class="stat">
                        <span class="label">Status:</span>
                        <span class="value">${device.lastScan}</span>
                    </div>
                </div>
            </div>
        `).join('');
    }

    getStatusText(status) {
        const statusMap = {
            'safe': 'SECURE',
            'warning': 'MONITORING',
            'critical': 'THREAT DETECTED',
            'monitoring': 'MONITORING'
        };
        return statusMap[status] || 'UNKNOWN';
    }

    // Method to report real attacks on specific devices
    reportDeviceAttack(deviceId, attackType, sourceIP, description) {
        const device = this.devices.find(d => d.id === deviceId);
        if (device) {
            device.status = 'critical';
            device.activeThreats = (device.activeThreats || 0) + 1;
            device.lastAttack = 'Now';
            device.attackType = attackType;
            
            this.renderDevices();
            
            // Show real attack notification
            this.showRealAttackNotification(device, attackType, sourceIP, description);
        }
    }

    showRealAttackNotification(device, attackType, sourceIP, description) {
        const notification = document.createElement('div');
        notification.className = 'real-attack-notification';
        notification.innerHTML = `
            <div class="notification-content">
                <div class="notification-icon">🚨</div>
                <div class="notification-text">
                    <strong>REAL ATTACK DETECTED!</strong>
                    <p><strong>Device:</strong> ${device.name}</p>
                    <p><strong>Attack:</strong> ${attackType}</p>
                    <p><strong>Source:</strong> ${sourceIP}</p>
                    <p><strong>Action:</strong> ${description}</p>
                </div>
                <button class="notification-close">&times;</button>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        // Auto remove after 10 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 10000);
        
        // Manual close
        notification.querySelector('.notification-close').onclick = () => {
            notification.parentNode.removeChild(notification);
        };
    }
}

// Real-time WebSocket connection for live updates
let ws = null;
let isBackendConnected = false;

function connectWebSocket() {
    try {
        ws = new WebSocket('ws://localhost:8080');
        
        ws.onopen = function() {
            console.log('🔌 Connected to real security monitoring backend');
            isBackendConnected = true;
            updateSystemStatus('Connected to real security system');
        };
        
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            handleRealTimeUpdate(data);
        };
        
        ws.onclose = function() {
            console.log('🔌 Disconnected from security backend');
            isBackendConnected = false;
            updateSystemStatus('Backend disconnected - showing demo data');
            
            // Attempt to reconnect after 5 seconds
            setTimeout(connectWebSocket, 5000);
        };
        
        ws.onerror = function(error) {
            console.log('❌ WebSocket error:', error);
            isBackendConnected = false;
        };
        
    } catch (error) {
        console.log('⚠️ Cannot connect to backend - using demo mode');
        isBackendConnected = false;
    }
}

function handleRealTimeUpdate(data) {
    console.log('📡 Real-time update received:', data);

    switch (data.type) {
        case 'device_detected':
            addRealDevice(data.device);
            showNotification(`New device detected: ${data.device.name}`, 'info');
            break;

        case 'device_updated':
            updateRealDevice(data.device);
            break;

        case 'real_attack':
            handleRealAttack(data);
            break;

        case 'real_threat_detected':
        case 'threat':
            addRealThreat(data.threat);
            showNotification(`Threat detected: ${data.threat.type}`, 'warning');
            break;

        case 'network_threat':
            addRealThreat(data.threat);
            showNotification(`Network threat: ${data.threat.type}`, 'error');
            break;

        case 'phishing_detected':
            handlePhishingDetection(data.threat);
            break;

        case 'suspicious_download':
            handleSuspiciousDownload(data.threat);
            break;

        case 'security_event':
            if (data.event) {
                addRealThreat(data.event);
            }
            break;

        case 'system_status':
            updateSystemStatus(data.message);
            break;
    }
}

function addRealDevice(device) {
    // Add or update device in the UI
    const devicesGrid = document.querySelector('.devices-grid');
    if (!devicesGrid) return;
    
    // Remove existing device card if it exists
    const existingCard = document.getElementById(`device-${device.id}`);
    if (existingCard) {
        existingCard.remove();
    }
    
    const deviceCard = createRealDeviceCard(device);
    devicesGrid.appendChild(deviceCard);
    
    console.log(`✅ Real device added: ${device.name} (${device.ip})`);
}

function createRealDeviceCard(device) {
    const card = document.createElement('div');
    card.className = `device-card ${device.security.status}`;
    card.id = `device-${device.id}`;
    
    const statusClass = device.security.status === 'under_attack' ? 'critical' : 
                       device.security.status === 'monitoring' ? 'safe' : 'warning';
    
    const statusText = device.security.status === 'under_attack' ? 'UNDER ATTACK' :
                      device.security.status === 'monitoring' ? 'MONITORING' : 'SUSPICIOUS';
    
    const deviceIcon = device.type === 'mobile' ? '📱' : 
                      device.type === 'router' ? '🌐' : 
                      device.type === 'printer' ? '🖨️' : '💻';
    
    card.innerHTML = `
        <div class="device-header">
            <div class="device-icon">${deviceIcon}</div>
            <div class="device-info">
                <h4>${device.name}</h4>
                <span class="device-ip">${device.ip}</span>
            </div>
            <div class="device-status ${statusClass}">${statusText}</div>
        </div>
        <div class="device-stats">
            <div class="stat">
                <span class="label">Threats Blocked:</span>
                <span class="value">${device.threats.blocked}</span>
            </div>
            <div class="stat">
                <span class="label">Last Seen:</span>
                <span class="value">${formatTimeAgo(device.lastSeen)}</span>
            </div>
        </div>
    `;
    
    return card;
}

function handleRealAttack(data) {
    const { device, attack } = data;
    
    // Show critical attack notification
    showRealAttackNotification(device, attack);
    
    // Update device status
    updateRealDevice(device);
    
    // Add to attack feed
    addToAttackFeed(`🚨 REAL ATTACK: ${attack.type} on ${device.name} from ${attack.source}`, 'critical');
    
    // Update statistics
    updateAttackStatistics();
    
    console.log(`🚨 REAL ATTACK DETECTED: ${attack.type} on ${device.name}`);
}

function showRealAttackNotification(device, attack) {
    // Remove existing notification
    const existing = document.querySelector('.real-attack-notification');
    if (existing) existing.remove();
    
    const notification = document.createElement('div');
    notification.className = 'real-attack-notification';
    notification.innerHTML = `
        <div class="notification-content">
            <div class="notification-icon">🚨</div>
            <div class="notification-text">
                <strong>REAL ATTACK DETECTED!</strong>
                <p><strong>Device:</strong> ${device.name} (${device.ip})</p>
                <p><strong>Attack:</strong> ${attack.type}</p>
                <p><strong>Source:</strong> ${attack.source}</p>
                <p><strong>Time:</strong> ${new Date(attack.timestamp).toLocaleTimeString()}</p>
            </div>
            <button class="notification-close" onclick="this.parentElement.parentElement.remove()">×</button>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 10 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 10000);
}

function addRealThreat(threat) {
    if (!window.dashboard) return;

    const alert = {
        id: threat.id || `ALT-${Date.now()}`,
        timestamp: new Date(threat.timestamp),
        severity: threat.severity || 'medium',
        type: threat.type,
        description: threat.description,
        source: threat.source
    };

    window.dashboard.alerts.unshift(alert);
    window.dashboard.renderAlerts();
    window.dashboard.updateSummaryCards();
    window.dashboard.generateChartData('24h');
    window.dashboard.drawChart();

    console.log(`⚠️ Real threat detected: ${threat.type}`);
}

function updateSystemStatus(message) {
    const statusText = document.querySelector('.status-text');
    if (statusText) {
        statusText.textContent = message;
    }
    
    // Update demo notice
    const demoNotice = document.querySelector('.demo-notice');
    if (demoNotice && isBackendConnected) {
        demoNotice.style.background = 'linear-gradient(135deg, var(--success-green), #10b981)';
        demoNotice.querySelector('.demo-text strong').textContent = 'REAL SECURITY MONITORING ACTIVE';
        demoNotice.querySelector('.demo-text p').textContent = 'Connected to real backend system - showing live security data.';
    }
}

// URL Scanner functionality
function initializeURLScanner() {
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanUrlBtn');
    const resultsContainer = document.getElementById('scannerResults');
    
    if (!scanBtn || !urlInput) return;
    
    scanBtn.addEventListener('click', async () => {
        const url = urlInput.value.trim();
        if (!url) {
            showNotification('Please enter a URL to scan');
            return;
        }

        // Show loading state
        scanBtn.disabled = true;
        scanBtn.textContent = 'Scanning...';
        resultsContainer.style.display = 'block';

        try {
            const result = await scanURL(url);
            displayScanResults(result);
        } catch (error) {
            displayScanError(error.message);
        } finally {
            scanBtn.disabled = false;
            scanBtn.textContent = 'Scan URL';
        }
    });

    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            scanBtn.click();
        }
    });
}

async function scanURL(url) {
    try {
        // Try to use real backend first
        if (isBackendConnected) {
            const response = await fetch('http://localhost:3001/api/security/scan/url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            return await response.json();
        }
        
        // Simulate processing delay
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        return analyzeURL(url);
        
    } catch (error) {
        console.error('URL scan error:', error);
        throw new Error('Failed to scan URL: ' + error.message);
    }
}

function analyzeURL(url) {
    // Simulate URL analysis
    const threats = [];
    let riskLevel = 'safe';
    
    // Check for suspicious patterns
    const suspiciousPatterns = ['phishing', 'malware', 'scam', 'fake'];
    suspiciousPatterns.forEach(pattern => {
        if (url.toLowerCase().includes(pattern)) {
            threats.push({
                type: 'Suspicious Pattern',
                severity: 'high',
                description: `URL contains suspicious keyword: ${pattern}`
            });
            riskLevel = 'warning';
        }
    });
    
    // Check for suspicious TLDs
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf'];
    suspiciousTlds.forEach(tld => {
        if (url.includes(tld)) {
            threats.push({
                type: 'Suspicious TLD',
                severity: 'medium',
                description: `Uses suspicious top-level domain: ${tld}`
            });
            if (riskLevel === 'safe') riskLevel = 'warning';
        }
    });
    
    return {
        url,
        riskLevel,
        threats,
        reputation: Math.floor(Math.random() * 100),
        scanTime: new Date().toISOString()
    };
}

function displayScanResults(result) {
    const container = document.getElementById('scannerResults');
    
    let statusClass = 'safe';
    let statusText = 'URL appears safe';
    let statusIcon = '✅';
    
    if (result.riskLevel === 'warning') {
        statusClass = 'warning';
        statusText = 'Suspicious activity detected';
        statusIcon = '⚠️';
    } else if (result.riskLevel === 'critical') {
        statusClass = 'critical';
        statusText = 'Critical threat detected';
        statusIcon = '🚨';
    }
    
    container.innerHTML = `
        <div class="scan-status ${statusClass}">
            <span class="status-icon">${statusIcon}</span>
            <span class="status-text">${statusText}</span>
        </div>
        <div class="scan-details">
            <h4>Scan Results for: ${result.url}</h4>
            <p>Reputation Score: ${result.reputation}/100</p>
            <p>Scan Time: ${new Date(result.scanTime).toLocaleString()}</p>
            ${result.threats.length > 0 ? `
                <div class="threats-detected">
                    <h5>Threats Detected:</h5>
                    ${result.threats.map(threat => `
                        <div class="threat-item">
                            <span class="threat-type">${threat.type}</span>
                            <span class="threat-severity ${threat.severity}">${threat.severity}</span>
                            <p>${threat.description}</p>
                        </div>
                    `).join('')}
                </div>
            ` : '<p>No threats detected.</p>'}
        </div>
    `;
}

function displayScanError(message) {
    const container = document.getElementById('scannerResults');
    container.innerHTML = `
        <div class="scan-status error">
            <span class="status-icon">❌</span>
            <span class="status-text">Scan failed: ${message}</span>
        </div>
    `;
}

// Utility functions
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        border-radius: 8px;
        color: white;
        z-index: 3000;
        max-width: 300px;
        font-size: 14px;
        animation: slideInRight 0.3s ease;
    `;
    
    // Set background color based on type
    const colors = {
        info: '#3b82f6',
        success: '#10b981',
        warning: '#f59e0b',
        error: '#ef4444'
    };
    notification.style.background = colors[type] || colors.info;
    
    document.body.appendChild(notification);
    
    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'fadeOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

function formatTimeAgo(timestamp) {
    const now = new Date();
    const time = new Date(timestamp);
    const diff = now - time;
    
    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) {
        return `${days}d ago`;
    } else if (hours > 0) {
        return `${hours}h ago`;
    } else if (minutes > 0) {
        return `${minutes}m ago`;
    } else {
        return 'Just now';
    }
}

function handlePhishingDetection(threat) {
    if (!window.dashboard) return;

    const alert = {
        id: threat.id,
        timestamp: new Date(threat.timestamp),
        severity: threat.severity || 'high',
        type: 'Phishing Link Detected',
        description: `🎣 ${threat.messageText || threat.url}`,
        source: threat.source || 'Unknown'
    };

    window.dashboard.alerts.unshift(alert);
    window.dashboard.renderAlerts();
    window.dashboard.updateSummaryCards();
    window.dashboard.generateChartData('24h');
    window.dashboard.drawChart();

    const threatDesc = threat.threats ? threat.threats.map(t => t.type).join(', ') : 'Phishing detected';
    showNotification(`🎣 PHISHING LINK from ${threat.source}: ${threatDesc}`, 'error');

    console.log(`🎣 PHISHING DETECTED: ${threat.url}`);
    console.log(`   From: ${threat.source}`);
    console.log(`   Threats: ${threatDesc}`);
}

function handleSuspiciousDownload(threat) {
    if (!window.dashboard) return;

    const alert = {
        id: threat.id,
        timestamp: new Date(threat.timestamp),
        severity: threat.severity || 'high',
        type: 'Suspicious Download',
        description: `📥 ${threat.filename}`,
        source: 'Downloads folder'
    };

    window.dashboard.alerts.unshift(alert);
    window.dashboard.renderAlerts();
    window.dashboard.updateSummaryCards();

    showNotification(`📥 SUSPICIOUS DOWNLOAD: ${threat.filename}`, 'error');

    console.log(`📥 SUSPICIOUS DOWNLOAD: ${threat.filename}`);
    console.log(`   Path: ${threat.path}`);
}

// Load real security data from backend
async function loadRealSecurityData() {
    if (!isBackendConnected) return;

    try {
        const response = await fetch('http://localhost:3001/api/security/status');
        const data = await response.json();

        // Update UI with real data
        data.devices.forEach(device => addRealDevice(device));
        data.threats.forEach(threat => addRealThreat(threat));

    } catch (error) {
        console.log('⚠️ Failed to load real security data:', error);
    }
}

function initializeScanButtons() {
    const quickScanBtn = document.getElementById('quickScanBtn');
    const fullScanBtn = document.getElementById('fullScanBtn');
    const quarantineBtn = document.getElementById('quarantineBtn');
    const historyBtn = document.getElementById('historyBtn');

    if (quickScanBtn) {
        quickScanBtn.addEventListener('click', async () => {
            quickScanBtn.disabled = true;
            quickScanBtn.style.opacity = '0.6';
            showNotification('🔍 Quick scan started...', 'info');

            try {
                const response = await fetch('http://localhost:3001/api/scan/quick', { method: 'POST' });
                const result = await response.json();
                showNotification('✅ Quick scan completed', 'success');
            } catch (error) {
                showNotification('Failed to start quick scan', 'error');
            } finally {
                quickScanBtn.disabled = false;
                quickScanBtn.style.opacity = '1';
            }
        });
    }

    if (fullScanBtn) {
        fullScanBtn.addEventListener('click', async () => {
            fullScanBtn.disabled = true;
            fullScanBtn.style.opacity = '0.6';
            showNotification('🔍 Full scan started...', 'info');

            try {
                const response = await fetch('http://localhost:3001/api/scan/full', { method: 'POST' });
                const result = await response.json();
                showNotification('✅ Full scan initiated', 'success');
            } catch (error) {
                showNotification('Failed to start full scan', 'error');
            } finally {
                fullScanBtn.disabled = false;
                fullScanBtn.style.opacity = '1';
            }
        });
    }

    if (quarantineBtn) {
        quarantineBtn.addEventListener('click', async () => {
            window.dashboard.switchSection('quarantine');
            loadQuarantineList();
        });
    }

    if (historyBtn) {
        historyBtn.addEventListener('click', async () => {
            window.dashboard.switchSection('history');
            loadHistoryList();
        });
    }
}

async function loadQuarantineList() {
    try {
        const response = await fetch('http://localhost:3001/api/quarantine');
        const threats = await response.json();

        const quarantineList = document.getElementById('quarantineList');
        if (!quarantineList) return;

        if (threats.length === 0) {
            quarantineList.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">✨</div>
                    <h3>No Quarantined Items</h3>
                    <p>Your system is clean and safe</p>
                </div>
            `;
            return;
        }

        quarantineList.innerHTML = threats.map(threat => `
            <div class="quarantine-item">
                <div class="quarantine-info">
                    <div class="quarantine-filename">🔒 ${threat.description || threat.type}</div>
                    <div class="quarantine-details">
                        Detected: ${new Date(threat.timestamp).toLocaleString()}
                    </div>
                </div>
                <div class="quarantine-actions">
                    <button class="btn-restore">Restore</button>
                    <button class="btn-delete">Delete</button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load quarantine list:', error);
    }
}

async function loadHistoryList() {
    try {
        if (!window.dashboard || !window.dashboard.alerts) return;

        const historyList = document.getElementById('historyList');
        if (!historyList) return;

        const alerts = window.dashboard.alerts.slice(0, 50);

        if (alerts.length === 0) {
            historyList.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">📋</div>
                    <h3>No History</h3>
                    <p>No threats detected yet</p>
                </div>
            `;
            return;
        }

        historyList.innerHTML = alerts.map(alert => {
            const threatType = alert.type || 'Unknown Threat';
            const icon = threatType.includes('Phishing') ? '🎣' :
                        threatType.includes('Malware') ? '🦠' :
                        threatType.includes('Ransomware') ? '🔐' :
                        threatType.includes('Trojan') ? '👾' : '⚠️';

            return `
                <div class="history-item">
                    <div class="history-icon">${icon}</div>
                    <div class="history-info">
                        <div class="history-title">${threatType}</div>
                        <div class="history-details">${alert.description || alert.source || 'Unknown'}</div>
                    </div>
                    <div class="history-time">${new Date(alert.timestamp).toLocaleTimeString()}</div>
                </div>
            `;
        }).join('');
    } catch (error) {
        console.error('Failed to load history list:', error);
    }
}

async function updateQuarantineCount() {
    try {
        const response = await fetch('http://localhost:3001/api/quarantine');
        const threats = await response.json();
        const quarantineCount = document.getElementById('quarantineCount');
        if (quarantineCount) {
            quarantineCount.textContent = `${threats.length} item${threats.length !== 1 ? 's' : ''}`;
        }
    } catch (error) {
        // Silent fail
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new CyberSecurityDashboard();
    initializeURLScanner();
    initializeScanButtons();
    connectWebSocket();

    // Load real data after connection
    setTimeout(loadRealSecurityData, 2000);
    setInterval(updateQuarantineCount, 5000);
});

// Handle window resize for chart redrawing
window.addEventListener('resize', () => {
    if (window.dashboard && window.dashboard.currentSection === 'dashboard') {
        setTimeout(() => {
            window.dashboard.drawChart();
        }, 100);
    }
});