const express = require("express");
const cors = require("cors");
const fetchEmails = require("./fetchEmails");
const path = require('path');

const app = express();

// Configure CORS
app.use(cors({
    origin: [
        'http://localhost:3000', 
        'http://127.0.0.1:3000', 
        'http://localhost:8080',
        'http://127.0.0.1:5500'  // Add this line
    ],
    methods: ['GET', 'POST'],
    credentials: true
}));

// Middleware to parse JSON bodies
app.use(express.json());

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, '../public')));

// API endpoint to fetch emails
app.get("/fetch-emails", async (req, res) => {
    try {
        const emails = await fetchEmails();
        res.json(emails);
    } catch (error) {
        res.status(500).json({ message: "Error fetching emails", error: error.message });
    }
});

// Route to serve the HTML front-end
app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Phishing Analyzer</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {
                --primary-color: #3498db;
                --danger-color: #e74c3c;
                --warning-color: #f39c12;
                --success-color: #2ecc71;
                --dark-color: #2c3e50;
                --light-color: #ecf0f1;
                --box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            
            body {
                background-color: #f9f9f9;
                color: #333;
                line-height: 1.6;
            }
            
            .container {
                max-width: 1300px;
                margin: 0 auto;
                padding: 20px;
            }
            
            header {
                background-color: var(--dark-color);
                color: white;
                padding: 20px 0;
                margin-bottom: 30px;
            }
            
            .header-content {
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .logo {
                font-size: 24px;
                font-weight: bold;
                display: flex;
                align-items: center;
            }
            
            .logo i {
                margin-right: 10px;
                color: var(--primary-color);
            }
            
            nav ul {
                display: flex;
                list-style: none;
            }
            
            nav ul li {
                margin-left: 20px;
            }
            
            nav ul li a {
                color: white;
                text-decoration: none;
                transition: color 0.3s;
            }
            
            nav ul li a:hover {
                color: var(--primary-color);
            }
            
            .main-content {
                display: flex;
                gap: 30px;
            }
            
            .left-panel {
                flex: 1;
            }
            
            .right-panel {
                flex: 2;
            }
            
            .card {
                background-color: white;
                border-radius: 8px;
                box-shadow: var(--box-shadow);
                padding: 20px;
                margin-bottom: 30px;
            }
            
            .card-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding-bottom: 15px;
                margin-bottom: 15px;
                border-bottom: 1px solid #eee;
            }
            
            .card-title {
                font-size: 20px;
                color: var(--dark-color);
            }
            
            .btn {
                display: inline-block;
                background-color: var(--primary-color);
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                text-decoration: none;
                font-size: 16px;
                transition: background-color 0.3s;
            }
            
            .btn:hover {
                background-color: #2980b9;
            }
            
            .btn-danger {
                background-color: var(--danger-color);
            }
            
            .btn-danger:hover {
                background-color: #c0392b;
            }
            
            .email-list {
                list-style: none;
            }
            
            .email-item {
                padding: 15px;
                border-bottom: 1px solid #eee;
                cursor: pointer;
                transition: background-color 0.3s;
            }
            
            .email-item:hover {
                background-color: #f5f5f5;
            }
            
            .email-item.active {
                background-color: #e3f2fd;
                border-left: 4px solid var(--primary-color);
            }
            
            .email-item h3 {
                font-size: 16px;
                margin-bottom: 5px;
            }
            
            .email-item p {
                color: #777;
                font-size: 14px;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }
            
            .badge {
                display: inline-block;
                padding: 4px 8px;
                border-radius: 50px;
                font-size: 12px;
                color: white;
            }
            
            .badge-danger {
                background-color: var(--danger-color);
            }
            
            .badge-warning {
                background-color: var(--warning-color);
            }
            
            .badge-success {
                background-color: var(--success-color);
            }
            
            .email-header {
                padding-bottom: 20px;
                border-bottom: 1px solid #eee;
                margin-bottom: 20px;
            }
            
            .email-subject {
                font-size: 22px;
                margin-bottom: 10px;
            }
            
            .email-meta {
                display: flex;
                justify-content: space-between;
                color: #777;
                font-size: 14px;
            }
            
            .email-body {
                line-height: 1.8;
                margin-bottom: 30px;
            }
            
            .analysis-section {
                background-color: #f9f9f9;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 20px;
            }
            
            .analysis-title {
                font-size: 18px;
                margin-bottom: 15px;
                color: var(--dark-color);
                border-bottom: 1px solid #eee;
                padding-bottom: 10px;
            }
            
            .risk-indicator {
                display: flex;
                align-items: center;
                margin-bottom: 20px;
            }
            
            .risk-meter {
                flex: 1;
                height: 10px;
                background-color: #e0e0e0;
                border-radius: 5px;
                overflow: hidden;
                margin: 0 15px;
            }
            
            .risk-level {
                height: 100%;
                border-radius: 5px;
            }
            
            .risk-low {
                background-color: var(--success-color);
                width: 30%;
            }
            
            .risk-medium {
                background-color: var(--warning-color);
                width: 60%;
            }
            
            .risk-high {
                background-color: var(--danger-color);
                width: 90%;
            }
            
            .detail-list {
                list-style: none;
            }
            
            .detail-item {
                padding: 10px 0;
                border-bottom: 1px solid #eee;
            }
            
            .detail-item:last-child {
                border-bottom: none;
            }
            
            .detail-label {
                font-weight: bold;
                color: var(--dark-color);
                margin-bottom: 5px;
            }
            
            .url-list {
                list-style: none;
                margin-top: 10px;
            }
            
            .url-item {
                padding: 8px;
                background-color: #f0f0f0;
                border-radius: 4px;
                margin-bottom: 8px;
                display: flex;
                align-items: center;
                justify-content: space-between;
            }
            
            .url-item i {
                margin-right: 8px;
            }
            
            .url-safe {
                border-left: 4px solid var(--success-color);
            }
            
            .url-suspicious {
                border-left: 4px solid var(--warning-color);
            }
            
            .url-malicious {
                border-left: 4px solid var(--danger-color);
            }
            
            .loading {
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 40px;
            }
            
            .spinner {
                border: 4px solid rgba(0, 0, 0, 0.1);
                border-radius: 50%;
                border-top: 4px solid var(--primary-color);
                width: 40px;
                height: 40px;
                animation: spin 1s linear infinite;
            }
            
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            
            .empty-state {
                text-align: center;
                padding: 60px 0;
                color: #777;
            }
            
            .empty-state i {
                font-size: 60px;
                color: #ddd;
                margin-bottom: 20px;
            }
            
            .empty-state h3 {
                margin-bottom: 15px;
                color: var(--dark-color);
            }
            
            .recommendations {
                margin-top: 20px;
            }
            
            .recommendation-item {
                background-color: #f0f8ff;
                padding: 15px;
                margin-bottom: 10px;
                border-radius: 4px;
                border-left: 4px solid var(--primary-color);
            }
            
            .domain-info {
                display: flex;
                align-items: center;
                margin-bottom: 10px;
            }
            
            .domain-age {
                margin-left: 10px;
                color: #777;
            }
            
            /* Responsive design */
            @media screen and (max-width: 992px) {
                .main-content {
                    flex-direction: column;
                }
                
                .left-panel, .right-panel {
                    flex: 1;
                }
            }
            
            @media screen and (max-width: 768px) {
                .header-content {
                    flex-direction: column;
                    text-align: center;
                }
                
                nav ul {
                    margin-top: 20px;
                    justify-content: center;
                }
                
                nav ul li {
                    margin: 0 10px;
                }
                
                .email-meta {
                    flex-direction: column;
                }
            }
            
            .timeline {
                position: relative;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px 0;
            }
            
            .timeline::after {
                content: '';
                position: absolute;
                width: 6px;
                background-color: #e0e0e0;
                top: 0;
                bottom: 0;
                left: 10px;
                margin-left: -3px;
            }
            
            .timeline-item {
                padding: 10px 40px;
                position: relative;
                background-color: inherit;
                margin-bottom: 20px;
            }
            
            .timeline-item::after {
                content: '';
                position: absolute;
                width: 20px;
                height: 20px;
                background-color: white;
                border: 4px solid var(--primary-color);
                top: 15px;
                border-radius: 50%;
                z-index: 1;
                left: 0;
            }
            
            .timeline-content {
                padding: 15px;
                background-color: white;
                border-radius: 6px;
                box-shadow: var(--box-shadow);
            }
            
            .timeline-title {
                font-weight: bold;
                margin-bottom: 5px;
            }
            
            .timeline-text {
                color: #777;
            }
            
            .empty-email-details {
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                padding: 60px 0;
                color: #777;
                text-align: center;
            }
            
            .empty-email-details i {
                font-size: 60px;
                color: #ddd;
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>
        <header>
            <div class="container">
                <div class="header-content">
                    <div class="logo">
                        <i class="fas fa-shield-alt"></i>
                        <span>Email Phishing Analyzer</span>
                    </div>
                    <nav>
                        <ul>
                            <li><a href="#" class="active">Dashboard</a></li>
                            <li><a href="#">Settings</a></li>
                            <li><a href="#">Help</a></li>
                        </ul>
                    </nav>
                </div>
            </div>
        </header>
        
        <div class="container">
            <div class="main-content">
                <!-- Left Panel: Email List -->
                <div class="left-panel">
                    <div class="card">
                        <div class="card-header">
                            <h2 class="card-title">Recent Emails</h2>
                            <button id="refreshBtn" class="btn">
                                <i class="fas fa-sync-alt"></i> Refresh
                            </button>
                        </div>
                        
                        <div id="emailListContainer">
                            <div class="loading">
                                <div class="spinner"></div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Right Panel: Email Details and Analysis -->
                <div class="right-panel">
                    <div class="card" id="emailDetailsCard">
                        <div id="emailDetailsContainer" class="empty-email-details">
                            <i class="far fa-envelope"></i>
                            <h3>Select an email to view details</h3>
                            <p>Click on any email from the list to view its details and phishing analysis</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                // Elements
                const emailListContainer = document.getElementById('emailListContainer');
                const emailDetailsContainer = document.getElementById('emailDetailsContainer');
                const refreshBtn = document.getElementById('refreshBtn');
                
                // Fetch emails on load
                fetchEmails();
                
                // Refresh button click handler
                refreshBtn.addEventListener('click', fetchEmails);
                
                // Fetch emails function
                function fetchEmails() {
                    // Show loading state
                    emailListContainer.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
                    
                    // Fetch emails from API
                    fetch('/fetch-emails')
                        .then(response => {
                            if (!response.ok) {
                                throw new Error('Network response was not ok');
                            }
                            return response.json();
                        })
                        .then(data => {
                            // Check if we got an error message
                            if (data.error || data.message) {
                                emailListContainer.innerHTML = '<div class="empty-state"><i class="fas fa-exclamation-circle"></i><h3>Error Loading Emails</h3><p>' + (data.error || data.message) + '</p></div>';
                                return;
                            }
                            
                            // Check if no emails were found
                            if (data.length === 0) {
                                emailListContainer.innerHTML = '<div class="empty-state"><i class="far fa-envelope"></i><h3>No Emails Found</h3><p>There are no emails to analyze</p></div>';
                                return;
                            }
                            
                            // Render email list
                            renderEmailList(data);
                        })
                        .catch(error => {
                            console.error('Error fetching emails:', error);
                            emailListContainer.innerHTML = '<div class="empty-state"><i class="fas fa-exclamation-circle"></i><h3>Error</h3><p>Failed to fetch emails. Please try again later.</p></div>';
                        });
                }
                
                // Render email list function
                function renderEmailList(emails) {
                    const emailList = document.createElement('ul');
                    emailList.className = 'email-list';
                    
                    emails.forEach((email, index) => {
                        const emailItem = document.createElement('li');
                        emailItem.className = 'email-item';
                        emailItem.dataset.index = index;
                        
                        // Set phishing badge
                        const badgeClass = email.isPhishingEmail ? 'badge-danger' : 'badge-success';
                        const badgeText = email.isPhishingEmail ? 'Suspicious' : 'Safe';
                        
                        emailItem.innerHTML = \`
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div style="flex: 1;">
                                    <h3>\${email.subject || 'No Subject'}</h3>
                                    <p>\${email.from}</p>
                                </div>
                                <span class="badge \${badgeClass}">\${badgeText}</span>
                            </div>
                            <p>\${email.snippet || ''}</p>
                        \`;
                        
                        // Add click event to show email details
                        emailItem.addEventListener('click', () => {
                            // Remove active class from all items
                            document.querySelectorAll('.email-item').forEach(item => {
                                item.classList.remove('active');
                            });
                            
                            // Add active class to clicked item
                            emailItem.classList.add('active');
                            
                            // Show email details
                            showEmailDetails(email);
                        });
                        
                        emailList.appendChild(emailItem);
                    });
                    
                    // Replace loading with email list
                    emailListContainer.innerHTML = '';
                    emailListContainer.appendChild(emailList);
                    
                    // Select the first email by default
                    if (emails.length > 0) {
                        const firstEmailItem = emailList.querySelector('.email-item');
                        if (firstEmailItem) {
                            firstEmailItem.classList.add('active');
                            showEmailDetails(emails[0]);
                        }
                    }
                }
                
                // Show email details function
                function showEmailDetails(email) {
                    // Determine risk level for UI
                    let riskLevel = 'low';
                    let riskLevelText = 'Low Risk';
                    
                    if (email.isPhishingEmail) {
                        if (email.phishingUrls && email.phishingUrls.length > 0) {
                            riskLevel = 'high';
                            riskLevelText = 'High Risk';
                        } else {
                            riskLevel = 'medium';
                            riskLevelText = 'Medium Risk';
                        }
                    }
                    
                    // Create URLs list HTML
                    let urlsHtml = '';
                    if (email.urls && email.urls.length > 0) {
                        urlsHtml += '<ul class="url-list">';
                        email.urls.forEach((url, index) => {
                            const isPhishing = email.phishingUrls && email.phishingUrls.includes(url);
                            const urlClass = isPhishing ? 'url-malicious' : 'url-safe';
                            const iconClass = isPhishing ? 'fas fa-exclamation-triangle' : 'fas fa-check-circle';
                            const iconColor = isPhishing ? '#e74c3c' : '#2ecc71';
                            
                            urlsHtml += \`
                                <li class="url-item \${urlClass}">
                                    <div>
                                        <i class="\${iconClass}" style="color: \${iconColor};"></i>
                                        <span>\${url}</span>
                                    </div>
                                    <div>
                                        <span>\${isPhishing ? 'Malicious' : 'Safe'}</span>
                                    </div>
                                </li>
                            \`;
                            
                            // Add domain reputation if available
                            if (email.domainReputation && email.domainReputation[index]) {
                                urlsHtml += \`
                                    <li class="domain-info">
                                        <span class="domain-age">\${email.domainReputation[index]}</span>
                                    </li>
                                \`;
                            }
                        });
                        urlsHtml += '</ul>';
                    } else {
                        urlsHtml = '<p>No URLs found in this email</p>';
                    }
                    
                    // Create recommendations
                    let recommendationsHtml = '';
                    if (email.isPhishingEmail) {
                        recommendationsHtml = \`
                            <div class="recommendations">
                                <h3 class="analysis-title">Recommendations</h3>
                                <div class="recommendation-item">
                                    <p><i class="fas fa-exclamation-triangle"></i> Do not click on any links in this email</p>
                                </div>
                                <div class="recommendation-item">
                                    <p><i class="fas fa-trash-alt"></i> Delete this email</p>
                                </div>
                                <div class="recommendation-item">
                                    <p><i class="fas fa-shield-alt"></i> Report as phishing to your IT department</p>
                                </div>
                            </div>
                        \`;
                    }
                    
                    // Set HTML content
                    emailDetailsContainer.innerHTML = \`
                        <div class="email-header">
                            <h2 class="email-subject">\${email.subject || 'No Subject'}</h2>
                            <div class="email-meta">
                                <div>
                                    <strong>From:</strong> \${email.from}
                                </div>
                                <div>
                                    <span class="badge \${email.isPhishingEmail ? 'badge-danger' : 'badge-success'}">\${email.isPhishingEmail ? 'Suspicious' : 'Safe'}</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="email-body">
                            <p>\${email.snippet || 'No preview available'}</p>
                        </div>
                        
                        <div class="analysis-section">
                            <h3 class="analysis-title">Phishing Analysis</h3>
                            
                            <div class="risk-indicator">
                                <span>Risk Level:</span>
                                <div class="risk-meter">
                                    <div class="risk-level risk-\${riskLevel}"></div>
                                </div>
                                <span>\${riskLevelText}</span>
                            </div>
                            
                            <ul class="detail-list">
                                <li class="detail-item">
                                    <div class="detail-label">Phishing Patterns</div>
                                    <div>\${email.isPhishingEmail ? 'Suspicious patterns detected in email content' : 'No suspicious patterns detected'}</div>
                                </li>
                                <li class="detail-item">
                                    <div class="detail-label">URLs Found (\${email.urls ? email.urls.length : 0})</div>
                                    \${urlsHtml}
                                </li>
                            </ul>
                        </div>
                        
                        \${recommendationsHtml}
                    \`;
                }
            });
        </script>
    </body>
    </html>
    `);
});

const PORT = 8080;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Open your browser and navigate to http://localhost:${PORT} to use the application`);
});