// Common phishing keywords and patterns
const PHISHING_KEYWORDS = [
    'urgent', 'account suspended', 'verify your account', 'password expired',
    'security alert', 'unusual activity', 'login attempt', 'click here',
    'update your information', 'payment pending', 'won', 'lottery',
    'inheritance', 'prince', 'bank transfer', 'suspicious activity'
];

// Suspicious TLDs often used in phishing
const SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.date',
    '.faith', '.zip', '.racing', '.win', '.loan', '.download'
];

function analyzeEmail(emailContent, subject, from) {
    let suspiciousPoints = 0;
    const analysis = {
        isPhishingEmail: false,
        urls: [],
        phishingUrls: [],
        reasons: []
    };

    // Extract URLs from email content using regex
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    analysis.urls = emailContent.match(urlRegex) || [];

    // Check URLs for suspicious patterns
    analysis.urls.forEach(url => {
        try {
            const urlObj = new URL(url);
            // Check for suspicious TLDs
            if (SUSPICIOUS_TLDS.some(tld => urlObj.hostname.endsWith(tld))) {
                suspiciousPoints += 2;
                analysis.phishingUrls.push(url);
                analysis.reasons.push(`Suspicious domain extension: ${urlObj.hostname}`);
            }
            // Check for IP addresses instead of domain names
            if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlObj.hostname)) {
                suspiciousPoints += 2;
                analysis.phishingUrls.push(url);
                analysis.reasons.push('URL contains IP address instead of domain name');
            }
        } catch (e) {
            // Invalid URL, might be suspicious
            suspiciousPoints += 1;
            analysis.reasons.push('Invalid URL format detected');
        }
    });

    // Check for phishing keywords in subject and content
    const contentToCheck = (subject + ' ' + emailContent).toLowerCase();
    PHISHING_KEYWORDS.forEach(keyword => {
        if (contentToCheck.includes(keyword.toLowerCase())) {
            suspiciousPoints += 1;
            analysis.reasons.push(`Suspicious keyword found: "${keyword}"`);
        }
    });

    // Check for urgency indicators
    if (/urgent|immediate|asap|quickly|today only/i.test(contentToCheck)) {
        suspiciousPoints += 1;
        analysis.reasons.push('Urgency indicators detected');
    }

    // Check for requests for sensitive information
    if (/password|ssn|social security|credit card|bank account/i.test(contentToCheck)) {
        suspiciousPoints += 2;
        analysis.reasons.push('Requests for sensitive information detected');
    }

    // Check sender address for suspicious patterns
    if (from) {
        // Check for mismatched or suspicious sender domains
        if (from.includes('@') && 
            (from.includes('security') || from.includes('admin') || from.includes('support'))) {
            if (!from.endsWith('.com') && !from.endsWith('.org') && !from.endsWith('.edu')) {
                suspiciousPoints += 1;
                analysis.reasons.push('Suspicious sender domain');
            }
        }
    }

    // Determine if email is likely phishing based on suspicious points
    analysis.isPhishingEmail = suspiciousPoints >= 3;
    analysis.suspiciousScore = suspiciousPoints;

    return analysis;
}

module.exports = { analyzeEmail };
