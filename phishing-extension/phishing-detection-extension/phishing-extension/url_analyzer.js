import { predictRandomForest } from './model/model_rf.js';

const SUSPICIOUS_TOKENS = new Set([
    'account', 'alert', 'amazon', 'amex', 'apple', 'bank', 'barclays',
    'billing', 'boa', 'capitalone', 'chase', 'citi', 'clone', 'confirm',
    'fake', 'halifax', 'hsbc', 'invoice', 'limited', 'lloyds', 'login',
    'microsoft', 'monzo', 'natwest', 'notice', 'office', 'outlook',
    'password', 'paypal', 'phish', 'refund', 'revolut', 'santander',
    'scam', 'secure', 'signin', 'spoof', 'support', 'td', 'unlock',
    'update', 'verify', 'wellsfargo'
]);

const SHORTENING_SERVICES = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly',
    'rebrandly.com', 'bl.ink', 'shorte.st', 'fb.me', 't.ly', 'lnkd.in',
    'amzn.to', 'wp.me', 'rb.gy', 'tiny.cc', 'cutt.ly', 's.id', 'u.to',
    'mcaf.ee', 'adf.ly', 'v.gd', 'qr.net'
];

const UNUSUAL_TLDS = new Set([
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'buzz', 'club', 'work',
    'info', 'wang', 'live', 'host', 'ru', 'online', 'icu'
]);

const SUSPICIOUS_EXTENSIONS = ['.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.exe', '.zip'];

// subdomains on these are user-controlled so can't be trusted
const FREE_HOSTING_PLATFORMS = new Set([
    'github.io', 'gitlab.io', 'netlify.app', 'vercel.app',
    'pages.dev', 'web.app', 'firebaseapp.com', 'herokuapp.com', 'glitch.me'
]);

const PHISHING_SUBSTRINGS = ['clone', 'fake', 'phish', 'spoof', 'scam'];

// known legitimate domains - skip ML check for these over HTTPS
const TRUSTED_DOMAINS = new Set([
    'google', 'youtube', 'facebook', 'instagram', 'twitter', 'linkedin',
    'microsoft', 'apple', 'amazon', 'github', 'wikipedia', 'bing',
    'netflix', 'spotify', 'dropbox', 'slack', 'adobe', 'mozilla',
    'cloudflare', 'stackoverflow', 'reddit', 'tiktok', 'whatsapp',
    'bbc', 'cnn', 'reuters', 'theguardian', 'nytimes', 'theverge',
    'techcrunch', 'wired',
    'paypal', 'ebay', 'etsy', 'walmart', 'target', 'shopify',
    'chase', 'wellsfargo', 'bankofamerica', 'hsbc', 'barclays', 'lloyds',
    'natwest', 'santander', 'monzo', 'revolut', 'amex', 'visa', 'mastercard',
    'gov', 'nhs', 'ac',
]);

export async function loadBlacklist() {
    try {
        const response = await fetch(chrome.runtime.getURL('data/blacklist.json'));
        const data = await response.json();
        return new Set((data.urls || []).map((u) => String(u).trim()));
    } catch (error) {
        return new Set();
    }
}

export function analyzeURL(url, blacklistSet) {
    const normalizedUrl = String(url).trim();
    const blacklistMatch = blacklistSet.has(normalizedUrl);

    // skip ML for trusted domains over HTTPS to avoid false positives
    if (!blacklistMatch) {
        try {
            const parsed = new URL(normalizedUrl);
            if (parsed.protocol === 'https:') {
                const bypassDomain = extractDomain(parsed.hostname);
                const bypassTld = extractTLD(parsed.hostname);
                // free hosting subdomains (e.g. user.github.io) still need ML check
                const onFreeHosting = isOnFreeHostingPlatform(parsed.hostname);
                if (TRUSTED_DOMAINS.has(bypassDomain) && !onFreeHosting) {
                    return {
                        decision: 'legitimate',
                        decisionSource: 'trusted_domain',
                        mlDecision: 'legitimate',
                        probability: 0,
                        blacklistMatch: false,
                        confidence: 'Very High',
                        reasons: []
                    };
                }
                // also bypass for likely popular domains not in the explicit list
                if (!onFreeHosting && isLikelyTopDomain(bypassDomain, bypassTld) === 1) {
                    const urlTokens = normalizedUrl.toLowerCase().split(/\W+/).filter((t) => t.length > 0);
                    const noSuspiciousToken = !urlTokens.some((t) => SUSPICIOUS_TOKENS.has(t));
                    const noDomainHyphen = !bypassDomain.includes('-');
                    const noSuspiciousExt = !checkSuspiciousFileExtension(parsed.pathname);
                    if (noSuspiciousToken && noDomainHyphen && noSuspiciousExt) {
                        return {
                            decision: 'legitimate',
                            decisionSource: 'trusted_domain',
                            mlDecision: 'legitimate',
                            probability: 0,
                            blacklistMatch: false,
                            confidence: 'High',
                            reasons: []
                        };
                    }
                }
            }
        } catch (_) {}
    }

    // flag non-public TLDs (.test, .local etc.) - model wasn't trained on these
    if (!blacklistMatch) {
        try {
            const parsed = new URL(normalizedUrl);
            const tld = extractTLD(parsed.hostname);
            const NON_ICANN_TLDS = new Set(['test', 'local', 'invalid', 'example', 'localhost']);
            if (NON_ICANN_TLDS.has(tld.toLowerCase()) || tld === '') {
                const urlTokens = normalizedUrl.toLowerCase().split(/\W+/).filter((t) => t.length > 0);
                const hasSuspiciousToken = urlTokens.some((t) => SUSPICIOUS_TOKENS.has(t));
                const forcedDecision = hasSuspiciousToken ? 'phishing' : 'suspicious';
                const forcedProbability = hasSuspiciousToken ? 0.85 : 0.55;
                return {
                    decision: forcedDecision,
                    decisionSource: 'rule',
                    mlDecision: forcedDecision,
                    probability: forcedProbability,
                    blacklistMatch: false,
                    confidence: hasSuspiciousToken ? 'High' : 'Medium',
                    reasons: ['URL uses a non-public TLD like .test or .local which are not real websites.']
                };
            }
        } catch (_) {}
    }

    const features = extractURLFeatures(normalizedUrl);
    let probability = Number(predictRandomForest(features));
    if (!Number.isFinite(probability)) probability = 0;
    probability = Math.max(0, Math.min(1, probability));

    const mlDecision = makeDecision(false, probability);

    let decision = mlDecision;
    let decisionSource = 'ml';

    if (blacklistMatch) {
        decision = 'phishing';
        decisionSource = 'blacklist';
    }

    // Post-ML rules: upgrade decision based on URL signals the model may miss.
    const ruleFlags = { phishingSubstring: false, freeHosting: false };
    if (!blacklistMatch) {
        const urlLower = normalizedUrl.toLowerCase();
        if (PHISHING_SUBSTRINGS.some((s) => urlLower.includes(s))) {
            ruleFlags.phishingSubstring = true;
            if (decision === 'legitimate') {
                decision = 'suspicious';
                decisionSource = 'rule';
            } else if (decision === 'suspicious') {
                decision = 'phishing';
                decisionSource = 'rule';
            }
        }
        try {
            const parsedPost = new URL(normalizedUrl);
            if (isOnFreeHostingPlatform(parsedPost.hostname) && decision === 'legitimate') {
                ruleFlags.freeHosting = true;
                decision = 'suspicious';
                decisionSource = 'rule';
            }
        } catch (_) {}
    }

    const reasons = decision === 'legitimate'
        ? []
        : buildReasons({
            blacklistMatch,
            probability,
            decision,
            decisionSource,
            features,
            ruleFlags
        });

    return {
        decision,
        decisionSource,
        mlDecision,
        probability,
        blacklistMatch,
        confidence: calculateConfidence(probability, decision, decisionSource),
        reasons
    };
}

function makeDecision(blacklistMatch, probability) {
    if (blacklistMatch) return 'phishing';
    if (probability >= 0.70) return 'phishing';
    if (probability >= 0.50) return 'suspicious';
    return 'legitimate';
}

function calculateConfidence(probability, decision, decisionSource) {
    if (decisionSource === 'blacklist') return 'Very High';

    if (decision === 'phishing') {
        if (probability >= 0.97) return 'Very High';
        if (probability >= 0.90) return 'High';
        return 'Medium';
    }

    if (decision === 'suspicious') {
        if (probability >= 0.75) return 'High';
        return 'Medium';
    }

    if (probability <= 0.1) return 'Very High';
    if (probability <= 0.25) return 'High';
    return 'Medium';
}

function buildReasons({ blacklistMatch, probability, decision, decisionSource, features, ruleFlags = {} }) {
    const reasons = [];

    if (blacklistMatch) {
        reasons.push('URL matched phishing blacklist.');
    }

    if (ruleFlags.phishingSubstring) {
        reasons.push('URL contains a keyword associated with cloned or fake sites (e.g., "clone", "fake").');
    }

    if (ruleFlags.freeHosting) {
        reasons.push('Site is hosted on a free platform where anyone can publish content.');
    }

    if (features[10] === 1) {
        reasons.push('URL contains suspicious keywords (e.g., login, verify, secure).');
    }

    if (features[8] === 1) {
        reasons.push('Host uses an IP address instead of a normal domain.');
    }

    if (features[9] === 0) {
        reasons.push('URL does not use HTTPS.');
    }

    if (features[17] === 1) {
        reasons.push('URL uses a shortening service.');
    }

    if (features[22] === 1) {
        reasons.push('URL ends with a risky file extension.');
    }

    if (reasons.length === 0) {
        reasons.push('Matched phishing-like URL pattern.');
    }

    return reasons.slice(0, 3);
}

// extract 24 numeric features from the URL for the RF model
function extractURLFeatures(urlString) {
    try {
        const url = new URL(urlString);
        const scheme = url.protocol.replace(':', '').toLowerCase();
        const host = url.hostname || '';
        const path = url.pathname || '';
        const query = url.search.substring(1);
        const full = urlString.trim().toLowerCase();

        const tld = extractTLD(host);
        const domain = extractDomain(host);
        const tokens = full.split(/\W+/).filter((t) => t.length > 0);

        const suspiciousHits = tokens.some((token) => SUSPICIOUS_TOKENS.has(token)) ? 1 : 0;
        const maxTokenLen = tokens.length > 0 ? Math.max(...tokens.map((t) => t.length)) : 0;

        const numSubdomains = countSubdomains(host);
        const entropyUrl = shannonEntropy(full);
        const entropyDomain = shannonEntropy(domain);
        const usesShortening = checkShorteningService(full);
        const unusualTld = UNUSUAL_TLDS.has(tld.toLowerCase()) ? 1 : 0;
        const specialCharsDomain = countSpecialCharsRatio(domain);
        const specialCharsPath = countSpecialCharsRatio(path);
        const specialCharsQuery = countSpecialCharsRatio(query);
        const hasSuspiciousFile = checkSuspiciousFileExtension(path);
        const inTop1m = isLikelyTopDomain(domain, tld);

        return [
            full.length,
            host.length,
            path.length,
            (full.match(/\./g) || []).length,
            (full.match(/-/g) || []).length,
            (full.match(/\d/g) || []).length,
            query ? query.split('&').length : 0,
            full.includes('@') ? 1 : 0,
            isIPAddress(host) ? 1 : 0,
            scheme === 'https' ? 1 : 0,
            suspiciousHits,
            maxTokenLen,
            tld.length,
            tld.length > 3 ? 1 : 0,
            numSubdomains,
            entropyUrl,
            entropyDomain,
            usesShortening,
            unusualTld,
            specialCharsDomain,
            specialCharsPath,
            specialCharsQuery,
            hasSuspiciousFile,
            inTop1m
        ];
    } catch (error) {
        return Array(24).fill(0);
    }
}

function extractTLD(host) {
    const parts = host.split('.');
    if (parts.length < 2) return '';
    const twoPartTLDs = ['co.uk', 'com.au', 'co.in', 'com.br', 'co.za'];
    const lastTwo = parts.slice(-2).join('.');
    if (twoPartTLDs.includes(lastTwo)) return lastTwo;
    return parts[parts.length - 1];
}

function extractDomain(host) {
    const parts = host.split('.');
    if (parts.length < 2) return host;
    const twoPartTLDs = ['co.uk', 'com.au', 'co.in', 'com.br', 'co.za'];
    const lastTwo = parts.slice(-2).join('.');
    const offset = twoPartTLDs.includes(lastTwo) ? 3 : 2;
    if (parts.length < offset) return parts[0];
    return parts[parts.length - offset];
}

// strip www first so it doesn't count as a subdomain
function countSubdomains(host) {
    return (host.replace(/^www\./, '').match(/\./g) || []).length;
}

function shannonEntropy(s) {
    if (!s) return 0;
    const counts = {};
    for (const char of s) counts[char] = (counts[char] || 0) + 1;

    let entropy = 0;
    for (const count of Object.values(counts)) {
        const p = count / s.length;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

function checkShorteningService(fullUrl) {
    return SHORTENING_SERVICES.some((service) => fullUrl.includes(service)) ? 1 : 0;
}

function countSpecialCharsRatio(section) {
    if (!section || section.length === 0) return 0;
    const specialChars = section.match(/[^a-z0-9]/gi) || [];
    return specialChars.length / section.length;
}

function checkSuspiciousFileExtension(path) {
    const lower = (path || '').toLowerCase();
    return SUSPICIOUS_EXTENSIONS.some((ext) => lower.endsWith(ext)) ? 1 : 0;
}

function isIPAddress(host) {
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Pattern.test(host)) {
        const parts = host.split('.');
        return parts.every((part) => parseInt(part, 10) >= 0 && parseInt(part, 10) <= 255);
    }

    const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
    return ipv6Pattern.test(host);
}

function isOnFreeHostingPlatform(hostname) {
    for (const platform of FREE_HOSTING_PLATFORMS) {
        if (hostname === platform || hostname.endsWith('.' + platform)) return true;
    }
    return false;
}

function isLikelyTopDomain(domainName, tldStr) {
    if (!domainName) return 0;
    const whitelist = new Set([
        'google', 'amazon', 'github', 'microsoft', 'gov', 'facebook',
        'apple', 'wikipedia', 'youtube', 'bing', 'linkedin', 'twitter', 'paypal'
    ]);
    if (whitelist.has(domainName)) return 1;

    const commonTlds = new Set(['com', 'org', 'net', 'gov', 'edu', 'co', 'uk', 'io']);
    const tldSuffix = tldStr.split('.').pop();
    if (domainName.length <= 9 && !/\d/.test(domainName) && commonTlds.has(tldSuffix)) return 1;
    return 0;
}
