import { loadBlacklist, analyzeURL } from './url_analyzer.js';

document.addEventListener('DOMContentLoaded', init);

async function init() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.url) {
            showError('Unable to access current tab URL');
            return;
        }

        renderUrlContext(tab.url);

        if (!isScannableUrl(tab.url)) {
            showError('This extension only analyzes http:// and https:// pages');
            return;
        }

        // Use the background's cached result so the popup always matches the badge.
        let result = null;
        try {
            result = await chrome.runtime.sendMessage({ type: 'GET_TAB_RESULT', tabId: tab.id });
        } catch (_) {}

        if (!result) {
            const blacklistSet = await loadBlacklist();
            result = analyzeURL(tab.url, blacklistSet);
        }

        displayResult(result);
    } catch (error) {
        showError(error.message || 'Unknown error');
    }
}

function isScannableUrl(url) {
    return typeof url === 'string' && (url.startsWith('http://') || url.startsWith('https://'));
}

function renderUrlContext(url) {
    const safeUrl = typeof url === 'string' && url.trim() ? url : 'Current tab URL unavailable';
    const hostname = formatUrlLabel(url);

    const urlDisplay = document.getElementById('urlDisplay');
    const hostnameDisplay = document.getElementById('hostnameDisplay');

    urlDisplay.textContent = safeUrl;
    urlDisplay.title = safeUrl;
    hostnameDisplay.textContent = hostname;
    hostnameDisplay.title = hostname;
}

function formatUrlLabel(url) {
    if (typeof url !== 'string' || !url.trim()) {
        return 'No URL';
    }

    try {
        const parsedUrl = new URL(url);
        if (parsedUrl.hostname) {
            return parsedUrl.hostname;
        }

        if (parsedUrl.protocol) {
            return `${parsedUrl.protocol.replace(':', '')} page`;
        }
    } catch (error) {
        return 'Active page';
    }

    return 'Active page';
}

function displayResult(result) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('result').style.display = 'grid';
    document.getElementById('error').style.display = 'none';

    const { decision, blacklistMatch, confidence, reasons, decisionSource } = result;
    const statusContent = getStatusContent(decision, blacklistMatch);
    const hasReason = Array.isArray(reasons) && reasons.length > 0 && decision !== 'legitimate';

    setUiState(decision);

    document.getElementById('statusIcon').textContent = statusContent.icon;
    document.getElementById('statusTag').textContent = statusContent.tag;
    document.getElementById('statusText').textContent = statusContent.title;
    document.getElementById('statusSummary').textContent = statusContent.summary;
    document.getElementById('confidence').textContent = confidence || 'N/A';
    document.getElementById('signalCount').textContent = String(getSignalCount(reasons, blacklistMatch));
    document.getElementById('sourceText').textContent = formatSourceLabel(decisionSource, blacklistMatch);

    const sourceCard = document.getElementById('sourceCard');
    const blacklistRow = document.getElementById('blacklistRow');
    const reasonRow = document.getElementById('reasonRow');

    if (blacklistMatch) {
        blacklistRow.style.display = 'block';
        document.getElementById('blacklistMatch').innerHTML = '<span class="badge badge-danger">Matched</span>';
    } else {
        blacklistRow.style.display = 'none';
        document.getElementById('blacklistMatch').innerHTML = '';
    }

    if (hasReason) {
        reasonRow.style.display = 'block';
        document.getElementById('reasonText').textContent = reasons[0];
    } else {
        reasonRow.style.display = 'none';
        document.getElementById('reasonText').textContent = '';
    }

    sourceCard.classList.toggle('full', !blacklistMatch && !hasReason);
}

function getStatusContent(decision, blacklistMatch) {
    if (decision === 'legitimate') {
        return {
            icon: 'OK',
            tag: 'Protection',
            title: 'Protected',
            summary: 'No strong phishing signals were found for this page in the local scan.'
        };
    }

    if (decision === 'suspicious') {
        return {
            icon: '!',
            tag: 'Attention',
            title: 'Suspicious',
            summary: 'Some URL patterns look unusual, so double-check the site before entering any personal data.'
        };
    }

    return {
        icon: 'X',
        tag: 'Blocked',
        title: 'Threat Detected',
        summary: blacklistMatch
            ? 'This page matched a blacklist entry and should be treated as unsafe.'
            : 'Multiple phishing signals were found, so it is safest not to interact with this site.'
    };
}

function getSignalCount(reasons, blacklistMatch) {
    const reasonCount = Array.isArray(reasons) ? reasons.length : 0;
    return reasonCount + (blacklistMatch ? 1 : 0);
}

function formatSourceLabel(decisionSource, blacklistMatch) {
    if (decisionSource === 'blacklist' || blacklistMatch) {
        return 'Blacklist rule override';
    }

    return 'Local ML scan';
}

function showError(message) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('result').style.display = 'grid';

    setUiState('error');

    const errorDiv = document.getElementById('error');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';

    document.getElementById('statusIcon').textContent = '?';
    document.getElementById('statusTag').textContent = 'Inactive';
    document.getElementById('statusText').textContent = 'Scan Unavailable';
    document.getElementById('statusSummary').textContent = getErrorSummary(message);
    document.getElementById('confidence').textContent = 'N/A';
    document.getElementById('signalCount').textContent = '0';
    document.getElementById('sourceText').textContent = 'The detector could not inspect this tab.';
    document.getElementById('sourceCard').classList.add('full');
    document.getElementById('blacklistRow').style.display = 'none';
    document.getElementById('reasonRow').style.display = 'none';
}

function getErrorSummary(message) {
    if (message.includes('http://') || message.includes('https://')) {
        return 'Browser pages, extension pages, and other internal tabs cannot be analyzed.';
    }

    if (message.includes('Unable to access')) {
        return 'The current tab URL was not available to the extension, so the scan could not start.';
    }

    return 'The detector could not finish this scan. Reload the tab and try again.';
}

function setUiState(state) {
    document.body.dataset.state = state;
}
