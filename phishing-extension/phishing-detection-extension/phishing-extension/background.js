import { loadBlacklist, analyzeURL } from './url_analyzer.js';

let blacklistSet = new Set();
const lastNotifiedByTab = new Map();
const tabResults = new Map();

// Reload blacklist into in-memory cache used by the service worker.
async function refreshBlacklist() {
    blacklistSet = await loadBlacklist();
}

// Return true only for URL schemes supported by the detector.
function isScannableUrl(url) {
    if (!url || typeof url !== 'string') return false;
    return url.startsWith('http://') || url.startsWith('https://');
}

// Analyze one tab URL and update badge, overlay, and popup behavior.
async function analyzeTab(tabId, url) {
    if (!isScannableUrl(url)) {
        clearTabWarning(tabId);
        return;
    }

    const result = analyzeURL(url, blacklistSet);
    const isPhishing = result.decision === 'phishing';
    const isSuspicious = result.decision === 'suspicious';
    const notifyKey = `${result.decision}:${url}`;

    tabResults.set(tabId, result);

    if (!isPhishing && !isSuspicious) {
        clearTabWarning(tabId);
        await sendClearMessage(tabId);
        return;
    }

    if (isPhishing) {
        chrome.action.setBadgeText({ tabId, text: '!' });
        chrome.action.setBadgeBackgroundColor({ tabId, color: '#dc3545' });
    } else {
        chrome.action.setBadgeText({ tabId, text: '?' });
        chrome.action.setBadgeBackgroundColor({ tabId, color: '#f59e0b' });
        await sendClearMessage(tabId); // suspicious should not show phishing overlay
    }

    const tabIsActive = await isActiveTab(tabId);
    if (!tabIsActive) return;

    const alreadyNotifiedForThisUrl = lastNotifiedByTab.get(tabId) === notifyKey;
    if (alreadyNotifiedForThisUrl) return;

    if (isPhishing) {
        try {
            await chrome.tabs.sendMessage(tabId, {
                type: 'SHOW_PHISHING_WARNING',
                url,
                blacklistMatch: result.blacklistMatch,
                confidence: result.confidence,
                decisionSource: result.decisionSource,
                reasons: result.reasons
            });
            lastNotifiedByTab.set(tabId, notifyKey);
        } catch (error) {
            // Some pages do not allow content scripts. Ignore.
        }
    }

    try {
        await chrome.action.openPopup();
    } catch (error) {
        // Ignore restrictions and rely on badge/overlay.
    }
}

// Clear badge state for a tab.
function clearTabWarning(tabId) {
    lastNotifiedByTab.delete(tabId);
    tabResults.delete(tabId);
    chrome.action.setBadgeText({ tabId, text: '' });
}

// Ask content script to remove any visible phishing overlay.
async function sendClearMessage(tabId) {
    try {
        await chrome.tabs.sendMessage(tabId, { type: 'CLEAR_PHISHING_WARNING' });
    } catch (error) {
        // Ignore pages without content-script access.
    }
}

// Return true when the tab is active in the current window.
async function isActiveTab(tabId) {
    const activeTabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return activeTabs.length > 0 && activeTabs[0].id === tabId;
}

chrome.runtime.onInstalled.addListener(async () => {
    await refreshBlacklist();
});

chrome.runtime.onStartup.addListener(async () => {
    await refreshBlacklist();
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.url) {
        await analyzeTab(tabId, changeInfo.url);
        return;
    }

    if (changeInfo.status === 'complete' && tab && tab.url) {
        await analyzeTab(tabId, tab.url);
    }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
    const tab = await chrome.tabs.get(tabId);
    if (tab && tab.url) {
        await analyzeTab(tabId, tab.url);
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    lastNotifiedByTab.delete(tabId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message) return;

    if (message.type === 'GET_TAB_RESULT') {
        sendResponse(tabResults.get(message.tabId) ?? null);
        return true;
    }

    // handles the case where background flagged the tab before content script was ready
    if (message.type === 'GET_CURRENT_TAB_WARNING') {
        const tabId = sender.tab?.id;
        const result = tabId !== undefined ? tabResults.get(tabId) : null;
        if (result && result.decision === 'phishing') {
            sendResponse({ ...result, url: sender.tab?.url ?? '' });
        } else {
            sendResponse(null);
        }
        return true;
    }

    if (message.type === 'CLOSE_WARNING_TAB') {
        if (!sender.tab || sender.tab.id === undefined) return;
        chrome.tabs.remove(sender.tab.id).catch(() => {});
    }
});

refreshBlacklist();
