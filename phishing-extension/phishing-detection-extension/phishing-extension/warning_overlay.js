const OVERLAY_ID = 'phishing-extension-warning-overlay';
const OVERLAY_STYLE_ID = 'phishing-extension-warning-overlay-style';
let lastShownUrl = null;
let audioUnlocked = Boolean(navigator.userActivation?.isActive);
let pendingSoundPlayback = false;
let audioUnlockListenersBound = false;

bindAudioUnlockListeners();

// check if the tab was already flagged before this script loaded
chrome.runtime.sendMessage({ type: 'GET_CURRENT_TAB_WARNING' }, (response) => {
    if (chrome.runtime.lastError) return;
    if (response && response.decision === 'phishing' && lastShownUrl !== response.url) {
        lastShownUrl = response.url;
        showWarningOverlay(response);
        playWarningSound();
    }
});

chrome.runtime.onMessage.addListener((message) => {
    if (!message || !message.type) return;

    if (message.type === 'SHOW_PHISHING_WARNING') {
        if (lastShownUrl === message.url) return;
        lastShownUrl = message.url;
        showWarningOverlay(message);
        playWarningSound();
    }

    if (message.type === 'CLEAR_PHISHING_WARNING') {
        clearWarningOverlay();
        lastShownUrl = null;
    }
});

function showWarningOverlay(data) {
    clearWarningOverlay();
    ensureOverlayStyles();

    const wrap = document.createElement('div');
    wrap.id = OVERLAY_ID;
    wrap.className = 'pdx-warning-overlay';
    wrap.addEventListener('click', (event) => {
        if (event.target === wrap) {
            clearWarningOverlay();
        }
    });

    const reasons = Array.isArray(data.reasons) ? data.reasons : [];
    const modal = document.createElement('div');
    modal.className = 'pdx-warning-modal';
    modal.innerHTML = `
        <div class="pdx-warning-topbar">
            <div class="pdx-warning-brand">
                <span class="pdx-warning-brand-mark">PD</span>
                <span>Phishing Detector</span>
            </div>
            <span class="pdx-warning-chip">Blocked</span>
        </div>

        <div class="pdx-warning-hero">
            <div class="pdx-warning-icon-wrap">
                <div class="pdx-warning-icon">!</div>
            </div>
            <div class="pdx-warning-copy">
                <h2>Potential phishing page detected</h2>
                <p>${getSummaryText(data.decisionSource)}</p>
            </div>
        </div>

        <div class="pdx-warning-url" title="${escapeHtml(data.url || '')}">${escapeHtml(data.url || '')}</div>

        <div class="pdx-warning-metrics">
            <div class="pdx-warning-metric">
                <span class="pdx-warning-metric-label">Confidence</span>
                <span class="pdx-warning-metric-value">${escapeHtml(data.confidence || 'High')}</span>
            </div>
            <div class="pdx-warning-metric">
                <span class="pdx-warning-metric-label">Signals</span>
                <span class="pdx-warning-metric-value">${getSignalCount(reasons, data.blacklistMatch)}</span>
            </div>
        </div>

        <div class="pdx-warning-reason-box">
            <div class="pdx-warning-reason-title">Why this was flagged</div>
            <ul class="pdx-warning-reason-list">
                ${buildReasonListHtml(reasons)}
            </ul>
        </div>

        <div class="pdx-warning-footer">
            <div class="pdx-warning-footer-line">
                Protection for <strong>${escapeHtml(formatUrlLabel(data.url))}</strong>
            </div>
            <div class="pdx-warning-footer-line">
                Source: ${escapeHtml(formatSourceLabel(data.decisionSource, data.blacklistMatch))}
            </div>
        </div>

        <div class="pdx-warning-actions">
            <button type="button" class="pdx-warning-button pdx-warning-button-primary" data-action="dismiss">Dismiss warning</button>
            <button type="button" class="pdx-warning-button pdx-warning-button-secondary" data-action="back">Go back</button>
        </div>
    `;

    modal.querySelector('[data-action="dismiss"]').addEventListener('click', clearWarningOverlay);
    modal.querySelector('[data-action="back"]').addEventListener('click', handleBackAction);

    wrap.appendChild(modal);
    document.documentElement.appendChild(wrap);
}

function getSummaryText(decisionSource) {
    if (decisionSource === 'blacklist') {
        return 'This page matched a blacklist entry and should be treated as unsafe.';
    }

    return 'This page looks like phishing. Avoid entering passwords, payment details, or recovery codes.';
}

function buildReasonListHtml(reasons) {
    const items = reasons.slice(0, 2);
    if (items.length === 0) {
        return '<li>Matched phishing-like URL pattern.</li>';
    }

    return items.map((reason) => `<li>${escapeHtml(reason)}</li>`).join('');
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

function formatUrlLabel(url) {
    if (typeof url !== 'string' || !url.trim()) {
        return 'Current page';
    }

    try {
        const parsedUrl = new URL(url);
        return parsedUrl.hostname || `${parsedUrl.protocol.replace(':', '')} page`;
    } catch (error) {
        return 'Current page';
    }
}

function ensureOverlayStyles() {
    if (document.getElementById(OVERLAY_STYLE_ID)) return;

    const style = document.createElement('style');
    style.id = OVERLAY_STYLE_ID;
    style.textContent = `
        .pdx-warning-overlay {
            position: fixed;
            inset: 0;
            z-index: 2147483647;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            background: rgba(26, 33, 52, 0.38);
            backdrop-filter: blur(6px);
        }

        .pdx-warning-modal,
        .pdx-warning-modal * {
            box-sizing: border-box;
            font-family: "Avenir Next", "Trebuchet MS", "Segoe UI", sans-serif;
        }

        .pdx-warning-modal {
            width: 100%;
            max-width: 560px;
            padding: 18px;
            border-radius: 24px;
            border: 1px solid #f0bcc5;
            background: linear-gradient(180deg, #eef2ff 0%, #ffffff 116px);
            box-shadow: 0 24px 60px rgba(14, 23, 47, 0.24);
            color: #20263a;
        }

        .pdx-warning-topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
        }

        .pdx-warning-brand {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            color: #314dd4;
            font-size: 16px;
            font-weight: 800;
            letter-spacing: -0.03em;
        }

        .pdx-warning-brand-mark {
            width: 24px;
            height: 24px;
            display: grid;
            place-items: center;
            border-radius: 999px;
            background: rgba(255, 255, 255, 0.9);
            box-shadow: 0 8px 18px rgba(65, 91, 173, 0.12);
            font-size: 11px;
            font-weight: 900;
        }

        .pdx-warning-chip {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 7px 12px;
            border-radius: 999px;
            background: #ffe8ec;
            color: #b8394d;
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .pdx-warning-hero {
            display: flex;
            gap: 16px;
            align-items: center;
            margin-top: 18px;
            padding: 18px;
            border-radius: 20px;
            background: rgba(255, 255, 255, 0.88);
        }

        .pdx-warning-icon-wrap {
            flex: 0 0 72px;
            width: 72px;
            height: 72px;
            border-radius: 50%;
            display: grid;
            place-items: center;
            background: radial-gradient(circle at center, #ffffff 0%, #fff2f4 60%, #fde7eb 100%);
            box-shadow: 0 12px 24px rgba(170, 72, 89, 0.12);
        }

        .pdx-warning-icon {
            width: 42px;
            height: 42px;
            display: grid;
            place-items: center;
            border-radius: 14px;
            color: #b8394d;
            font-size: 24px;
            font-weight: 900;
            background: #ffe8ec;
        }

        .pdx-warning-copy h2 {
            margin: 0;
            color: #b12136;
            font-size: 28px;
            line-height: 1;
            font-weight: 800;
            letter-spacing: -0.04em;
        }

        .pdx-warning-copy p {
            margin: 10px 0 0;
            color: #69728d;
            font-size: 14px;
            line-height: 1.5;
        }

        .pdx-warning-url {
            margin-top: 14px;
            padding: 10px 12px;
            border-radius: 14px;
            border: 1px solid #dde3f2;
            background: #f6f8ff;
            color: #5d6781;
            font-family: "SFMono-Regular", "Consolas", "Liberation Mono", monospace;
            font-size: 11px;
            line-height: 1.5;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .pdx-warning-metrics {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 10px;
            margin-top: 14px;
        }

        .pdx-warning-metric {
            padding: 12px 14px;
            border-radius: 16px;
            background: #f6f8ff;
        }

        .pdx-warning-metric-label {
            display: block;
            color: #69728d;
            font-size: 10px;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .pdx-warning-metric-value {
            display: block;
            margin-top: 6px;
            color: #20263a;
            font-size: 16px;
            font-weight: 800;
        }

        .pdx-warning-reason-box {
            margin-top: 14px;
            padding: 14px;
            border-radius: 18px;
            border: 1px solid #ffd1d9;
            background: #fff7f8;
        }

        .pdx-warning-reason-title {
            color: #b12136;
            font-size: 13px;
            font-weight: 800;
        }

        .pdx-warning-reason-list {
            margin: 8px 0 0;
            padding-left: 18px;
            color: #7e3a47;
            font-size: 13px;
            line-height: 1.5;
        }

        .pdx-warning-footer {
            display: grid;
            gap: 4px;
            margin-top: 14px;
            color: #69728d;
            font-size: 12px;
            line-height: 1.45;
        }

        .pdx-warning-footer strong {
            color: #20263a;
            font-weight: 800;
        }

        .pdx-warning-actions {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 10px;
            margin-top: 16px;
        }

        .pdx-warning-button {
            border: 0;
            border-radius: 16px;
            padding: 13px 16px;
            font-size: 14px;
            font-weight: 800;
            cursor: pointer;
        }

        .pdx-warning-button-primary {
            background: #de3447;
            color: #ffffff;
            box-shadow: 0 10px 22px rgba(217, 83, 100, 0.24);
        }

        .pdx-warning-button-secondary {
            background: #f6f8ff;
            color: #20263a;
            border: 1px solid #dde3f2;
        }

        @media (max-width: 640px) {
            .pdx-warning-overlay {
                padding: 12px;
            }

            .pdx-warning-modal {
                padding: 14px;
            }

            .pdx-warning-topbar,
            .pdx-warning-hero,
            .pdx-warning-metrics,
            .pdx-warning-actions {
                grid-template-columns: 1fr;
            }

            .pdx-warning-topbar {
                display: grid;
            }

            .pdx-warning-hero {
                display: grid;
            }

            .pdx-warning-copy h2 {
                font-size: 24px;
            }
        }
    `;

    document.documentElement.appendChild(style);
}

function escapeHtml(text) {
    return String(text)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

function bindAudioUnlockListeners() {
    if (audioUnlockListenersBound) return;

    const unlockAudio = () => {
        audioUnlocked = true;

        if (pendingSoundPlayback && document.getElementById(OVERLAY_ID)) {
            pendingSoundPlayback = false;
            playWarningSound();
        }
    };

    window.addEventListener('pointerdown', unlockAudio, { capture: true });
    window.addEventListener('keydown', unlockAudio, { capture: true });
    audioUnlockListenersBound = true;
}

// Remove warning overlay if it exists.
function clearWarningOverlay() {
    const existing = document.getElementById(OVERLAY_ID);
    if (existing) existing.remove();
    pendingSoundPlayback = false;
}

function handleBackAction() {
    if (window.history.length <= 1) {
        requestTabClose();
        return;
    }

    let navigationStarted = false;
    const markNavigated = () => {
        navigationStarted = true;
        window.removeEventListener('pagehide', markNavigated);
        window.removeEventListener('popstate', markNavigated);
    };

    window.addEventListener('pagehide', markNavigated, { once: true });
    window.addEventListener('popstate', markNavigated, { once: true });
    window.history.back();

    window.setTimeout(() => {
        if (!navigationStarted) {
            window.removeEventListener('pagehide', markNavigated);
            window.removeEventListener('popstate', markNavigated);
            requestTabClose();
        }
    }, 450);
}

function requestTabClose() {
    chrome.runtime.sendMessage({ type: 'CLOSE_WARNING_TAB' }).catch(() => {
        window.close();
    });
}

function playWarningSound() {
    try {
        audioUnlocked = audioUnlocked || Boolean(navigator.userActivation?.isActive);
        if (!audioUnlocked) {
            pendingSoundPlayback = true;
            return;
        }

        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (!AudioCtx) return;

        const ctx = new AudioCtx();
        const playSequence = () => {
            playBeep(ctx, 0.00, 880, 0.12);
            playBeep(ctx, 0.18, 740, 0.12);
            playBeep(ctx, 0.36, 880, 0.18);

            setTimeout(() => {
                ctx.close().catch(() => { });
            }, 900);
        };

        if (ctx.state === 'suspended') {
            ctx.resume().then(playSequence).catch(() => {
                ctx.close().catch(() => { });
            });
            return;
        }

        playSequence();
    } catch (error) {
        // If blocked by browser autoplay policy, warning overlay still appears.
    }
}

function playBeep(ctx, startOffset, frequency, duration) {
    const now = ctx.currentTime + startOffset;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = 'sine';
    osc.frequency.value = frequency;
    gain.gain.value = 0.0001;

    osc.connect(gain);
    gain.connect(ctx.destination);

    gain.gain.exponentialRampToValueAtTime(0.18, now + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + duration);

    osc.start(now);
    osc.stop(now + duration + 0.02);
}
