/**
 * CyberShield College Beacon — college-beacon.js
 *
 * Shared helper used by BOTH college sites to send attack/access
 * events to the CyberShield backend at localhost:8081.
 *
 * Usage (include in every college page):
 *   <script src="college-beacon.js"></script>
 *
 * Auto-called on page load. Extra calls on form submit.
 */

const CYBERSHIELD_API = 'http://localhost:8081/api/college-events';

/**
 * Send a beacon event to CyberShield
 * @param {Object} event - event payload
 */
async function sendBeacon(event) {
  try {
    const resp = await fetch(CYBERSHIELD_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event)
    });
    if (resp.ok) {
      const result = await resp.json();
      console.log(`[CyberShield] Event processed: ${result.eventType} | Score: ${result.riskScore} | ${result.severity}`);
      return result;
    }
  } catch (err) {
    // Silent fail — don't break the college page UI
    console.warn('[CyberShield] Beacon failed (is the server running?)', err.message);
  }
  return null;
}

/**
 * Detect SQLi patterns in a string
 */
function detectSqli(value) {
  if (!value) return false;
  const patterns = ["'", '"', '--', '1=1', 'OR ', 'UNION', 'SELECT', 'DROP', 'INSERT', 'DELETE', 'admin\''];
  return patterns.some(p => value.toUpperCase().includes(p.toUpperCase()));
}

/**
 * Detect XSS patterns in a string
 */
function detectXss(value) {
  if (!value) return false;
  const patterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert('];
  return patterns.some(p => value.toLowerCase().includes(p.toLowerCase()));
}

/**
 * Auto page-load beacon — fires when a college page is opened
 * @param {string} institutionCode  e.g. "COL-A-SOUTH"
 * @param {string} collegeName      e.g. "College A - South Campus"
 * @param {string} page             e.g. "login"
 * @param {string} eventType        e.g. "PAGE_ACCESS"
 */
function autoBeacon(institutionCode, collegeName, page, eventType = 'PAGE_ACCESS') {
  sendBeacon({
    institutionCode,
    collegeName,
    page,
    eventType,
    attackerIp: 'auto-detected',
    userAgent: navigator.userAgent
  });
}

/**
 * Form submit beacon — fires on form submission, detects attack patterns
 * @param {string} institutionCode
 * @param {string} collegeName
 * @param {string} page
 * @param {string} username         - form field value to inspect
 * @param {string} password         - form field value to inspect
 * @returns {Promise<Object>}       - the processed event from CyberShield
 */
async function formBeacon(institutionCode, collegeName, page, username, password) {
  const combined = (username || '') + ' ' + (password || '');
  let eventType = 'LOGIN_ATTEMPT';
  let inputPayload = combined.trim();

  if (detectSqli(combined)) {
    eventType = 'SQL_INJECTION';
  } else if (detectXss(combined)) {
    eventType = 'XSS';
  }

  const result = await sendBeacon({
    institutionCode,
    collegeName,
    page,
    eventType,
    inputPayload,
    attackerIp: 'auto-detected',
    userAgent: navigator.userAgent
  });

  return result;
}

/**
 * Show a CyberShield detection toast on the page
 */
function showDetectionToast(result) {
  if (!result || result.riskScore < 40) return;

  const colors = {
    'CRITICAL': '#ef4444',
    'HIGH':     '#f97316',
    'MEDIUM':   '#eab308',
    'LOW':      '#10b981'
  };
  const color = colors[result.severity] || '#64748b';

  const toast = document.createElement('div');
  toast.style.cssText = `
    position:fixed;top:16px;right:16px;z-index:9999;
    background:#1e293b;border:1px solid ${color};border-radius:8px;
    padding:12px 16px;max-width:340px;font-family:sans-serif;
    box-shadow:0 4px 20px rgba(0,0,0,0.5);animation:slideIn 0.3s ease;
  `;
  toast.innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
      <span style="font-size:18px;">🛡️</span>
      <span style="color:${color};font-weight:700;font-size:13px;">CyberShield Detected</span>
    </div>
    <div style="color:#cbd5e1;font-size:12px;line-height:1.5;">
      <b>${result.eventType}</b> | Risk Score: <b style="color:${color}">${result.riskScore}/100</b><br>
      ${result.attackPattern || 'Activity logged'}
      ${result.incidentCreated ? `<br>🚨 <a href="http://localhost:8081/incidents.html" style="color:${color};" target="_blank">Incident #${result.incidentId} created</a>` : ''}
    </div>
  `;

  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 6000);
}
