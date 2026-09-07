#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');
const crypto = require('crypto');
const axios = require('axios');
const koffi = require('koffi');
const { execSync } = require('child_process');

try { require('dotenv').config(); } catch { /* ignore if dotenv unavailable */ }

// ======================== 环境变量定义 ========================
const UPLOAD_URL     = process.env.UPLOAD_URL     || '';         // 订阅或节点自动上传地址,需填写部署Merge-sub项目后的首页地址
const PROJECT_URL    = process.env.PROJECT_URL    || '';         // 需要上传订阅或保活时需填写项目分配的url
const AUTO_ACCESS    = process.env.AUTO_ACCESS    || false;      // false关闭自动保活，true开启,需同时填写PROJECT_URL变量
const YT_WARPOUT     = process.env.YT_WARPOUT     || false;      // 设置为true时强制使用warp出站访问youtube
const FILE_PATH      = process.env.FILE_PATH      || '.npm';     // sub.txt订阅文件路径
const SUB_PATH       = process.env.SUB_PATH       || 'sub';      // 订阅sub路径，默认为sub
const UUID           = process.env.UUID           || '0a6568ff-ea3c-4271-9020-450560e10d63'; // UUID，运行哪吒请修改
const NEZHA_SERVER   = process.env.NEZHA_SERVER   || '';         // 哪吒面板地址，v1形式：nz.serv00.net:8008
const NEZHA_PORT     = process.env.NEZHA_PORT     || '';         // v1哪吒请留空，v0 agent端口
const NEZHA_KEY      = process.env.NEZHA_KEY      || '';         // v1的NZ_CLIENT_SECRET或v0 agent密钥
const ARGO_DOMAIN    = process.env.ARGO_DOMAIN    || '';         // argo固定隧道域名,留空即使用临时隧道
const ARGO_AUTH      = process.env.ARGO_AUTH      || '';         // argo固定隧道token或json,留空即使用临时隧道
const ARGO_PORT   = Number(process.env.ARGO_PORT) || 8001;       // argo固定隧道端口
const S5_PORT        = process.env.S5_PORT        || '';         // socks5端口，留空不启用
const TUIC_PORT      = process.env.TUIC_PORT      || '';         // tuic端口，留空不启用
const HY2_PORT       = process.env.HY2_PORT       || '';         // hy2端口，留空不启用
const ANYTLS_PORT    = process.env.ANYTLS_PORT    || '';         // AnyTLS端口，留空不启用
const REALITY_PORT   = process.env.REALITY_PORT   || '';         // reality端口，留空不启用
const CFIP           = process.env.CFIP           || 'saas.sin.fan'; // 优选域名或优选IP
const CFPORT         = Number(process.env.CFPORT) || 443;        // 优选域名或优选IP对应端口
const PORT           = Number(process.env.PORT)   || 3000;       // http订阅端口
const NAME           = process.env.NAME           || '';         // 节点名称
const CHAT_ID        = process.env.CHAT_ID        || '';         // Telegram chat_id，两个变量不全不推送
const BOT_TOKEN      = process.env.BOT_TOKEN      || '';         // Telegram bot_token，两个变量不全不推送
const DISABLE_ARGO   = process.env.DISABLE_ARGO   || false;      // 设置为true时禁用argo
const SHOW_LOG       = !['false', 'disable', 'no'].includes((process.env.SHOW_LOG || 'true').toLowerCase()); // 是否显示日志输出，true/yes显示，false/disable/no屏蔽，默认显示
// ==============================================================

// 控制日志输出
function log(...args) {
  if (SHOW_LOG) console.log(...args);
}

const ROOT = process.cwd();
const runtimeFilePath = path.resolve(ROOT, FILE_PATH);
const libraryDir = runtimeFilePath;
const singBoxConfigPath = path.resolve(runtimeFilePath, 'config.json');
const nezhaConfigPath = path.resolve(runtimeFilePath, 'config.yaml');
const bootLogPath = path.resolve(runtimeFilePath, 'boot.log');
const subPath = path.resolve(runtimeFilePath, 'sub.txt');
const listPath = path.resolve(runtimeFilePath, 'list.txt');
const keypairPath = path.resolve(runtimeFilePath, 'keypair.properties');
const subscribePath = '/' + SUB_PATH.replace(/^\//, '');
const httpPort = PORT;

const arch = (() => {
  const a = os.arch().toLowerCase();
  if (a === 'arm64' || a === 'aarch64') return 'arm64';
  return 'amd64';
})();

let privateKey = '';
let publicKey = '';

// ======================== 辅助函数 ========================

function isValidPort(port) {
  try {
    if (port === null || port === undefined || port === '') return false;
    if (typeof port === 'string' && port.trim() === '') return false;
    const portNum = parseInt(port);
    if (isNaN(portNum)) return false;
    if (portNum < 1 || portNum > 65535) return false;
    return true;
  } catch (error) {
    return false;
  }
}

// ======================== 文件清理 ========================

const pathsToDelete = ['boot.log', 'list.txt', 'config.json', 'config.yaml', 'cert.pem', 'private.key', 'tunnel.json', 'tunnel.yml'];
function cleanupOldFiles() {
  pathsToDelete.forEach(file => {
    const filePath = path.join(FILE_PATH, file);
    fs.unlink(filePath, () => {});
  });
  const tmpDir = path.resolve(ROOT, '.tmp');
  if (fs.existsSync(tmpDir)) {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) { }
  }
}

function cleanupFiles(options = {}) {
  const keepFiles = new Set(['keypair.properties']);
  if (options.keepSub) keepFiles.add('sub.txt');
  if (fs.existsSync(runtimeFilePath)) {
    try {
      const files = fs.readdirSync(runtimeFilePath);
      for (const file of files) {
        if (keepFiles.has(file)) continue;
        const filePath = path.resolve(runtimeFilePath, file);
        try {
          const stat = fs.statSync(filePath);
          if (stat.isDirectory()) {
            fs.rmSync(filePath, { recursive: true, force: true });
          } else {
            fs.unlinkSync(filePath);
          }
        } catch (e) { /* skip locked/in-use files */ }
      }
    } catch (e) {
      log('Cleanup failed:', e.message);
    }
  }
  const tmpDir = path.resolve(ROOT, '.tmp');
  if (fs.existsSync(tmpDir)) {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) { }
  }
}

function clearConsole() {
  process.stdout.write('\x1Bc');
}

// ======================== 节点删除 ========================

function deleteNodes() {
  try {
    if (!UPLOAD_URL) return;
    if (!fs.existsSync(subPath)) return;
    let fileContent;
    try { fileContent = fs.readFileSync(subPath, 'utf-8'); } catch { return null; }
    const decoded = Buffer.from(fileContent, 'base64').toString('utf-8');
    const nodes = decoded.split('\n').filter(line =>
      /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line)
    );
    if (nodes.length === 0) return;
    return axios.post(`${UPLOAD_URL}/api/delete-nodes`,
      JSON.stringify({ nodes }),
      { headers: { 'Content-Type': 'application/json' } }
    ).catch(() => null);
  } catch (err) {
    return null;
  }
}

// ======================== Argo 隧道配置 ========================

function argoType() {
  if (DISABLE_ARGO === 'true' || DISABLE_ARGO === true) {
    log("DISABLE_ARGO is set to true, disable argo tunnel");
    return;
  }
  if (!ARGO_AUTH || !ARGO_DOMAIN) {
    log("ARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnel");
    return;
  }
  if (ARGO_AUTH.includes('TunnelSecret')) {
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.json'), ARGO_AUTH);
    const tunnelYaml = `
  tunnel: ${ARGO_AUTH.split('"')[11]}
  credentials-file: ${path.join(FILE_PATH, 'tunnel.json')}
  protocol: http2
  
  ingress:
    - hostname: ${ARGO_DOMAIN}
      service: http://localhost:${ARGO_PORT}
      originRequest:
        noTLSVerify: true
    - service: http_status:404
  `;
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.yml'), tunnelYaml);
  } else {
    log(`Using token connect to tunnel, please set ${ARGO_PORT} in cloudflare`);
  }
}

// ======================== 下载库文件 ========================

async function sha256Matches(filePath, expected) {
  if (!expected) return true;
  const actual = await sha256(filePath);
  return actual.toLowerCase() === expected.toLowerCase();
}

function sha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

async function downloadLibrary(url, fileName, expectedSha256) {
  const target = path.resolve(libraryDir, fileName);
  if (fs.existsSync(target) && await sha256Matches(target, expectedSha256)) {
    log(`Using cached native library: ${target}`);
    return target;
  }
  await fs.promises.mkdir(libraryDir, { recursive: true });
  const tmp = path.resolve(libraryDir, `${fileName}.download`);
  const fallbackUrl = url.replace(`${arch}.oooen.com`, `${arch}.ssss.nyc.mn`);
  let lastError;
  for (const candidateUrl of [url, fallbackUrl]) {
    try {
      log(`Downloading -> ${target}`);
      const writer = fs.createWriteStream(tmp);
      const response = await axios.get(candidateUrl, { responseType: 'stream', timeout: 3 * 60 * 1000 });
      if (response.status < 200 || response.status >= 300) {
        throw new Error(`Failed to download ${candidateUrl}: HTTP ${response.status}`);
      }
      response.data.pipe(writer);
      await new Promise((resolve, reject) => writer.on('finish', resolve).on('error', reject));
      if (!(await sha256Matches(tmp, expectedSha256))) {
        throw new Error(`SHA-256 mismatch for ${tmp}`);
      }
      await fs.promises.rename(tmp, target);
      return target;
    } catch (error) {
      lastError = error;
      try { await fs.promises.unlink(tmp); } catch { }
      if (candidateUrl === url) {
        log(`Primary download failed, trying fallback: ${error.message}`);
      }
    }
  }
  throw lastError;
}

// ======================== Koffi 服务管理 ========================

function createService(name, libraryPath, startSymbol, stopSymbol, payload) {
  const lib = koffi.load(libraryPath);
  const startFn = lib.func(`int ${startSymbol}(str)`);
  const stopFn = lib.func(`int ${stopSymbol}()`);
  return {
    name,
    start: () => {
      startFn.async(payload || '', (err, code) => {
        if (err) {
          log(`${name} native service failed: ${err.message}`);
        } else if (code !== 0) {
          log(`${name} native service exited with code ${code}`);
        }
      });
    },
    stop: () => new Promise((resolve, reject) => {
      try {
        stopFn.async((err, code) => {
          if (err) return reject(err);
          resolve(code);
        });
      } catch (error) {
        resolve(-1);
      }
    })
  };
}

// ======================== Reality X25519 密钥对 (纯JS) ========================

const _X25519_P = (1n << 255n) - 19n;
const _X25519_A24 = 121665n;

function _clampScalar(buf) {
  buf[0] &= 248;
  buf[31] &= 127;
  buf[31] |= 64;
}

function _mod(value) {
  value = ((value % _X25519_P) + _X25519_P) % _X25519_P;
  return value;
}

function _decodeLE(buf) {
  let result = 0n;
  for (let i = buf.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(buf[i]);
  }
  return result;
}

function _encodeLE(value) {
  const buf = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    buf[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return buf;
}

function _x25519(scalar, u) {
  let x1 = _decodeLE(u);
  let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n;
  let swap = 0;
  for (let t = 254; t >= 0; t--) {
    const byteIdx = Math.floor(t / 8);
    const kt = ((scalar[byteIdx] & 0xff) >> (t % 8)) & 1;
    swap ^= kt;
    if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    swap = kt;
    const a = _mod(x2 + z2);
    const aa = _mod(a * a);
    const b = _mod(x2 - z2 + _X25519_P);
    const bb = _mod(b * b);
    const e = _mod(aa - bb + _X25519_P);
    const c = _mod(x3 + z3);
    const d = _mod(x3 - z3 + _X25519_P);
    const da = _mod(d * a);
    const cb = _mod(c * b);
    x3 = _mod((da + cb) * (da + cb));
    z3 = _mod(x1 * _mod((da - cb + _X25519_P) * (da - cb + _X25519_P)));
    x2 = _mod(aa * bb);
    z2 = _mod(e * _mod(aa + _X25519_A24 * e));
  }
  if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
  const z2inv = _modPow(z2, _X25519_P - 2n, _X25519_P);
  return _encodeLE(_mod(x2 * z2inv));
}

function _modPow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function generateRealityKeyPair() {
  const privateBytes = crypto.randomBytes(32);
  _clampScalar(privateBytes);
  const basepoint = Buffer.alloc(32);
  basepoint[0] = 9;
  const publicBytes = _x25519(privateBytes, basepoint);
  return {
    privateKey: privateBytes.toString('base64url'),
    publicKey: publicBytes.toString('base64url')
  };
}

function generateOrLoadKeyPair() {
  if (fs.existsSync(keypairPath)) {
    const content = fs.readFileSync(keypairPath, 'utf8');
    const privateKeyMatch = content.match(/PrivateKey:\s*(.*)/);
    const publicKeyMatch = content.match(/PublicKey:\s*(.*)/);
    if (privateKeyMatch && publicKeyMatch) {
      privateKey = privateKeyMatch[1];
      publicKey = publicKeyMatch[1];
      log('Private Key:', privateKey);
      log('Public Key:', publicKey);
      return;
    }
  }
  const pair = generateRealityKeyPair();
  privateKey = pair.privateKey;
  publicKey = pair.publicKey;
  fs.writeFileSync(keypairPath, `PrivateKey: ${privateKey}\nPublicKey: ${publicKey}\n`, 'utf8');
  log('Private Key:', privateKey);
  log('Public Key:', publicKey);
}

// ======================== TLS 证书 ========================

const FALLBACK_EC_KEY =
  '-----BEGIN EC PARAMETERS-----\n' +
  'BggqhkjOPQMBBw==\n' +
  '-----END EC PARAMETERS-----\n' +
  '-----BEGIN EC PRIVATE KEY-----\n' +
  'MHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/++siNnfBYsdUYoAoGCCqGSM49\n' +
  'AwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASANnngZreoQDF16ARa\n' +
  '/TsyLyFoPkhLxSbehH/NBEjHtSZGaDhMqQ==\n' +
  '-----END EC PRIVATE KEY-----\n';

const FALLBACK_CERT =
  '-----BEGIN CERTIFICATE-----\n' +
  'MIIBejCCASGgAwIBAgIUfWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw\n' +
  'EzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwOTE4MTgyMDIyWhcNMzUwOTE2MTgy\n' +
  'MDIyWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\n' +
  'A0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgDZ54Ga3qEAxdegEWv07Mi8h\n' +
  'aD5IS8Um3oR/zQRIx7UmRmg4TKmjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR\n' +
  'BfGbgkrMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgkrMNzAPBgNVHRMB\n' +
  'Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAIDAJvg0vd/ytrQVvEcSm6XTlB+\n' +
  'eQ6OFb9LbLYL9f+sAiAffoMbi4y/0YUSlTtz7as9S8/lciBF5VCUoVIKS+vX2g==\n' +
  '-----END CERTIFICATE-----\n';

function ensureTlsCertificates(certPath, keyPath) {
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) return;
  fs.mkdirSync(path.dirname(certPath), { recursive: true });
  try {
    execSync('openssl version', { stdio: 'ignore' });
    execSync(`openssl ecparam -genkey -name prime256v1 -out "${keyPath}"`, { stdio: 'ignore' });
    execSync(`openssl req -new -x509 -days 3650 -key "${keyPath}" -out "${certPath}" -subj "/CN=bing.com"`, { stdio: 'ignore' });
    return;
  } catch (e) { /* openssl not available */ }
  fs.writeFileSync(keyPath, FALLBACK_EC_KEY);
  fs.writeFileSync(certPath, FALLBACK_CERT);
}

// ======================== sing-box 配置生成 ========================

function generateSingBoxConfig(certPath, keyPath) {
  const inbounds = [];

  // VMess+WS inbound (for argo reverse proxy)
  inbounds.push({
    type: 'vmess',
    tag: 'vmess-ws-in',
    listen: '::',
    listen_port: ARGO_PORT,
    users: [{ uuid: UUID }],
    transport: {
      type: 'ws',
      path: '/vmess-argo',
      early_data_header_name: 'Sec-WebSocket-Protocol'
    }
  });

  // Reality
  if (isValidPort(REALITY_PORT)) {
    inbounds.push({
      type: 'vless',
      tag: 'vless-reality',
      listen: '::',
      listen_port: parseInt(REALITY_PORT),
      users: [{ uuid: UUID, flow: 'xtls-rprx-vision' }],
      tls: {
        enabled: true,
        server_name: 'www.iij.ad.jp',
        reality: {
          enabled: true,
          handshake: { server: 'www.iij.ad.jp', server_port: 443 },
          private_key: privateKey,
          short_id: ['']
        }
      }
    });
  }

  // Hysteria2
  if (isValidPort(HY2_PORT)) {
    inbounds.push({
      type: 'hysteria2',
      tag: 'hysteria-in',
      listen: '::',
      listen_port: parseInt(HY2_PORT),
      users: [{ password: UUID }],
      masquerade: 'https://bing.com',
      tls: {
        enabled: true,
        alpn: ['h3'],
        certificate_path: certPath,
        key_path: keyPath
      }
    });
  }

  // TUIC
  if (isValidPort(TUIC_PORT)) {
    inbounds.push({
      type: 'tuic',
      tag: 'tuic-in',
      listen: '::',
      listen_port: parseInt(TUIC_PORT),
      users: [{ uuid: UUID, password: UUID }],
      congestion_control: 'bbr',
      tls: {
        enabled: true,
        alpn: ['h3'],
        certificate_path: certPath,
        key_path: keyPath
      }
    });
  }

  // SOCKS5
  if (isValidPort(S5_PORT)) {
    inbounds.push({
      type: 'socks',
      tag: 's5-in',
      listen: '::',
      listen_port: parseInt(S5_PORT),
      users: [{
        username: UUID.substring(0, 8),
        password: UUID.slice(-12)
      }]
    });
  }

  // AnyTLS
  if (isValidPort(ANYTLS_PORT)) {
    inbounds.push({
      type: 'anytls',
      tag: 'anytls-in',
      listen: '::',
      listen_port: parseInt(ANYTLS_PORT),
      users: [{ password: UUID }],
      tls: {
        enabled: true,
        certificate_path: certPath,
        key_path: keyPath
      }
    });
  }

  // Wireguard endpoint + route rules
  const endpoints = [{
    type: 'wireguard',
    tag: 'wireguard-out',
    mtu: 1280,
    address: ['172.16.0.2/32', '2606:4700:110:8dfe:d141:69bb:6b80:925/128'],
    private_key: 'YFYOAdbw1bKTHlNNi+aEjBM3BO7unuFC5rOkMRAz9XY=',
    peers: [{
      address: 'engage.cloudflareclient.com',
      port: 2408,
      public_key: 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=',
      allowed_ips: ['0.0.0.0/0', '::/0'],
      reserved: [78, 135, 76]
    }]
  }];

  const remoteRuleSet = (tag, url) => ({
    tag,
    type: 'remote',
    format: 'binary',
    url
  });
  const ruleSet = [
    remoteRuleSet('netflix', 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/netflix.srs'),
    remoteRuleSet('openai', 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs')
  ];
  const wireguardRuleSets = ['netflix'];

  // YouTube WARP 出站检测
  let needYoutubeWarp = YT_WARPOUT === true || YT_WARPOUT === 'true';
  if (!needYoutubeWarp) {
    try {
      const youtubeTest = execSync('curl -o /dev/null -m 2 -s -w "%{http_code}" https://www.youtube.com', { encoding: 'utf8' }).trim();
      needYoutubeWarp = youtubeTest !== '200';
    } catch (curlError) {
      if (curlError.output && curlError.output[1]) {
        const test = curlError.output[1].toString().trim();
        needYoutubeWarp = test !== '200';
      } else {
        needYoutubeWarp = true;
      }
    }
  }
  if (needYoutubeWarp) {
    ruleSet.push(remoteRuleSet('youtube', 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs'));
    wireguardRuleSets.push('youtube');
    log('Add YouTube outbound rule');
  }

  const route = {
    default_http_client: 'http-client-direct',
    rule_set: ruleSet,
    rules: [{ rule_set: wireguardRuleSets, outbound: 'wireguard-out' }],
    final: 'direct'
  };

  return {
    log: { disabled: true, level: 'error', timestamp: true },
    http_clients: [{ tag: 'http-client-direct' }],
    inbounds,
    endpoints,
    outbounds: [{ type: 'direct', tag: 'direct' }],
    route
  };
}

// ======================== nezha 配置生成 ========================

function generateNezhaConfig() {
  const nzport = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
  const tlsPorts = new Set(['443', '8443', '2096', '2087', '2083', '2053']);
  const nezhatls = tlsPorts.has(nzport) ? 'true' : 'false';
  const configYaml = `client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: ${NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${nezhatls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}`;
  fs.writeFileSync(nezhaConfigPath, configYaml, 'utf8');
}

// ======================== Cloudflared Payload ========================

function cloudflaredPayload() {
  if (DISABLE_ARGO === 'true' || DISABLE_ARGO === true) return null;
  if (ARGO_AUTH && ARGO_DOMAIN) {
    if (ARGO_AUTH.match(/^[A-Z0-9a-z=]{120,250}$/)) {
      return JSON.stringify({
        args: ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2', 'run', '--token', ARGO_AUTH]
      });
    } else if (ARGO_AUTH.match(/TunnelSecret/)) {
      return JSON.stringify({
        args: ['tunnel', '--edge-ip-version', 'auto', '--config', path.join(FILE_PATH, 'tunnel.yml'), 'run']
      });
    }
  }
  // Quick tunnel
  return JSON.stringify({
    args: [
      'tunnel', '--edge-ip-version', 'auto', '--no-autoupdate',
      '--protocol', 'http2', '--logfile', bootLogPath,
      '--loglevel', 'info', '--url', `http://localhost:${ARGO_PORT}`
    ]
  });
}

function singBoxPayload() {
  return JSON.stringify({ config: singBoxConfigPath, workingDir: '.', disableColor: true });
}

function nezhaPayload() {
  return JSON.stringify({ config: nezhaConfigPath });
}

// ======================== 隧道域名检测 ========================

function waitForQuickTunnelDomain(logPath, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if (fs.existsSync(logPath)) {
        const content = fs.readFileSync(logPath, 'utf8');
        const matches = [...content.matchAll(/https:\/\/([A-Za-z0-9.-]+\.trycloudflare\.com)/g)];
        if (matches.length > 0) {
          return matches[matches.length - 1][1];
        }
      }
    } catch (e) { /* file may not exist yet */ }
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    const sleepMs = Math.min(1000, remaining);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, sleepMs);
  }
  return null;
}

async function extractDomain() {
  if (DISABLE_ARGO === 'true' || DISABLE_ARGO === true) return null;
  if (ARGO_AUTH && ARGO_DOMAIN) {
    log('ARGO_DOMAIN:', ARGO_DOMAIN);
    return ARGO_DOMAIN;
  }
  // Quick tunnel
  log('Waiting for quick tunnel domain in log...');
  let domain = waitForQuickTunnelDomain(bootLogPath, 30000);
  if (!domain) {
    log('Quick tunnel domain not found, retrying...');
    try { fs.unlinkSync(bootLogPath); } catch (e) { }
    await new Promise(r => setTimeout(r, 5000));
    domain = waitForQuickTunnelDomain(bootLogPath, 30000);
  }
  if (domain) {
    log('ArgoDomain:', domain);
  } else {
    log('ArgoDomain not found');
  }
  return domain;
}

// ======================== ISP 信息 ========================

async function getMetaInfo() {
  try {
    const response1 = await axios.get('https://api.ip.sb/geoip', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 } });
    if (response1.data && response1.data.country_code && response1.data.isp) {
      return `${response1.data.country_code}-${response1.data.isp}`.replace(/\s+/g, '_');
    }
  } catch (error) {
    try {
      const response2 = await axios.get('http://ip-api.com/json', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 } });
      if (response2.data && response2.data.status === 'success' && response2.data.countryCode && response2.data.org) {
        return `${response2.data.countryCode}-${response2.data.org}`.replace(/\s+/g, '_');
      }
    } catch (error) { /* backup also failed */ }
  }
  return 'Unknown';
}

// ======================== 节点链接生成 ========================

async function generateLinks(argoDomain) {
  let SERVER_IP = '';
  try {
    const ipv4Response = await axios.get('http://ipv4.ip.sb', { timeout: 3000 });
    SERVER_IP = ipv4Response.data.trim();
  } catch (err) {
    try {
      SERVER_IP = execSync('curl -sm 3 ipv4.ip.sb').toString().trim();
    } catch (curlErr) {
      try {
        const ipv6Response = await axios.get('http://ipv6.ip.sb', { timeout: 3000 });
        SERVER_IP = `[${ipv6Response.data.trim()}]`;
      } catch (ipv6AxiosErr) {
        try {
          SERVER_IP = `[${execSync('curl -sm 3 ipv6.ip.sb').toString().trim()}]`;
        } catch (ipv6CurlErr) {
          log('Failed to get IP address:', ipv6CurlErr.message);
        }
      }
    }
  }

  const ISP = await getMetaInfo();
  const nodeName = NAME ? `${NAME}-${ISP}` : ISP;

  await new Promise(r => setTimeout(r, 2000));

  let subTxt = '';

  // VMess+WS (argo)
  if ((DISABLE_ARGO !== 'true' && DISABLE_ARGO !== true) && argoDomain) {
    const vmessNode = `vmess://${Buffer.from(JSON.stringify({ v: '2', ps: `${nodeName}`, add: CFIP, port: CFPORT, id: UUID, aid: '0', scy: 'auto', net: 'ws', type: 'none', host: argoDomain, path: '/vmess-argo?ed=2560', tls: 'tls', sni: argoDomain, alpn: '', fp: 'firefox' })).toString('base64')}`;
    subTxt = vmessNode;
  }

  // TUIC
  if (isValidPort(TUIC_PORT)) {
    subTxt += `\ntuic://${UUID}:${UUID}@${SERVER_IP}:${TUIC_PORT}?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#${nodeName}`;
  }

  // Hysteria2
  if (isValidPort(HY2_PORT)) {
    subTxt += `\nhysteria2://${UUID}@${SERVER_IP}:${HY2_PORT}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#${nodeName}`;
  }

  // Reality
  if (isValidPort(REALITY_PORT)) {
    subTxt += `\nvless://${UUID}@${SERVER_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=firefox&pbk=${publicKey}&type=tcp&headerType=none#${nodeName}`;
  }

  // AnyTLS
  if (isValidPort(ANYTLS_PORT)) {
    subTxt += `\nanytls://${UUID}@${SERVER_IP}:${ANYTLS_PORT}?security=tls&sni=${SERVER_IP}&fp=chrome&insecure=1&allowInsecure=1#${nodeName}`;
  }

  // SOCKS5
  if (isValidPort(S5_PORT)) {
    const S5_AUTH = Buffer.from(`${UUID.substring(0, 8)}:${UUID.slice(-12)}`).toString('base64');
    subTxt += `\nsocks://${S5_AUTH}@${SERVER_IP}:${S5_PORT}#${nodeName}`;
  }

  // 打印绿色 base64 编码
  log('\x1b[32m' + Buffer.from(subTxt).toString('base64') + '\x1b[0m');
  log('\x1b[35m' + 'Logs will be deleted in 45 seconds, you can copy the above nodes' + '\x1b[0m');

  fs.writeFileSync(subPath, Buffer.from(subTxt).toString('base64'));
  fs.writeFileSync(listPath, subTxt, 'utf8');
  log(`${FILE_PATH}/sub.txt saved successfully`);

  return subTxt;
}

// ======================== Telegram 推送 ========================

async function sendTelegram() {
  if (!BOT_TOKEN || !CHAT_ID) {
    log('TG variables is empty, Skipping push nodes to TG');
    return;
  }
  try {
    const message = fs.readFileSync(subPath, 'utf8');
    const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
    const escapedName = NAME.replace(/[_*[\]()~`>#+=|{}.!-]/g, '\\$&');
    const params = {
      chat_id: CHAT_ID,
      text: `**${escapedName}节点推送通知**\n\`\`\`${message}\`\`\``,
      parse_mode: 'MarkdownV2'
    };
    await axios.post(url, null, { params });
    log('Telegram message sent successfully');
  } catch (error) {
    log('Failed to send Telegram message', error);
  }
}

// ======================== 节点上传 ========================

async function uploadNodes() {
  if (UPLOAD_URL && PROJECT_URL) {
    const subscriptionUrl = `${PROJECT_URL}/${SUB_PATH}`;
    const jsonData = { subscription: [subscriptionUrl] };
    try {
      const response = await axios.post(`${UPLOAD_URL}/api/add-subscriptions`, jsonData, {
        headers: { 'Content-Type': 'application/json' }
      });
      if (response.status === 200) log('Subscription uploaded successfully');
    } catch (error) { /* ignore */ }
  } else if (UPLOAD_URL) {
    if (!fs.existsSync(listPath)) return;
    const content = fs.readFileSync(listPath, 'utf-8');
    const nodes = content.split('\n').filter(line => /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line));
    if (nodes.length === 0) return;
    try {
      const response = await axios.post(`${UPLOAD_URL}/api/add-nodes`,
        JSON.stringify({ nodes }),
        { headers: { 'Content-Type': 'application/json' } }
      );
      if (response.status === 200) log('Subscription uploaded successfully');
    } catch (error) { /* ignore */ }
  }
}

// ======================== 自动保活 ========================

async function addVisitTask() {
  if (!AUTO_ACCESS || !PROJECT_URL) {
    log('Skipping adding automatic access task');
    return;
  }
  try {
    await axios.post('https://keep.gvrander.eu.org/add-url', {
      url: PROJECT_URL
    }, { headers: { 'Content-Type': 'application/json' } });
    log('Automatic access task added successfully');
  } catch (error) {
    log(`Add URL failed: ${error.message}`);
  }
}

// ======================== HTTP 服务器 ========================

function startHttpServer(subTxt) {
  const server = http.createServer((req, res) => {
    if (req.method !== 'GET') {
      res.statusCode = 405;
      res.end('Method Not Allowed');
      return;
    }
    const url = new URL(req.url, `http://localhost`);
    if (url.pathname === subscribePath) {
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      const encodedContent = Buffer.from(subTxt).toString('base64');
      res.end(encodedContent);
    } else if (url.pathname === '/') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(`Hello world!<br><br>You can access /${SUB_PATH}(Default: /sub) get your nodes!`);
    } else {
      res.statusCode = 404;
      res.end('Not Found');
    }
  });

  function tryListen(port, retries) {
    server.listen(port, '0.0.0.0', () => {
      console.log(`Server is running on port ${port}`);
    });
    server.once('error', err => {
      if (err.code === 'EADDRINUSE' && retries > 0) {
        log(`Port ${port} in use, trying ${port + 1}...`);
        tryListen(port + 1, retries - 1);
      } else {
        log('HTTP server error:', err.message);
      }
    });
  }

  tryListen(httpPort, 5);
}

// ======================== 主流程 ========================

async function startServer() {
  // 1. 删除旧节点
  deleteNodes();

  // 2. 创建运行目录 + 清理文件
  if (!fs.existsSync(FILE_PATH)) {
    fs.mkdirSync(FILE_PATH);
    log(`${FILE_PATH} is created`);
  }
  cleanupOldFiles();

  // 3. 生成 Argo 隧道配置
  argoType();

  // 4. 下载 .so 库文件
  const baseUrl = `https://${arch}.oooen.com`;
  const singBoxLib = await downloadLibrary(`${baseUrl}/sbx.so`, 'sbx.so');
  let cloudflaredLib = null;
  let nezhaLib = null;

  if (DISABLE_ARGO !== 'true' && DISABLE_ARGO !== true) {
    cloudflaredLib = await downloadLibrary(`${baseUrl}/bot.so`, 'bot.so');
  }

  if (NEZHA_SERVER && NEZHA_KEY) {
    nezhaLib = await downloadLibrary(`${baseUrl}/v1.so`, 'v1.so');
  } else {
    log('NEZHA variable is empty, skipping nezha-agent');
  }

  // 5. 生成 Reality 密钥对
  if (REALITY_PORT) {
    generateOrLoadKeyPair();
  }

  // 6. 生成 TLS 证书
  const certPath = path.join(FILE_PATH, 'cert.pem');
  const keyPath = path.join(FILE_PATH, 'private.key');
  const needsTls = !!(HY2_PORT || TUIC_PORT || ANYTLS_PORT);
  if (needsTls) {
    ensureTlsCertificates(certPath, keyPath);
  }

  // 7. 生成 nezha config
  if (NEZHA_SERVER && NEZHA_KEY && !NEZHA_PORT) {
    generateNezhaConfig();
  }

  // 8. 生成 sing-box config.json
  const sbxConfig = generateSingBoxConfig(certPath, keyPath);
  fs.writeFileSync(singBoxConfigPath, JSON.stringify(sbxConfig, null, 2));

  // 9. 启动服务
  const services = [];

  // sing-box
  const singBoxService = createService('sing-box', singBoxLib, 'StartSingBox', 'StopSingBox', singBoxPayload());
  services.push(singBoxService);

  // cloudflared
  let cloudflaredService = null;
  if (cloudflaredLib) {
    const cfPayload = cloudflaredPayload();
    if (cfPayload) {
      cloudflaredService = createService('cloudflared', cloudflaredLib, 'StartCloudflared', 'StopCloudflared', cfPayload);
      services.push(cloudflaredService);
    }
  }

  // nezha
  let nezhaService = null;
  if (nezhaLib) {
    nezhaService = createService('nezha-agent', nezhaLib, 'StartNezhaAgent', 'StopNezhaAgent', nezhaPayload());
    services.push(nezhaService);
  }

  // 信号监听
  async function stopAll() {
    for (let i = services.length - 1; i >= 0; i--) {
      try { await services[i].stop(); } catch (e) { }
    }
    process.exit(0);
  }
  process.on('SIGINT', stopAll);
  process.on('SIGTERM', stopAll);

  services.forEach(service => service.start());
  await new Promise(r => setTimeout(r, 1000));
  log('web is running');
  if (cloudflaredService) log('bot is running');
  if (nezhaService) log('php is running');

  // 10. 等待并检测隧道域名
  await new Promise(r => setTimeout(r, 5000));
  const argoDomain = await extractDomain();

  // 11. 生成节点链接
  const subTxt = await generateLinks(argoDomain);

  // 12. 启动 HTTP 服务器
  startHttpServer(subTxt);

  // 13. Telegram 推送 + 节点上传 + 自动保活
  await sendTelegram();
  await uploadNodes();
  await addVisitTask();

  // 14. 45秒后清理文件 + 清屏 + 打印欢迎语
  setTimeout(() => {
    cleanupFiles({ keepSub: true });
    clearConsole();
    console.log('App is running');
    log('Thank you for using this script, enjoy!');
  }, 45000);
}

startServer();
setInterval(() => {}, 1000);
