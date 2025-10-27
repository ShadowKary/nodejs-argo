#!/usr/bin/env node

const express = require("express");
const app = express();
const axios = require("axios");
const os = require('os');
const fs = require("fs");
const path = require("path");
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const { execSync } = require('child_process');
const UPLOAD_URL = process.env.UPLOAD_URL || '';
const PROJECT_URL = process.env.PROJECT_URL || '';
const AUTO_ACCESS = process.env.AUTO_ACCESS || false;
const YT_WARPOUT = process.env.YT_WARPOUT || false;
const FILE_PATH = process.env.FILE_PATH || '.npm';
const SUB_PATH = process.env.SUB_PATH || 'sub';
const UUID = process.env.UUID || '';
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';
const NEZHA_PORT = process.env.NEZHA_PORT || '';
const NEZHA_KEY = process.env.NEZHA_KEY || '';
const ARGO_DOMAIN = process.env.ARGO_DOMAIN || '';
const ARGO_AUTH = process.env.ARGO_AUTH || '';
const ARGO_PORT = process.env.ARGO_PORT || 8001;
const TUIC_PORT = process.env.TUIC_PORT || '';
const HY2_PORT = process.env.HY2_PORT || '';
const REALITY_PORT = process.env.REALITY_PORT || '';
const CFIP = process.env.CFIP || 'cdns.doon.eu.org';
const CFPORT = process.env.CFPORT || 443;
const PORT = process.env.PORT || 3000;
const NAME = process.env.NAME || '';
const CHAT_ID = process.env.CHAT_ID || '';
const BOT_TOKEN = process.env.BOT_TOKEN || '';

if (!fs.existsSync(FILE_PATH)) {
  fs.mkdirSync(FILE_PATH);
  console.log(`${FILE_PATH} is created`);
} else {
  console.log(`${FILE_PATH} already exists`);
}

let privateKey = '';
let publicKey = '';

function generateRandomName() {
  const chars = 'abcdefghijklmnopqrstuvwxyz';
  let result = '';
  for (let i = 0; i < 6; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

const npmRandomName = generateRandomName();
const webRandomName = generateRandomName();
const botRandomName = generateRandomName();
const phpRandomName = generateRandomName();

let npmPath = path.join(FILE_PATH, npmRandomName);
let phpPath = path.join(FILE_PATH, phpRandomName);
let webPath = path.join(FILE_PATH, webRandomName);
let botPath = path.join(FILE_PATH, botRandomName);
let subPath = path.join(FILE_PATH, 'sub.txt');
let listPath = path.join(FILE_PATH, 'list.txt');
let bootLogPath = path.join(FILE_PATH, 'boot.log');
let configPath = path.join(FILE_PATH, 'config.json');

function deleteNodes() {
  try {
    if (!UPLOAD_URL) return;

    const subPath = path.join(FILE_PATH, 'sub.txt');
    if (!fs.existsSync(subPath)) return;

    let fileContent;
    try {
      fileContent = fs.readFileSync(subPath, 'utf-8');
    } catch {
      return null;
    }

    const decoded = Buffer.from(fileContent, 'base64').toString('utf-8');
    const nodes = decoded.split('\n').filter(line => 
      /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line)
    );

    if (nodes.length === 0) return;

    return axios.post(`${UPLOAD_URL}/api/delete-nodes`, 
      JSON.stringify({ nodes }),
      { headers: { 'Content-Type': 'application/json' } }
    ).catch((error) => { 
      return null; 
    });
  } catch (err) {
    return null;
  }
}

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

const pathsToDelete = [ webRandomName, botRandomName, npmRandomName, 'boot.log', 'list.txt'];
function cleanupOldFiles() {
  pathsToDelete.forEach(file => {
    const filePath = path.join(FILE_PATH, file);
    fs.unlink(filePath, () => {});
  });
}


app.get("/", function(req, res) {
  res.send("Hello world!");
});

function argoType() {
  if (!ARGO_AUTH || !ARGO_DOMAIN) {
    console.log("ARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels");
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
    console.log("ARGO_AUTH mismatch TunnelSecret,use token connect to tunnel");
  }
}

function getSystemArchitecture() {
  const arch = os.arch();
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    return 'arm';
  } else {
    return 'amd';
  }
}

function downloadFile(fileName, fileUrl, callback) {
  const filePath = path.join(FILE_PATH, fileName);
  const writer = fs.createWriteStream(filePath);

  axios({
    method: 'get',
    url: fileUrl,
    responseType: 'stream',
  })
    .then(response => {
      response.data.pipe(writer);

      writer.on('finish', () => {
        writer.close();
        console.log(`Download ${fileName} successfully`);
        callback(null, fileName);
      });

      writer.on('error', err => {
        fs.unlink(filePath, () => { });
        const errorMessage = `Download ${fileName} failed: ${err.message}`;
        console.error(errorMessage);
        callback(errorMessage);
      });
    })
    .catch(err => {
      const errorMessage = `Download ${fileName} failed: ${err.message}`;
      console.error(errorMessage);
      callback(errorMessage);
    });
}

async function downloadFilesAndRun() {
  const architecture = getSystemArchitecture();
  const filesToDownload = getFilesForArchitecture(architecture);

  if (filesToDownload.length === 0) {
    console.log(`Can't find a file for the current architecture`);
    return;
  }

  const renamedFiles = filesToDownload.map(file => {
    let newFileName;
    if (file.fileName === 'npm') {
      newFileName = npmRandomName;
    } else if (file.fileName === 'web') {
      newFileName = webRandomName;
    } else if (file.fileName === 'bot') {
      newFileName = botRandomName;
    } else if (file.fileName === 'php') {
      newFileName = phpRandomName;
    } else {
      newFileName = file.fileName;
    }
    return { ...file, fileName: newFileName };
  });

  const downloadPromises = renamedFiles.map(fileInfo => {
    return new Promise((resolve, reject) => {
      downloadFile(fileInfo.fileName, fileInfo.fileUrl, (err, fileName) => {
        if (err) {
          reject(err);
        } else {
          resolve(fileName);
        }
      });
    });
  });

  try {
    await Promise.all(downloadPromises);
  } catch (err) {
    console.error('Error downloading files:', err);
    return;
  }

  function authorizeFiles(filePaths) {
    const newPermissions = 0o775;
    filePaths.forEach(relativeFilePath => {
      const absoluteFilePath = path.join(FILE_PATH, relativeFilePath);
      if (fs.existsSync(absoluteFilePath)) {
        fs.chmod(absoluteFilePath, newPermissions, (err) => {
          if (err) {
            console.error(`Empowerment failed for ${absoluteFilePath}: ${err}`);
          } else {
            console.log(`Empowerment success for ${absoluteFilePath}: ${newPermissions.toString(8)}`);
          }
        });
      }
    });
  }
  const filesToAuthorize = NEZHA_PORT ? [npmRandomName, webRandomName, botRandomName] : [phpRandomName, webRandomName, botRandomName];
  authorizeFiles(filesToAuthorize);

  const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
  const tlsPorts = new Set(['443', '8443', '2096', '2087', '2083', '2053']);
  const nezhatls = tlsPorts.has(port) ? 'true' : 'false';

  if (NEZHA_SERVER && NEZHA_KEY) {
    if (!NEZHA_PORT) {
      const configYaml = `
client_secret: ${NEZHA_KEY}
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
      
      fs.writeFileSync(path.join(FILE_PATH, 'config.yaml'), configYaml);
    }
  }
  
  const keyFilePath = path.join(FILE_PATH, 'key.txt');

  if (fs.existsSync(keyFilePath)) {
    const content = fs.readFileSync(keyFilePath, 'utf8');
    const privateKeyMatch = content.match(/PrivateKey:\s*(.*)/);
    const publicKeyMatch = content.match(/PublicKey:\s*(.*)/);
  
    privateKey = privateKeyMatch ? privateKeyMatch[1] : '';
    publicKey = publicKeyMatch ? publicKeyMatch[1] : '';
  
    if (!privateKey || !publicKey) {
      console.error('Failed to extract privateKey or publicKey from key.txt.');
      return;
    }
  
    console.log('Private Key:', privateKey);
    console.log('Public Key:', publicKey);

    continueExecution();
  } else {
    exec(`${path.join(FILE_PATH, webRandomName)} generate reality-keypair`, async (err, stdout, stderr) => {
      if (err) {
        console.error(`Error generating reality-keypair: ${err.message}`);
        return;
      }
    
      const privateKeyMatch = stdout.match(/PrivateKey:\s*(.*)/);
      const publicKeyMatch = stdout.match(/PublicKey:\s*(.*)/);
    
      privateKey = privateKeyMatch ? privateKeyMatch[1] : '';
      publicKey = publicKeyMatch ? publicKeyMatch[1] : '';
    
      if (!privateKey || !publicKey) {
        console.error('Failed to extract privateKey or publicKey from output.');
        return;
      }
    
      fs.writeFileSync(keyFilePath, `PrivateKey: ${privateKey}\nPublicKey: ${publicKey}\n`, 'utf8');
    
      console.log('Private Key:', privateKey);
      console.log('Public Key:', publicKey);

      continueExecution();
    });
  }

  function continueExecution() {

    exec('which openssl || where.exe openssl', async (err, stdout, stderr) => {
        if (err || stdout.trim() === '') {

          const privateKeyContent = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/++siNnfBYsdUYoAoGCCqGSM49
AwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASANnngZreoQDF16ARa
/TsyLyFoPkhLxSbehH/NBEjHtSZGaDhMqQ==
-----END EC PRIVATE KEY-----`;
          
          fs.writeFileSync(path.join(FILE_PATH, 'private.key'), privateKeyContent);

          const certContent = `-----BEGIN CERTIFICATE-----
MIIBejCCASGgAwIBAgIUfWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw
EzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwOTE4MTgyMDIyWhcNMzUwOTE2MTgy
MDIyWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgDZ54Ga3qEAxdegEWv07Mi8h
aD5IS8Um3oR/zQRIx7UmRmg4TKmjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR
BfGbgkrMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgkrMNzAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAIDAJvg0vd/ytrQVvEcSm6XTlB+
eQ6OFb9LbLYL9f+sAiAffoMbi4y/0YUSlTtz7as9S8/lciBF5VCUoVIKS+vX2g==
-----END CERTIFICATE-----`;
          
      fs.writeFileSync(path.join(FILE_PATH, 'cert.pem'), certContent);
    } else {

      try {
        await execPromise(`openssl ecparam -genkey -name prime256v1 -out "${path.join(FILE_PATH, 'private.key')}"`);
      } catch (err) {
        console.error(`Error generating private.key: ${err.message}`);
        return;
      }
      
      try {
        await execPromise(`openssl req -new -x509 -days 3650 -key "${path.join(FILE_PATH, 'private.key')}" -out "${path.join(FILE_PATH, 'cert.pem')}" -subj "/CN=bing.com"`);
      } catch (err) {
        console.error(`Error generating cert.pem: ${err.message}`);
        return;
      }
    }

    if (!privateKey || !publicKey) {
      console.error('PrivateKey or PublicKey is missing, retrying...');
      return;
    }

    const config = {
      "log": {
        "disabled": true,
        "level": "error",
        "timestamp": true
      },
      "dns": {
        "servers": [
          {
            "address": "8.8.8.8",
            "address_resolver": "local"
          },
          {
            "tag": "local",
            "address": "local"
          }
        ]
      },
      "inbounds": [
        {
          "tag": "vmess-ws-in",
          "type": "vmess",
          "listen": "::",
          "listen_port": ARGO_PORT,
          "users": [
            {
              "uuid": UUID
            }
          ],
          "transport": {
            "type": "ws",
            "path": "/vmess-argo",
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        }
      ],
      "outbounds": [
        {
          "type": "direct",
          "tag": "direct"
        },
        {
          "type": "block",
          "tag": "block"
        },
        {
          "type": "wireguard",
          "tag": "wireguard-out",
          "server": "engage.cloudflareclient.com",
          "server_port": 2408,
          "local_address": [
            "172.16.0.2/32",
            "2606:4700:110:851f:4da3:4e2c:cdbf:2ecf/128"
          ],
          "private_key": "eAx8o6MJrH4KE7ivPFFCa4qvYw5nJsYHCBQXPApQX1A=",
          "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
          "reserved": [82, 90, 51],
          "mtu": 1420
        }
      ],
      "route": {
        "rule_set": [
          {
            "tag": "netflix",
            "type": "remote",
            "format": "binary",
            "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/netflix.srs",
            "download_detour": "direct"
          },
          {
            "tag": "openai",
            "type": "remote",
            "format": "binary",
            "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs",
            "download_detour": "direct"
          }
        ],
        "rules": [
          {
            "rule_set": ["openai", "netflix"],
            "outbound": "wireguard-out"
          }
        ],
        "final": "direct"
      }
    };

    try {
      if (isValidPort(REALITY_PORT)) {
        config.inbounds.push({
          "tag": "vless-in",
          "type": "vless",
          "listen": "::",
          "listen_port": parseInt(REALITY_PORT),
          "users": [
            {
              "uuid": UUID,
              "flow": "xtls-rprx-vision"
            }
          ],
          "tls": {
            "enabled": true,
            "server_name": "www.iij.ad.jp",
            "reality": {
              "enabled": true,
              "handshake": {
                "server": "www.iij.ad.jp",
                "server_port": 443
              },
              "private_key": privateKey, 
              "short_id": [""]
            }
          }
        });
      }
    } catch (error) {
    }

    try {
      if (isValidPort(HY2_PORT)) {
        config.inbounds.push({
          "tag": "hysteria-in",
          "type": "hysteria2",
          "listen": "::",
          "listen_port": parseInt(HY2_PORT),
          "users": [
            {
              "password": UUID
            }
          ],
          "masquerade": "https://bing.com",
          "tls": {
            "enabled": true,
            "alpn": ["h3"],
            "certificate_path": path.join(FILE_PATH, "cert.pem"),
            "key_path": path.join(FILE_PATH, "private.key")
          }
        });
      }
    } catch (error) {
    }

    try {
      if (isValidPort(TUIC_PORT)) {
        config.inbounds.push({
          "tag": "tuic-in",
          "type": "tuic",
          "listen": "::",
          "listen_port": parseInt(TUIC_PORT),
          "users": [
            {
              "uuid": UUID
            }
          ],
          "congestion_control": "bbr",
          "tls": {
            "enabled": true,
            "alpn": ["h3"],
            "certificate_path": path.join(FILE_PATH, "cert.pem"),
            "key_path": path.join(FILE_PATH, "private.key")
          }
        });
      }
    } catch (error) {
    }

    try {
      let isYouTubeAccessible = true;
      
      if (YT_WARPOUT === true) {
        isYouTubeAccessible = false;
      } else {
        try {
          const youtubeTest = execSync('curl -o /dev/null -m 2 -s -w "%{http_code}" https://www.youtube.com', { encoding: 'utf8' }).trim();
          isYouTubeAccessible = youtubeTest === '200';
        } catch (curlError) {
          if (curlError.output && curlError.output[1]) {
            const youtubeTest = curlError.output[1].toString().trim();
            isYouTubeAccessible = youtubeTest === '200';
          } else {
            isYouTubeAccessible = false;
          }
        }
      }
      if (!isYouTubeAccessible) {
        
        if (!config.route) {
          config.route = {};
        }
        if (!config.route.rule_set) {
          config.route.rule_set = [];
        }
        if (!config.route.rules) {
          config.route.rules = [];
        }
        
        const existingYoutubeRule = config.route.rule_set.find(rule => rule.tag === 'youtube');
        if (!existingYoutubeRule) {
          config.route.rule_set.push({
            "tag": "youtube",
            "type": "remote",
            "format": "binary",
            "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs",
            "download_detour": "direct"
          });
        } else {
        }
        
        let wireguardRule = config.route.rules.find(rule => rule.outbound === 'wireguard-out');
        if (!wireguardRule) {
          wireguardRule = {
            "rule_set": ["openai", "netflix", "youtube"],
            "outbound": "wireguard-out"
          };
          config.route.rules.push(wireguardRule);
        } else {
          if (!wireguardRule.rule_set.includes('youtube')) {
            wireguardRule.rule_set.push('youtube');
          } else {
          }
        }
        
        console.log('Add YouTube outbound rule');
      } else {
      }
    } catch (error) {
      console.error('YouTube check error:', error);
    }

    fs.writeFileSync(path.join(FILE_PATH, 'config.json'), JSON.stringify(config, null, 2));

    let NEZHA_TLS = '';
    if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
      const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
      if (tlsPorts.includes(NEZHA_PORT)) {
        NEZHA_TLS = '--tls';
      } else {
        NEZHA_TLS = '';
      }
      const command = `nohup ${path.join(FILE_PATH, npmRandomName)} -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;
      try {
        await execPromise(command);
        console.log('npm is running');
        await new Promise((resolve) => setTimeout(resolve, 1000));
      } catch (error) {
        console.error(`npm running error: ${error}`);
      }
    } else if (NEZHA_SERVER && NEZHA_KEY) {
        const command = `nohup ${FILE_PATH}/${phpRandomName} -c "${FILE_PATH}/config.yaml" >/dev/null 2>&1 &`;
        try {
          await exec(command);
          console.log('php is running');
          await new Promise((resolve) => setTimeout(resolve, 1000));
        } catch (error) {
          console.error(`php running error: ${error}`);
        }
    } else {
      console.log('NEZHA variable is empty, skipping running');
    }

    const command1 = `nohup ${path.join(FILE_PATH, webRandomName)} run -c ${path.join(FILE_PATH, 'config.json')} >/dev/null 2>&1 &`;
    try {
      await execPromise(command1);
      console.log('web is running');
      await new Promise((resolve) => setTimeout(resolve, 1000));
    } catch (error) {
      console.error(`web running error: ${error}`);
    }

    if (fs.existsSync(path.join(FILE_PATH, botRandomName))) {
      let args;

      if (ARGO_AUTH.match(/^[A-Z0-9a-z=]{120,250}$/)) {
        args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}`;
      } else if (ARGO_AUTH.match(/TunnelSecret/)) {
        args = `tunnel --edge-ip-version auto --config ${path.join(FILE_PATH, 'tunnel.yml')} run`;
      } else {
        args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${path.join(FILE_PATH, 'boot.log')} --loglevel info --url http://localhost:${ARGO_PORT}`;
      }

      try {
        await execPromise(`nohup ${path.join(FILE_PATH, botRandomName)} ${args} >/dev/null 2>&1 &`);
        console.log('bot is running');
        await new Promise((resolve) => setTimeout(resolve, 2000));
      } catch (error) {
        console.error(`Error executing command: ${error}`);
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 5000));

    await extractDomains();
    });
  };
}

function execPromise(command) {
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        resolve(stdout || stderr);
      }
    });
  });
}

function getFilesForArchitecture(architecture) {
  let baseFiles;
  if (architecture === 'arm') {
    baseFiles = [
      { fileName: "web", fileUrl: "https://arm64.ssss.nyc.mn/sb" },
      { fileName: "bot", fileUrl: "https://arm64.ssss.nyc.mn/bot" }
    ];
  } else {
    baseFiles = [
      { fileName: "web", fileUrl: "https://amd64.ssss.nyc.mn/sb" },
      { fileName: "bot", fileUrl: "https://amd64.ssss.nyc.mn/bot" }
    ];
  }

  if (NEZHA_SERVER && NEZHA_KEY) {
    if (NEZHA_PORT) {
      const npmUrl = architecture === 'arm' 
        ? "https://arm64.ssss.nyc.mn/agent"
        : "https://amd64.ssss.nyc.mn/agent";
        baseFiles.unshift({ 
          fileName: "npm", 
          fileUrl: npmUrl 
        });
    } else {
      const phpUrl = architecture === 'arm' 
        ? "https://arm64.ssss.nyc.mn/v1" 
        : "https://amd64.ssss.nyc.mn/v1";
      baseFiles.unshift({ 
        fileName: "php", 
        fileUrl: phpUrl
      });
    }
  }

  return baseFiles;
}

async function extractDomains() {
  let argoDomain;

  if (ARGO_AUTH && ARGO_DOMAIN) {
    argoDomain = ARGO_DOMAIN;
    console.log('ARGO_DOMAIN:', argoDomain);
    await generateLinks(argoDomain);
  } else {
    try {
      const fileContent = fs.readFileSync(path.join(FILE_PATH, 'boot.log'), 'utf-8');
      const lines = fileContent.split('\n');
      const argoDomains = [];
      lines.forEach((line) => {
        const domainMatch = line.match(/https?:\/\/([^ ]*trycloudflare\.com)\/?/);
        if (domainMatch) {
          const domain = domainMatch[1];
          argoDomains.push(domain);
        }
      });

      if (argoDomains.length > 0) {
        argoDomain = argoDomains[0];
        console.log('ArgoDomain:', argoDomain);
        await generateLinks(argoDomain);
      } else {
        console.log('ArgoDomain not found, re-running bot to obtain ArgoDomain');
          fs.unlinkSync(path.join(FILE_PATH, 'boot.log'));
          async function killBotProcess() {
            try {
              await exec(`pkill -f "${botRandomName}" > /dev/null 2>&1`);
            } catch (error) {
                return null;
            }
          }
          killBotProcess();
          await new Promise((resolve) => setTimeout(resolve, 1000));
          const args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${FILE_PATH}/boot.log --loglevel info --url http://localhost:${ARGO_PORT}`;
          try {
            await exec(`nohup ${path.join(FILE_PATH, botRandomName)} ${args} >/dev/null 2>&1 &`);
            console.log('bot is running.');
            await new Promise((resolve) => setTimeout(resolve, 6000));
            await extractDomains();
          } catch (error) {
            console.error(`Error executing command: ${error}`);
          }
        }
      } catch (error) {
      console.error('Error reading boot.log:', error);
    }
  }
}
  
  async function generateLinks(argoDomain) {
    let SERVER_IP = '';
    try {
      SERVER_IP = execSync('curl -s --max-time 2 ipv4.ip.sb').toString().trim();
    } catch (err) {
      try {
        SERVER_IP = `[${execSync('curl -s --max-time 1 ipv6.ip.sb').toString().trim()}]`;
      } catch (ipv6Err) {
        console.error('Failed to get IP address:', ipv6Err.message);
      }
    }

    const metaInfo = execSync(
      'curl -s https://speed.cloudflare.com/meta | awk -F\\" \'{print $26"-"$18}\' | sed -e \'s/ /_/g\'',
      { encoding: 'utf-8' }
    );
    const ISP = metaInfo.trim();

    const nodeName = NAME ? `${NAME}-${ISP}` : ISP;

    return new Promise((resolve) => {
      setTimeout(() => {
        const vmessNode = `vmess://${Buffer.from(JSON.stringify({ v: '2', ps: `${nodeName}`, add: CFIP, port: CFPORT, id: UUID, aid: '0', scy: 'none', net: 'ws', type: 'none', host: argoDomain, path: '/vmess-argo?ed=2560', tls: 'tls', sni: argoDomain, alpn: '', fp: 'firefox'})).toString('base64')}`;

        let subTxt = vmessNode;

        if (isValidPort(TUIC_PORT)) {
          const tuicNode = `\ntuic://${UUID}:@${SERVER_IP}:${TUIC_PORT}?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#${nodeName}`;
          subTxt += tuicNode;
        }

        if (isValidPort(HY2_PORT)) {
          const hysteriaNode = `\nhysteria2://${UUID}@${SERVER_IP}:${HY2_PORT}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#${nodeName}`;
          subTxt += hysteriaNode;
        }

        if (isValidPort(REALITY_PORT)) {
          const vlessNode = `\nvless://${UUID}@${SERVER_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=firefox&pbk=${publicKey}&type=tcp&headerType=none#${nodeName}`;
          subTxt += vlessNode;
        }

        console.log(Buffer.from(subTxt).toString('base64')); 
        fs.writeFileSync(subPath, Buffer.from(subTxt).toString('base64'));
        fs.writeFileSync(listPath, subTxt, 'utf8');
        console.log(`${FILE_PATH}/sub.txt saved successfully`);
        sendTelegram();
        uplodNodes();
        app.get(`/${SUB_PATH}`, (req, res) => {
          const encodedContent = Buffer.from(subTxt).toString('base64');
          res.set('Content-Type', 'text/plain; charset=utf-8');
          res.send(encodedContent);
        });
        resolve(subTxt);
      }, 2000);
    });
  }
 
function cleanFiles() {
  setTimeout(() => {
    const filesToDelete = [bootLogPath, configPath, listPath, webPath, botPath, phpPath, npmPath];  
    
    if (NEZHA_PORT) {
      filesToDelete.push(npmPath);
    } else if (NEZHA_SERVER && NEZHA_KEY) {
      filesToDelete.push(phpPath);
    }

    const filePathsToDelete = filesToDelete.map(file => {
      if ([webPath, botPath, phpPath, npmPath].includes(file)) {
        return file;
      }
      return path.join(FILE_PATH, path.basename(file));
    });

    exec(`rm -rf ${filePathsToDelete.join(' ')} >/dev/null 2>&1`, (error) => {
      console.clear();
      console.log('App is running');
      console.log('Thank you for using this script, enjoy!');
    });
  }, 90000);
}

async function sendTelegram() {
  if (!BOT_TOKEN || !CHAT_ID) {
      console.log('TG variables is empty,Skipping push nodes to TG');
      return;
  }
  try {
      const message = fs.readFileSync(path.join(FILE_PATH, 'sub.txt'), 'utf8');
      const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
      
      const escapedName = NAME.replace(/[_*[\]()~`>#+=|{}.!-]/g, '\\$&');
      
      const params = {
          chat_id: CHAT_ID,
          text: `**${escapedName}节点推送通知**\n\`\`\`${message}\`\`\``,
          parse_mode: 'MarkdownV2'
      };

      await axios.post(url, null, { params });
      console.log('Telegram message sent successfully');
  } catch (error) {
      console.error('Failed to send Telegram message', error);
  }
}

async function uplodNodes() {
  if (UPLOAD_URL && PROJECT_URL) {
    const subscriptionUrl = `${PROJECT_URL}/${SUB_PATH}`;
    const jsonData = {
      subscription: [subscriptionUrl]
    };
    try {
        const response = await axios.post(`${UPLOAD_URL}/api/add-subscriptions`, jsonData, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (response.status === 200) {
            console.log('Subscription uploaded successfully');
        } else {
          return null;
        }
    } catch (error) {
        if (error.response) {
            if (error.response.status === 400) {
            }
        }
    }
  } else if (UPLOAD_URL) {
      if (!fs.existsSync(listPath)) return;
      const content = fs.readFileSync(listPath, 'utf-8');
      const nodes = content.split('\n').filter(line => /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line));

      if (nodes.length === 0) return;

      const jsonData = JSON.stringify({ nodes });

      try {
          const response = await axios.post(`${UPLOAD_URL}/api/add-nodes`, jsonData, {
              headers: { 'Content-Type': 'application/json' }
          });
          if (response.status === 200) {
            console.log('Subscription uploaded successfully');
          } else {
            return null;
          }
      } catch (error) {
          return null;
      }
  } else {
      return;
  }
}

async function AddVisitTask() {
  if (!AUTO_ACCESS || !PROJECT_URL) {
    console.log("Skipping adding automatic access task");
    return;
  }

  try {
    const response = await axios.post('https://keep.gvrander.eu.org/add-url', {
      url: PROJECT_URL
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    console.log('automatic access task added successfully');
  } catch (error) {
    console.error(`添加URL失败: ${error.message}`);
  }
}

async function startserver() {
  deleteNodes();
  cleanupOldFiles();
  argoType();
  await downloadFilesAndRun();
  AddVisitTask();
  cleanFiles();
}
startserver();
  
app.listen(PORT, () => console.log(`server is running on port:${PORT}!`));
