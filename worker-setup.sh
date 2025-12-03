#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BLUE='\033[0;34m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}    Custom Game Panel - Worker Unit     ${NC}"
echo -e "${BLUE}    Installation Script for Ubuntu 25.10${NC}"
echo -e "${BLUE}========================================${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root${NC}" 
    exit 1
fi

# Configuration
read -p "Enter Control Panel URL (e.g., https://panel.yourdomain.com): " CONTROL_PANEL_URL
read -p "Enter Worker Secret Token (from control panel): " WORKER_TOKEN
read -p "Enter Worker Name (e.g., worker-1): " WORKER_NAME
read -p "Enter Worker Port (default: 2025): " WORKER_PORT
WORKER_PORT=${WORKER_PORT:-2025}

# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')

echo -e "${YELLOW}Configuration Summary:${NC}"
echo -e "  Control Panel: ${CONTROL_PANEL_URL}"
echo -e "  Worker Name:   ${WORKER_NAME}"
echo -e "  Worker Port:   ${WORKER_PORT}"
echo -e "  Server IP:     ${SERVER_IP}"

# Update system
echo -e "${GREEN}[1/15] Updating system packages...${NC}"
apt update && apt upgrade -y

# Install Docker
echo -e "${GREEN}[2/15] Installing Docker...${NC}"
# Remove old versions
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
    apt remove -y $pkg 2>/dev/null || true
done

# Install Docker from official repository
apt install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Install Node.js
echo -e "${GREEN}[3/15] Installing Node.js...${NC}"
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs

# Install additional packages
echo -e "${GREEN}[4/15] Installing additional packages...${NC}"
apt install -y curl wget git ufw nginx jq python3 python3-pip lm-sensors htop

# Install Docker Compose (standalone for compatibility)
curl -SL https://github.com/docker/compose/releases/download/v2.20.3/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Configure firewall
echo -e "${GREEN}[5/15] Configuring firewall...${NC}"
ufw allow OpenSSH
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow ${WORKER_PORT}/tcp
ufw allow 2022/tcp  # Default Docker SSH port
ufw --force enable

# Create application directory
echo -e "${GREEN}[6/15] Creating application directory...${NC}"
mkdir -p /var/lib/gamepanel-worker
cd /var/lib/gamepanel-worker

# Create directory structure
mkdir -p {servers,backups,logs,scripts,templates,data}

# Setup worker application
echo -e "${GREEN}[7/15] Setting up worker application...${NC}"
mkdir -p app
cd app

# Create package.json
cat > package.json <<EOF
{
  "name": "gamepanel-worker",
  "version": "1.0.0",
  "description": "Worker for Game Panel",
  "main": "dist/worker.js",
  "scripts": {
    "dev": "nodemon src/worker.ts",
    "build": "tsc",
    "start": "node dist/worker.js",
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "dependencies": {
    "axios": "^1.5.0",
    "ws": "^8.14.2",
    "dockerode": "^3.3.5",
    "node-pty": "^1.0.0",
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "winston": "^3.10.0",
    "node-cron": "^3.0.2",
    "uuid": "^9.0.0",
    "dotenv": "^16.3.1",
    "tar": "^6.2.0",
    "fs-extra": "^11.1.1",
    "archiver": "^5.3.1",
    "extract-zip": "^2.0.1",
    "form-data": "^4.0.0",
    "socket.io-client": "^4.6.1"
  },
  "devDependencies": {
    "typescript": "^5.2.2",
    "@types/node": "^20.5.6",
    "@types/ws": "^8.5.6",
    "@types/dockerode": "^3.3.18",
    "@types/node-pty": "^0.10.3",
    "@types/express": "^4.17.17",
    "@types/node-cron": "^3.0.7",
    "nodemon": "^3.0.1",
    "ts-node": "^10.9.1"
  }
}
EOF

# Install dependencies
npm install

# Create tsconfig.json
cat > tsconfig.json <<EOF
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "sourceMap": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
EOF

# Create environment file
cat > .env <<EOF
# Worker Configuration
WORKER_NAME="${WORKER_NAME}"
WORKER_SECRET="${WORKER_TOKEN}"
CONTROL_PANEL_URL="${CONTROL_PANEL_URL}"
WORKER_PORT=${WORKER_PORT}
SERVER_IP="${SERVER_IP}"

# Docker Configuration
DOCKER_SOCKET="/var/run/docker.sock"
DOCKER_NETWORK="gamepanel-network"
DEFAULT_DOCKER_IMAGE="debian:bullseye-slim"

# Resource Limits
MAX_MEMORY=$(free -m | awk '/^Mem:/{print int($2*0.85)}')
MAX_DISK=$(df -m / | awk 'NR==2{print int($4*0.85)}')
MAX_CPU=$(nproc)
MAX_SERVERS=50

# Paths
SERVER_DATA_PATH="/var/lib/gamepanel-worker/servers"
BACKUP_PATH="/var/lib/gamepanel-worker/backups"
LOG_PATH="/var/lib/gamepanel-worker/logs"
TEMPLATE_PATH="/var/lib/gamepanel-worker/templates"

# WebSocket
WEBSOCKET_ENABLED=true
HEARTBEAT_INTERVAL=30000
CONSOLE_BUFFER_SIZE=1000

# Performance
MAX_CONCURRENT_DOWNLOADS=3
MAX_CONCURRENT_UPLOADS=3
FILE_CHUNK_SIZE=65536
EOF

# Create source directory structure
mkdir -p src/{docker,websocket,api,utils,managers}

# Create main worker file
cat > src/worker.ts <<'EOF'
import Docker from 'dockerode';
import axios, { AxiosInstance } from 'axios';
import WebSocket from 'ws';
import * as pty from 'node-pty';
import fs from 'fs-extra';
import path from 'path';
import { EventEmitter } from 'events';
import cron from 'node-cron';
import winston from 'winston';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createReadStream, createWriteStream } from 'fs';
import { pipeline } from 'stream/promises';
import archiver from 'archiver';
import { extract } from 'extract-zip';
import tar from 'tar';

// Configuration
const config = {
  workerName: process.env.WORKER_NAME || 'worker-1',
  workerSecret: process.env.WORKER_SECRET || '',
  controlPanelUrl: process.env.CONTROL_PANEL_URL || '',
  workerPort: parseInt(process.env.WORKER_PORT || '2025'),
  dockerSocket: process.env.DOCKER_SOCKET || '/var/run/docker.sock',
  serverDataPath: process.env.SERVER_DATA_PATH || '/var/lib/gamepanel-worker/servers',
  backupPath: process.env.BACKUP_PATH || '/var/lib/gamepanel-worker/backups',
  maxMemory: parseInt(process.env.MAX_MEMORY || '8192'),
  maxDisk: parseInt(process.env.MAX_DISK || '51200'),
  maxCPU: parseInt(process.env.MAX_CPU || '4'),
  maxServers: parseInt(process.env.MAX_SERVERS || '50'),
  heartbeatInterval: parseInt(process.env.HEARTBEAT_INTERVAL || '30000'),
};

// Logger setup
const logDir = path.dirname(process.env.LOG_PATH || '/var/lib/gamepanel-worker/logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} [${level.toUpperCase()}] ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ 
      filename: path.join(logDir, 'worker.log') 
    }),
  ],
});

// Docker client
const docker = new Docker({ socketPath: config.dockerSocket });

// HTTP client for control panel communication
const httpClient: AxiosInstance = axios.create({
  baseURL: config.controlPanelUrl,
  timeout: 10000,
  headers: {
    'X-Worker-Token': config.workerSecret,
    'Content-Type': 'application/json',
  },
  validateStatus: () => true, // Don't throw on non-2xx status
});

// Server manager class
class ServerManager extends EventEmitter {
  private servers: Map<string, ServerInstance> = new Map();
  private ptyProcesses: Map<string, pty.IPty> = new Map();
  private consoleBuffers: Map<string, string[]> = new Map();

  constructor() {
    super();
    this.loadExistingContainers();
  }

  private async loadExistingContainers() {
    try {
      const containers = await docker.listContainers({ all: true });
      
      for (const containerInfo of containers) {
        const serverId = containerInfo.Labels['gamepanel.server.id'];
        if (serverId) {
          const container = docker.getContainer(containerInfo.Id);
          const server: ServerInstance = {
            id: serverId,
            container,
            status: containerInfo.State,
            stats: null,
            resources: {
              memoryLimit: parseInt(containerInfo.Labels['gamepanel.server.memory'] || '1024'),
              cpuLimit: parseInt(containerInfo.Labels['gamepanel.server.cpu'] || '100'),
              diskLimit: parseInt(containerInfo.Labels['gamepanel.server.disk'] || '10240'),
            },
            allocatedPorts: JSON.parse(containerInfo.Labels['gamepanel.server.ports'] || '[]'),
          };
          
          this.servers.set(serverId, server);
          logger.info(`Loaded existing server: ${serverId} (${containerInfo.State})`);
        }
      }
    } catch (error) {
      logger.error(`Failed to load existing containers: ${error}`);
    }
  }

  async createServer(serverData: any): Promise<CreateServerResult> {
    const { 
      id, 
      dockerImage, 
      environment, 
      memoryLimit, 
      cpuLimit, 
      diskLimit, 
      startupCommand,
      allocatedPorts 
    } = serverData;
    
    try {
      // Create server directory
      const serverPath = path.join(config.serverDataPath, id);
      await fs.ensureDir(serverPath);
      
      // Prepare environment variables
      const envVars = Object.entries(environment || {}).map(([key, value]) => `${key}=${value}`);
      
      // Prepare port bindings
      const portBindings: any = {};
      const exposedPorts: any = {};
      
      for (const port of allocatedPorts || []) {
        const portKey = `${port}/tcp`;
        portBindings[portKey] = [{ HostPort: port.toString() }];
        exposedPorts[portKey] = {};
      }
      
      // Create container
      const container = await docker.createContainer({
        Image: dockerImage,
        name: `gamepanel-${id}`,
        Env: envVars,
        Cmd: startupCommand ? ['/bin/sh', '-c', startupCommand] : ['/bin/bash'],
        HostConfig: {
          Memory: memoryLimit * 1024 * 1024, // Convert MB to bytes
          MemorySwap: memoryLimit * 1024 * 1024 * 2,
          CpuQuota: cpuLimit * 1000, // Convert percentage to microseconds
          CpuPeriod: 100000,
          CpuShares: 1024,
          Binds: [
            `${serverPath}:/home/container:rw`,
          ],
          PortBindings: portBindings,
          RestartPolicy: {
            Name: 'unless-stopped',
            MaximumRetryCount: 3
          },
          LogConfig: {
            Type: 'json-file',
            Config: {
              'max-size': '10m',
              'max-file': '3'
            }
          },
          NetworkMode: 'bridge',
        },
        ExposedPorts: exposedPorts,
        Labels: {
          'gamepanel.server.id': id,
          'gamepanel.server.memory': memoryLimit.toString(),
          'gamepanel.server.cpu': cpuLimit.toString(),
          'gamepanel.server.disk': diskLimit.toString(),
          'gamepanel.server.ports': JSON.stringify(allocatedPorts || []),
          'gamepanel.managed': 'true',
        },
        AttachStdin: true,
        AttachStdout: true,
        AttachStderr: true,
        Tty: true,
        OpenStdin: true,
        StdinOnce: false,
      });
      
      const server: ServerInstance = {
        id,
        container,
        status: 'created',
        stats: null,
        resources: { memoryLimit, cpuLimit, diskLimit },
        allocatedPorts: allocatedPorts || [],
      };
      
      this.servers.set(id, server);
      
      logger.info(`Created server container: ${id} (${container.id})`);
      return { 
        success: true, 
        containerId: container.id,
        serverPath 
      };
    } catch (error) {
      logger.error(`Failed to create server ${id}: ${error}`);
      throw error;
    }
  }

  async startServer(serverId: string): Promise<boolean> {
    try {
      const server = this.servers.get(serverId);
      if (!server) {
        throw new Error(`Server ${serverId} not found`);
      }
      
      await server.container.start();
      server.status = 'running';
      
      // Start console session
      await this.startConsole(serverId);
      
      logger.info(`Started server: ${serverId}`);
      return true;
    } catch (error) {
      logger.error(`Failed to start server ${serverId}: ${error}`);
      throw error;
    }
  }

  async stopServer(serverId: string): Promise<boolean> {
    try {
      const server = this.servers.get(serverId);
      if (!server) {
        throw new Error(`Server ${serverId} not found`);
      }
      
      await server.container.stop({ t: 30 }); // 30 second timeout
      server.status = 'stopped';
      
      // Stop console
      this.stopConsole(serverId);
      
      logger.info(`Stopped server: ${serverId}`);
      return true;
    } catch (error) {
      logger.error(`Failed to stop server ${serverId}: ${error}`);
      throw error;
    }
  }

  async restartServer(serverId: string): Promise<boolean> {
    try {
      const server = this.servers.get(serverId);
      if (!server) {
        throw new Error(`Server ${serverId} not found`);
      }
      
      await server.container.restart({ t: 30 });
      server.status = 'running';
      
      logger.info(`Restarted server: ${serverId}`);
      return true;
    } catch (error) {
      logger.error(`Failed to restart server ${serverId}: ${error}`);
      throw error;
    }
  }

  async deleteServer(serverId: string, removeData: boolean = false): Promise<boolean> {
    try {
      const server = this.servers.get(serverId);
      if (!server) {
        throw new Error(`Server ${serverId} not found`);
      }
      
      // Stop if running
      if (server.status === 'running') {
        await this.stopServer(serverId);
      }
      
      // Remove container
      await server.container.remove({ v: true, force: true });
      this.servers.delete(serverId);
      
      // Clean up directory if requested
      if (removeData) {
        const serverPath = path.join(config.serverDataPath, serverId);
        await fs.remove(serverPath);
      }
      
      logger.info(`Deleted server: ${serverId}`);
      return true;
    } catch (error) {
      logger.error(`Failed to delete server ${serverId}: ${error}`);
      throw error;
    }
  }

  private async startConsole(serverId: string) {
    try {
      const server = this.servers.get(serverId);
      if (!server) return;
      
      // Create exec instance for console
      const exec = await server.container.exec({
        Cmd: ['/bin/bash'],
        AttachStdin: true,
        AttachStdout: true,
        AttachStderr: true,
        Tty: true,
      });
      
      // Start the exec instance
      const stream = await exec.start({ hijack: true, stdin: true });
      
      // Initialize console buffer
      this.consoleBuffers.set(serverId, []);
      
      // Handle console output
      stream.on('data', (chunk: Buffer) => {
        const output = chunk.toString();
        
        // Add to buffer
        const buffer = this.consoleBuffers.get(serverId) || [];
        buffer.push(output);
        if (buffer.length > 1000) buffer.shift();
        this.consoleBuffers.set(serverId, buffer);
        
        // Emit event
        this.emit('console-output', { serverId, output });
        
        // Send to control panel
        this.sendConsoleOutput(serverId, output);
      });
      
      server.consoleStream = stream;
      logger.info(`Started console for server: ${serverId}`);
    } catch (error) {
      logger.error(`Failed to start console for ${serverId}: ${error}`);
    }
  }

  private stopConsole(serverId: string) {
    const ptyProcess = this.ptyProcesses.get(serverId);
    if (ptyProcess) {
      ptyProcess.kill();
      this.ptyProcesses.delete(serverId);
    }
    this.consoleBuffers.delete(serverId);
  }

  async sendConsoleInput(serverId: string, input: string): Promise<boolean> {
    try {
      const server = this.servers.get(serverId);
      if (!server || !server.consoleStream) {
        throw new Error(`Console not available for server ${serverId}`);
      }
      
      server.consoleStream.write(input);
      logger.debug(`Sent console input to ${serverId}: ${input.substring(0, 100)}...`);
      return true;
    } catch (error) {
      logger.error(`Failed to send console input to ${serverId}: ${error}`);
      throw error;
    }
  }

  async getConsoleBuffer(serverId: string, lines: number = 100): Promise<string[]> {
    const buffer = this.consoleBuffers.get(serverId) || [];
    return buffer.slice(-lines);
  }

  private async sendConsoleOutput(serverId: string, output: string) {
    try {
      await httpClient.post(`${config.controlPanelUrl}/api/nodes/server/${serverId}/console`, {
        output,
        type: 'CONSOLE'
      });
    } catch (error) {
      logger.error(`Failed to send console output to control panel: ${error}`);
    }
  }

  async getServerStats(): Promise<ServerStats[]> {
    const stats: ServerStats[] = [];
    
    for (const [serverId, server] of this.servers) {
      try {
        if (server.status !== 'running') {
          stats.push({
            serverId,
            cpu: 0,
            memory: 0,
            disk: await this.getServerDiskUsage(serverId),
            status: server.status,
            uptime: 0,
          });
          continue;
        }
        
        const containerStats = await server.container.stats({ stream: false });
        const cpuDelta = containerStats.cpu_stats.cpu_usage.total_usage - 
                        containerStats.precpu_stats.cpu_usage.total_usage;
        const systemDelta = containerStats.cpu_stats.system_cpu_usage - 
                           containerStats.precpu_stats.system_cpu_usage;
        
        const cpuPercent = systemDelta > 0 ? (cpuDelta / systemDelta) * 100 * containerStats.cpu_stats.online_cpus : 0;
        const memoryUsage = containerStats.memory_stats.usage || 0;
        const memoryLimit = containerStats.memory_stats.limit || 1;
        const memoryPercent = (memoryUsage / memoryLimit) * 100;
        
        stats.push({
          serverId,
          cpu: Math.min(cpuPercent, 100),
          memory: Math.round(memoryUsage / 1024 / 1024), // Convert to MB
          disk: await this.getServerDiskUsage(serverId),
          status: server.status,
          uptime: Math.floor((Date.now() - new Date(containerStats.read).getTime()) / 1000),
        });
      } catch (error) {
        logger.error(`Failed to get stats for server ${serverId}: ${error}`);
        stats.push({
          serverId,
          cpu: 0,
          memory: 0,
          disk: 0,
          status: 'error',
          uptime: 0,
        });
      }
    }
    
    return stats;
  }

  private async getServerDiskUsage(serverId: string): Promise<number> {
    try {
      const serverPath = path.join(config.serverDataPath, serverId);
      if (!await fs.pathExists(serverPath)) {
        return 0;
      }
      
      // Use du command to get disk usage
      const { exec } = require('child_process');
      return new Promise((resolve) => {
        exec(`du -sb ${serverPath} | cut -f1`, (error: any, stdout: string) => {
          if (error) {
            resolve(0);
          } else {
            const bytes = parseInt(stdout.trim());
            resolve(Math.round(bytes / 1024 / 1024)); // Convert to MB
          }
        });
      });
    } catch (error) {
      return 0;
    }
  }

  async getSystemStats(): Promise<SystemStats> {
    try {
      // Get Docker info
      const info = await docker.info();
      
      // Get server stats
      const serverStats = await this.getServerStats();
      
      // Calculate totals
      let usedMemory = 0;
      let usedCpu = 0;
      let usedDisk = 0;
      
      for (const stat of serverStats) {
        usedMemory += stat.memory;
        usedCpu += stat.cpu;
        usedDisk += stat.disk;
      }
      
      return {
        totalMemory: Math.round(info.MemTotal / 1024 / 1024), // Convert to MB
        totalDisk: config.maxDisk,
        totalCpu: info.NCPU * 100, // Convert cores to percentage
        usedMemory,
        usedDisk,
        usedCpu,
        serverStats,
        containerCount: info.ContainersRunning || 0,
        dockerVersion: info.ServerVersion,
      };
    } catch (error) {
      logger.error(`Failed to get system stats: ${error}`);
      throw error;
    }
  }

  async getServerFiles(serverId: string, directory: string = '/'): Promise<FileInfo[]> {
    try {
      const server = this.servers.get(serverId);
      if (!server) {
        throw new Error(`Server ${serverId} not found`);
      }
      
      // Create exec to list files
      const exec = await server.container.exec({
        Cmd: ['find', directory, '-maxdepth', '1', '-printf', '%y %s %T@ %p\\n'],
        AttachStdout: true,
        AttachStderr: true,
      });
      
      return new Promise((resolve, reject) => {
        const files: FileInfo[] = [];
        
        exec.start({}, (err: any, stream: any) => {
          if (err) {
            reject(err);
            return;
          }
          
          let output = '';
          stream.on('data', (chunk: Buffer) => {
            output += chunk.toString();
          });
          
          stream.on('end', () => {
            const lines = output.trim().split('\n');
            for (const line of lines) {
              const [type, size, mtime, ...pathParts] = line.split(' ');
              const filePath = pathParts.join(' ');
              
              if (filePath === directory) continue; // Skip the directory itself
              
              files.push({
                name: path.basename(filePath),
                path: filePath,
                type: type === 'd' ? 'directory' : 'file',
                size: parseInt(size),
                modified: new Date(parseFloat(mtime) * 1000),
                permissions: '644', // Simplified
              });
            }
            resolve(files);
          });
        });
      });
    } catch (error) {
      logger.error(`Failed to get files for server ${serverId}: ${error}`);
      throw error;
    }
  }

  async readFile(serverId: string, filePath: string): Promise<string> {
    try {
      const server = this.servers.get(serverId);
      if (!server) {
        throw new Error(`Server ${serverId} not found`);
      }
      
      // Create exec to read file
      const exec = await server.container.exec({
        Cmd: ['cat', filePath],
        AttachStdout: true,
        AttachStderr: true,
      });
      
      return new Promise((resolve, reject) => {
        let content = '';
        
        exec.start({}, (err: any, stream: any) => {
          if (err) {
            reject(err);
            return;
          }
          
          stream.on('data', (chunk: Buffer) => {
            content += chunk.toString();
          });
          
          stream.on('end', () => {
            resolve(content);
          });
          
          stream.on('error', reject);
        });
      });
    } catch (error) {
      logger.error(`Failed to read file ${filePath} from server ${serverId}: ${error}`);
      throw error;
    }
  }

  async writeFile(serverId: string, filePath: string, content: string): Promise<boolean> {
    try {
      const server = this.servers.get(serverId);
      if (!server) {
        throw new Error(`Server ${serverId} not found`);
      }
      
      // Create exec to write file
      const exec = await server.container.exec({
        Cmd: ['sh', '-c', `cat > "${filePath}"`],
        AttachStdin: true,
        AttachStdout: true,
        AttachStderr: true,
      });
      
      return new Promise((resolve, reject) => {
        exec.start({}, (err: any, stream: any) => {
          if (err) {
            reject(err);
            return;
          }
          
          stream.write(content);
          stream.end();
          
          stream.on('end', () => {
            resolve(true);
          });
          
          stream.on('error', reject);
        });
      });
    } catch (error) {
      logger.error(`Failed to write file ${filePath} to server ${serverId}: ${error}`);
      throw error;
    }
  }

  async createBackup(serverId: string, backupName: string): Promise<string> {
    try {
      const server = this.servers.get(serverId);
      if (!server) {
        throw new Error(`Server ${serverId} not found`);
      }
      
      const serverPath = path.join(config.serverDataPath, serverId);
      const backupDir = path.join(config.backupPath, serverId);
      await fs.ensureDir(backupDir);
      
      const backupFile = path.join(backupDir, `${backupName}.tar.gz`);
      
      // Create tar archive
      await tar.c(
        {
          gzip: true,
          file: backupFile,
          cwd: serverPath,
        },
        ['.']
      );
      
      const stats = await fs.stat(backupFile);
      logger.info(`Created backup for server ${serverId}: ${backupFile} (${stats.size} bytes)`);
      
      return backupFile;
    } catch (error) {
      logger.error(`Failed to create backup for server ${serverId}: ${error}`);
      throw error;
    }
  }

  async restoreBackup(serverId: string, backupFile: string): Promise<boolean> {
    try {
      const serverPath = path.join(config.serverDataPath, serverId);
      
      // Clear existing data
      await fs.emptyDir(serverPath);
      
      // Extract backup
      await tar.x({
        file: backupFile,
        cwd: serverPath,
      });
      
      logger.info(`Restored backup for server ${serverId} from ${backupFile}`);
      return true;
    } catch (error) {
      logger.error(`Failed to restore backup for server ${serverId}: ${error}`);
      throw error;
    }
  }
}

// Control panel communicator
class ControlPanelCommunicator {
  private isRegistered = false;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;

  async registerWorker() {
    try {
      const systemStats = await serverManager.getSystemStats();
      
      const response = await httpClient.post('/api/nodes/register', {
        name: config.workerName,
        hostname: require('os').hostname(),
        ipAddress: config.SERVER_IP || await this.getPublicIp(),
        port: config.workerPort,
        secretToken: config.workerSecret,
        location: 'datacenter-1',
        totalMemory: systemStats.totalMemory,
        totalDisk: systemStats.totalDisk,
        totalCpu: systemStats.totalCpu,
        dockerVersion: systemStats.dockerVersion,
      });
      
      if (response.status === 200 || response.status === 201) {
        this.isRegistered = true;
        this.reconnectAttempts = 0;
        logger.info('Successfully registered with control panel');
      } else {
        throw new Error(`Registration failed: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      this.isRegistered = false;
      this.reconnectAttempts++;
      
      if (this.reconnectAttempts <= this.maxReconnectAttempts) {
        logger.error(`Failed to register with control panel (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts}): ${error}`);
        
        // Exponential backoff
        const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
        setTimeout(() => this.registerWorker(), delay);
      } else {
        logger.error(`Max registration attempts reached. Worker will not register.`);
      }
    }
  }

  async sendHeartbeat() {
    if (!this.isRegistered && this.reconnectAttempts < this.maxReconnectAttempts) {
      await this.registerWorker();
      return;
    }
    
    if (!this.isRegistered) {
      return;
    }
    
    try {
      const systemStats = await serverManager.getSystemStats();
      
      const response = await httpClient.post('/api/nodes/heartbeat', {
        usedMemory: systemStats.usedMemory,
        usedDisk: systemStats.usedDisk,
        usedCpu: systemStats.usedCpu,
        serverStats: systemStats.serverStats,
        containerCount: systemStats.containerCount,
        status: 'online',
      });
      
      if (response.status !== 200) {
        this.isRegistered = false;
        logger.warn('Heartbeat failed, worker marked as offline');
      } else {
        logger.debug('Heartbeat sent successfully');
      }
    } catch (error) {
      logger.error(`Failed to send heartbeat: ${error}`);
      this.isRegistered = false;
    }
  }

  async sendServerStats(serverId: string, stats: any) {
    try {
      await httpClient.post(`/api/nodes/server/${serverId}/stats`, stats);
    } catch (error) {
      logger.error(`Failed to send server stats for ${serverId}: ${error}`);
    }
  }

  async sendInstallProgress(serverId: string, progress: number, message: string) {
    try {
      await httpClient.post(`/api/nodes/server/${serverId}/install-progress`, {
        progress,
        message,
      });
    } catch (error) {
      logger.error(`Failed to send install progress for ${serverId}: ${error}`);
    }
  }

  private async getPublicIp(): Promise<string> {
    try {
      const response = await axios.get('https://api.ipify.org?format=json', { timeout: 5000 });
      return response.data.ip;
    } catch (error) {
      return '127.0.0.1';
    }
  }
}

// WebSocket client for real-time communication
class WebSocketClient {
  private ws: WebSocket | null = null;
  private reconnectTimeout: NodeJS.Timeout | null = null;
  private isConnected = false;

  constructor(private controlPanelUrl: string, private workerSecret: string) {
    this.connect();
  }

  private connect() {
    try {
      const wsUrl = this.controlPanelUrl.replace('https://', 'wss://').replace('http://', 'ws://');
      this.ws = new WebSocket(`${wsUrl}/socket.io/?workerToken=${this.workerSecret}`);
      
      this.ws.on('open', () => {
        this.isConnected = true;
        logger.info('WebSocket connected to control panel');
        
        // Send worker identification
        this.send({
          type: 'worker-identify',
          data: {
            name: config.workerName,
            secret: config.workerSecret,
          }
        });
      });
      
      this.ws.on('message', (data) => {
        this.handleMessage(data.toString());
      });
      
      this.ws.on('close', () => {
        this.isConnected = false;
        logger.warn('WebSocket disconnected, reconnecting in 5 seconds...');
        this.scheduleReconnect();
      });
      
      this.ws.on('error', (error) => {
        logger.error(`WebSocket error: ${error}`);
      });
    } catch (error) {
      logger.error(`Failed to connect WebSocket: ${error}`);
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect() {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
    }
    
    this.reconnectTimeout = setTimeout(() => {
      this.connect();
    }, 5000);
  }

  private handleMessage(message: string) {
    try {
      const data = JSON.parse(message);
      
      switch (data.type) {
        case 'console-input':
          if (data.serverId && data.command) {
            serverManager.sendConsoleInput(data.serverId, data.command);
          }
          break;
          
        case 'server-power':
          if (data.serverId && data.action) {
            this.handlePowerAction(data.serverId, data.action);
          }
          break;
          
        case 'file-action':
          if (data.serverId && data.action) {
            this.handleFileAction(data.serverId, data.action, data);
          }
          break;
          
        case 'backup-action':
          if (data.serverId && data.action) {
            this.handleBackupAction(data.serverId, data.action, data);
          }
          break;
          
        case 'ping':
          this.send({ type: 'pong', timestamp: Date.now() });
          break;
      }
    } catch (error) {
      logger.error(`Failed to handle WebSocket message: ${error}`);
    }
  }

  private async handlePowerAction(serverId: string, action: string) {
    try {
      switch (action) {
        case 'start':
          await serverManager.startServer(serverId);
          break;
        case 'stop':
          await serverManager.stopServer(serverId);
          break;
        case 'restart':
          await serverManager.restartServer(serverId);
          break;
        case 'kill':
          // Force stop
          const server = serverManager['servers'].get(serverId);
          if (server) {
            await server.container.stop({ t: 0 });
          }
          break;
      }
      
      this.send({
        type: 'server-update',
        serverId,
        status: action === 'start' ? 'running' : 'stopped',
      });
    } catch (error) {
      logger.error(`Failed to handle power action ${action} for server ${serverId}: ${error}`);
    }
  }

  private async handleFileAction(serverId: string, action: string, data: any) {
    try {
      switch (action) {
        case 'list':
          const files = await serverManager.getServerFiles(serverId, data.path);
          this.send({
            type: 'file-list',
            serverId,
            path: data.path,
            files,
          });
          break;
          
        case 'read':
          const content = await serverManager.readFile(serverId, data.path);
          this.send({
            type: 'file-content',
            serverId,
            path: data.path,
            content,
          });
          break;
          
        case 'write':
          await serverManager.writeFile(serverId, data.path, data.content);
          this.send({
            type: 'file-saved',
            serverId,
            path: data.path,
          });
          break;
          
        case 'delete':
          // Implement file deletion
          break;
      }
    } catch (error) {
      logger.error(`Failed to handle file action ${action} for server ${serverId}: ${error}`);
    }
  }

  private async handleBackupAction(serverId: string, action: string, data: any) {
    try {
      switch (action) {
        case 'create':
          const backupFile = await serverManager.createBackup(serverId, data.name);
          this.send({
            type: 'backup-created',
            serverId,
            name: data.name,
            file: backupFile,
          });
          break;
          
        case 'restore':
          await serverManager.restoreBackup(serverId, data.file);
          this.send({
            type: 'backup-restored',
            serverId,
            file: data.file,
          });
          break;
      }
    } catch (error) {
      logger.error(`Failed to handle backup action ${action} for server ${serverId}: ${error}`);
    }
  }

  send(data: any) {
    if (this.ws && this.isConnected) {
      this.ws.send(JSON.stringify(data));
    }
  }

  sendConsoleOutput(serverId: string, output: string) {
    this.send({
      type: 'console-output',
      serverId,
      output,
      timestamp: Date.now(),
    });
  }

  sendServerStats(serverId: string, stats: any) {
    this.send({
      type: 'server-stats',
      serverId,
      stats,
      timestamp: Date.now(),
    });
  }
}

// Types
interface ServerInstance {
  id: string;
  container: Docker.Container;
  status: string;
  stats: any;
  resources: {
    memoryLimit: number;
    cpuLimit: number;
    diskLimit: number;
  };
  allocatedPorts: number[];
  consoleStream?: any;
}

interface CreateServerResult {
  success: boolean;
  containerId: string;
  serverPath: string;
}

interface ServerStats {
  serverId: string;
  cpu: number;
  memory: number;
  disk: number;
  status: string;
  uptime: number;
}

interface SystemStats {
  totalMemory: number;
  totalDisk: number;
  totalCpu: number;
  usedMemory: number;
  usedDisk: number;
  usedCpu: number;
  serverStats: ServerStats[];
  containerCount: number;
  dockerVersion: string;
}

interface FileInfo {
  name: string;
  path: string;
  type: 'file' | 'directory';
  size: number;
  modified: Date;
  permissions: string;
}

// Initialize components
const serverManager = new ServerManager();
const controlPanelComms = new ControlPanelCommunicator();
let websocketClient: WebSocketClient | null = null;

// Listen for console output
serverManager.on('console-output', ({ serverId, output }) => {
  if (websocketClient) {
    websocketClient.sendConsoleOutput(serverId, output);
  }
});

// Setup Express API for local management
const app = express();
app.use(cors());
app.use(helmet());
app.use(express.json({ limit: '100mb' }));

// Worker status endpoint
app.get('/status', (req, res) => {
  res.json({
    status: 'online',
    workerName: config.workerName,
    serverCount: serverManager['servers'].size,
    timestamp: new Date().toISOString(),
  });
});

// Server management endpoints
app.post('/servers/:id/console', async (req, res) => {
  try {
    const { id } = req.params;
    const { command } = req.body;
    
    if (!command) {
      return res.status(400).json({ error: 'Command is required' });
    }
    
    await serverManager.sendConsoleInput(id, command);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/servers/:id/files', async (req, res) => {
  try {
    const { id } = req.params;
    const { path = '/' } = req.query;
    
    const files = await serverManager.getServerFiles(id, path as string);
    res.json(files);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/servers/:id/files/read', async (req, res) => {
  try {
    const { id } = req.params;
    const { path } = req.query;
    
    if (!path) {
      return res.status(400).json({ error: 'Path is required' });
    }
    
    const content = await serverManager.readFile(id, path as string);
    res.json({ content });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/servers/:id/files/write', async (req, res) => {
  try {
    const { id } = req.params;
    const { path, content } = req.body;
    
    if (!path || content === undefined) {
      return res.status(400).json({ error: 'Path and content are required' });
    }
    
    await serverManager.writeFile(id, path, content);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/servers/:id/backup', async (req, res) => {
  try {
    const { id } = req.params;
    const { name } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Backup name is required' });
    }
    
    const backupFile = await serverManager.createBackup(id, name);
    res.json({ success: true, backupFile });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Start the worker
async function startWorker() {
  logger.info('Starting Game Panel Worker...');
  logger.info(`Worker Name: ${config.workerName}`);
  logger.info(`Control Panel: ${config.controlPanelUrl}`);
  logger.info(`Server Data Path: ${config.serverDataPath}`);
  
  // Register with control panel
  await controlPanelComms.registerWorker();
  
  // Start WebSocket client
  if (config.controlPanelUrl) {
    websocketClient = new WebSocketClient(config.controlPanelUrl, config.workerSecret);
  }
  
  // Start heartbeat (every 30 seconds)
  cron.schedule('*/30 * * * * *', () => {
    controlPanelComms.sendHeartbeat();
  });
  
  // Send detailed server stats (every 10 seconds)
  cron.schedule('*/10 * * * * *', async () => {
    try {
      const stats = await serverManager.getServerStats();
      for (const stat of stats) {
        if (websocketClient) {
          websocketClient.sendServerStats(stat.serverId, stat);
        }
      }
    } catch (error) {
      logger.error(`Failed to send detailed stats: ${error}`);
    }
  });
  
  // Start Express API
  app.listen(config.workerPort, () => {
    logger.info(`Worker API listening on port ${config.workerPort}`);
  });
  
  logger.info('Worker started successfully');
  
  // Log system info
  const systemStats = await serverManager.getSystemStats();
  logger.info(`System Resources - Memory: ${systemStats.usedMemory}/${systemStats.totalMemory}MB, CPU: ${systemStats.usedCpu}/${systemStats.totalCpu}%, Disk: ${systemStats.usedDisk}/${systemStats.totalDisk}MB`);
}

// Handle graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('Shutting down worker...');
  
  // Stop all servers gracefully
  for (const [serverId, server] of serverManager['servers']) {
    if (server.status === 'running') {
      try {
        await serverManager.stopServer(serverId);
        logger.info(`Stopped server ${serverId} during shutdown`);
      } catch (error) {
        logger.error(`Failed to stop server ${serverId} during shutdown: ${error}`);
      }
    }
  }
  
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('Received SIGINT, shutting down...');
  process.exit(0);
});

// Start the worker
startWorker().catch((error) => {
  logger.error(`Failed to start worker: ${error}`);
  process.exit(1);
});
EOF

# Build the worker
echo -e "${GREEN}[8/15] Building worker application...${NC}"
cd /var/lib/gamepanel-worker/app
npm run build

# Create systemd service for worker
cat > /etc/systemd/system/gamepanel-worker.service <<EOF
[Unit]
Description=Game Panel Worker
After=docker.service network.target
Requires=docker.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/var/lib/gamepanel-worker/app
Environment=NODE_ENV=production
EnvironmentFile=/var/lib/gamepanel-worker/app/.env
ExecStart=/usr/bin/npm start
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gamepanel-worker

# Security
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/gamepanel-worker

# Docker socket access
BindReadOnlyPaths=/var/run/docker.sock

[Install]
WantedBy=multi-user.target
EOF

# Create Docker network
echo -e "${GREEN}[9/15] Creating Docker network...${NC}"
docker network create gamepanel-network 2>/dev/null || true

# Set permissions
echo -e "${GREEN}[10/15] Setting permissions...${NC}"
chown -R root:root /var/lib/gamepanel-worker
chmod -R 755 /var/lib/gamepanel-worker

# Start worker service
echo -e "${GREEN}[11/15] Starting worker service...${NC}"
systemctl daemon-reload
systemctl start gamepanel-worker
systemctl enable gamepanel-worker

# Create test script
echo -e "${GREEN}[12/15] Creating test scripts...${NC}"
cat > /var/lib/gamepanel-worker/scripts/test-connection.sh <<EOF
#!/bin/bash
echo "Testing connection to control panel..."
curl -X POST "${CONTROL_PANEL_URL}/api/nodes/register" \
  -H "X-Worker-Token: ${WORKER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "${WORKER_NAME}",
    "hostname": "$(hostname)",
    "ipAddress": "${SERVER_IP}",
    "port": ${WORKER_PORT},
    "secretToken": "${WORKER_TOKEN}",
    "location": "datacenter-1",
    "totalMemory": $(free -m | awk '/^Mem:/{print $2}'),
    "totalDisk": $(df -m / | awk 'NR==2{print $4}'),
    "totalCpu": $(nproc)
  }'
echo ""
EOF

cat > /var/lib/gamepanel-worker/scripts/docker-images.sh <<EOF
#!/bin/bash
# Install common game server images
echo "Pulling common Docker images..."

# Minecraft
docker pull itzg/minecraft-server:latest

# CS:GO
docker pull cm2network/csgo:latest

# Team Fortress 2
docker pull cm2network/tf2:latest

# Garry's Mod
docker pull cm2network/garrysmod:latest

# Satisfactory
docker pull wolveix/satisfactory-server:latest

# Valheim
docker pull lloesche/valheim-server:latest

# Factorio
docker pull factoriotools/factorio:latest

echo "Images pulled successfully!"
EOF

chmod +x /var/lib/gamepanel-worker/scripts/*.sh

# Create monitoring script
cat > /var/lib/gamepanel-worker/scripts/monitor.sh <<EOF
#!/bin/bash
# Monitor script for worker

LOG_FILE="/var/lib/gamepanel-worker/logs/monitor.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - \$1" >> \$LOG_FILE
}

check_docker() {
    if ! systemctl is-active --quiet docker; then
        log "Docker is not running, restarting..."
        systemctl restart docker
        sleep 5
    fi
    
    if docker ps > /dev/null 2>&1; then
        log "Docker is running"
        return 0
    else
        log "Docker is not responding"
        return 1
    fi
}

check_worker() {
    if ! systemctl is-active --quiet gamepanel-worker; then
        log "Worker service is not running, restarting..."
        systemctl restart gamepanel-worker
        return 1
    else
        log "Worker service is running"
        return 0
    fi
}

check_disk() {
    USAGE=\$(df /var/lib/gamepanel-worker | awk 'NR==2 {print \$5}' | sed 's/%//')
    if [ \$USAGE -gt 90 ]; then
        log "⚠️  Disk usage is high: \${USAGE}%"
        
        # Clean up old backups
        find /var/lib/gamepanel-worker/backups -name "*.tar.gz" -mtime +7 -delete
        log "Cleaned up backups older than 7 days"
    fi
}

check_memory() {
    FREE_MEM=\$(free -m | awk 'NR==2{print \$4}')
    if [ \$FREE_MEM -lt 512 ]; then
        log "⚠️  Low memory: \${FREE_MEM}MB free"
    fi
}

check_containers() {
    TOTAL=\$(docker ps -q | wc -l)
    RUNNING=\$(docker ps -q --filter "status=running" | wc -l)
    
    if [ \$RUNNING -ne \$TOTAL ]; then
        log "⚠️  Some containers are not running: \${RUNNING}/\${TOTAL}"
        
        # Try to restart stopped containers
        STOPPED=\$(docker ps -a --filter "status=exited" --filter "status=paused" -q)
        if [ -n "\$STOPPED" ]; then
            echo "\$STOPPED" | xargs -r docker start
            log "Restarted stopped containers"
        fi
    fi
}

log "=== Starting monitoring check ==="
check_docker
check_worker
check_disk
check_memory
check_containers
log "=== Monitoring check completed ==="
EOF

chmod +x /var/lib/gamepanel-worker/scripts/monitor.sh

# Add monitoring to cron
(crontab -l 2>/dev/null; echo "*/5 * * * * /var/lib/gamepanel-worker/scripts/monitor.sh") | crontab -

# Pull some common Docker images
echo -e "${GREEN}[13/15] Pulling common Docker images...${NC}"
docker pull debian:bullseye-slim
docker pull alpine:latest
docker pull ubuntu:22.04

# Test Docker
echo -e "${GREEN}[14/15] Testing Docker...${NC}"
docker run --rm hello-world

# Final test
echo -e "${GREEN}[15/15] Testing worker service...${NC}"
sleep 5
systemctl status gamepanel-worker --no-pager

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}🎉 Worker Unit Installation Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e ""
echo -e "${YELLOW}📋 Installation Summary:${NC}"
echo -e "  Worker Name:    ${WORKER_NAME}"
echo -e "  Control Panel:  ${CONTROL_PANEL_URL}"
echo -e "  Worker Port:    ${WORKER_PORT}"
echo -e "  Server IP:      ${SERVER_IP}"
echo -e "  Docker Socket:  /var/run/docker.sock"
echo -e ""
echo -e "${YELLOW}🔧 Management Commands:${NC}"
echo -e "  Start worker:   systemctl start gamepanel-worker"
echo -e "  Stop worker:    systemctl stop gamepanel-worker"
echo -e "  View logs:      journalctl -u gamepanel-worker -f"
echo -e "  Test connection:/var/lib/gamepanel-worker/scripts/test-connection.sh"
echo -e ""
echo -e "${YELLOW}📁 Important Directories:${NC}"
echo -e "  Server data:    /var/lib/gamepanel-worker/servers/"
echo -e "  Backups:        /var/lib/gamepanel-worker/backups/"
echo -e "  Logs:           /var/lib/gamepanel-worker/logs/"
echo -e "  Application:    /var/lib/gamepanel-worker/app/"
echo -e ""
echo -e "${YELLOW}⚠️  Next Steps:${NC}"
echo -e "  1. Ensure the control panel has this worker's IP in ALLOWED_IPS"
echo -e "  2. Pull game server images: /var/lib/gamepanel-worker/scripts/docker-images.sh"
echo -e "  3. Configure firewall to allow traffic from control panel"
echo -e "  4. Set up monitoring (Prometheus/Grafana) for this worker"
echo -e ""
echo -e "${BLUE}========================================${NC}"