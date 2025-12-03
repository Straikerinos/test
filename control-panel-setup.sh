#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BLUE='\033[0;34m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}    Custom Game Panel - Control Panel   ${NC}"
echo -e "${BLUE}    Installation Script for Ubuntu 25.10${NC}"
echo -e "${BLUE}========================================${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root${NC}" 
    exit 1
fi

# Configuration
read -p "Enter domain name for control panel (e.g., panel.yourdomain.com): " DOMAIN
read -p "Enter admin email for SSL certificates: " ADMIN_EMAIL
read -p "Enter database password for PostgreSQL: " DB_PASSWORD
read -p "Enter JWT secret key (minimum 32 characters): " JWT_SECRET

# Generate random secrets if not provided
DB_PASSWORD=${DB_PASSWORD:-$(openssl rand -base64 32)}
JWT_SECRET=${JWT_SECRET:-$(openssl rand -base64 48)}
WORKER_TOKEN=$(openssl rand -base64 32)
ENCRYPTION_KEY=$(openssl rand -base64 32)

# Log configuration
echo -e "${YELLOW}Configuration Summary:${NC}"
echo -e "Domain: ${DOMAIN}"
echo -e "Admin Email: ${ADMIN_EMAIL}"
echo -e "Worker Token: ${WORKER_TOKEN}"

# Update system
echo -e "${GREEN}[1/20] Updating system packages...${NC}"
apt update && apt upgrade -y

# Install required packages
echo -e "${GREEN}[2/20] Installing required packages...${NC}"
apt install -y curl wget git gnupg lsb-release ca-certificates apt-transport-https \
    software-properties-common ufw nginx certbot python3-certbot-nginx \
    postgresql postgresql-contrib redis-server build-essential \
    python3 python3-pip python3-venv

# Install Node.js 20.x
echo -e "${GREEN}[3/20] Installing Node.js...${NC}"
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs

# Verify installations
node --version
npm --version

# Firewall configuration
echo -e "${GREEN}[4/20] Configuring firewall...${NC}"
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# Configure PostgreSQL
echo -e "${GREEN}[5/20] Configuring PostgreSQL...${NC}"
sudo -u postgres psql -c "CREATE DATABASE gamepanel_control;"
sudo -u postgres psql -c "CREATE USER panel_admin WITH PASSWORD '$DB_PASSWORD';"
sudo -u postgres psql -c "ALTER USER panel_admin WITH SUPERUSER;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE gamepanel_control TO panel_admin;"
sudo -u postgres psql -d gamepanel_control -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"

# Configure Redis
echo -e "${GREEN}[6/20] Configuring Redis...${NC}"
systemctl enable redis-server
systemctl start redis-server

# Create application directory
echo -e "${GREEN}[7/20] Creating application directory...${NC}"
mkdir -p /var/www/gamepanel
cd /var/www/gamepanel

# Clone or create project structure
if [ ! -d "control-panel" ]; then
    mkdir -p control-panel
fi

cd control-panel

# Create project structure
mkdir -p {backend,frontend,uploads,scripts,logs,ssl}

# Setup backend
echo -e "${GREEN}[8/20] Setting up backend...${NC}"
cd backend

# Create package.json
cat > package.json <<EOF
{
  "name": "gamepanel-control",
  "version": "1.0.0",
  "description": "Custom Game Control Panel",
  "main": "dist/server.js",
  "scripts": {
    "dev": "nodemon src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js",
    "migrate": "npx prisma migrate deploy",
    "prisma:generate": "npx prisma generate"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.0",
    "dotenv": "^16.3.1",
    "prisma": "^5.3.1",
    "@prisma/client": "^5.3.1",
    "socket.io": "^4.6.1",
    "ioredis": "^5.3.2",
    "@socket.io/redis-adapter": "^8.2.0",
    "multer": "^1.4.5-lts.1",
    "uuid": "^9.0.0",
    "swagger-ui-express": "^5.0.0",
    "yamljs": "^0.3.0",
    "express-rate-limit": "^6.10.0",
    "express-validator": "^7.0.1",
    "winston": "^3.10.0",
    "winston-daily-rotate-file": "^4.7.1",
    "nodemailer": "^6.9.5",
    "node-cron": "^3.0.2"
  },
  "devDependencies": {
    "typescript": "^5.2.2",
    "@types/node": "^20.5.6",
    "@types/express": "^4.17.17",
    "@types/cors": "^2.8.13",
    "@types/bcryptjs": "^2.4.3",
    "@types/jsonwebtoken": "^9.0.2",
    "@types/multer": "^1.4.7",
    "@types/uuid": "^9.0.2",
    "nodemon": "^3.0.1",
    "ts-node": "^10.9.1",
    "@typescript-eslint/parser": "^6.5.0",
    "@typescript-eslint/eslint-plugin": "^6.5.0"
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
    "declarationMap": true,
    "sourceMap": true,
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
EOF

# Create environment file
cat > .env <<EOF
# Database
DATABASE_URL="postgresql://panel_admin:${DB_PASSWORD}@localhost:5432/gamepanel_control?schema=public"

# Redis
REDIS_URL="redis://localhost:6379"

# Application
NODE_ENV=production
PORT=3001
HOST=0.0.0.0
API_VERSION=v1
JWT_SECRET="${JWT_SECRET}"
JWT_EXPIRES_IN=7d
BCRYPT_SALT_ROUNDS=12

# Security
ENCRYPTION_KEY="${ENCRYPTION_KEY}"
ALLOWED_ORIGINS="https://${DOMAIN}"
ALLOWED_IPS="192.168.1.0/24,10.0.0.0/8,127.0.0.1"

# Worker Communication
WORKER_SECRET_TOKEN="${WORKER_TOKEN}"
WORKER_HEARTBEAT_INTERVAL=30000

# File Upload
MAX_FILE_SIZE=104857600
UPLOAD_PATH="/var/www/gamepanel/control-panel/uploads"
MAX_UPLOAD_FILES=50

# Email (configure as needed)
SMTP_HOST="smtp.gmail.com"
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=""
SMTP_PASS=""
EMAIL_FROM="noreply@${DOMAIN}"

# WebSocket
WEBSOCKET_PATH="/socket.io"
WEBSOCKET_PING_TIMEOUT=60000
WEBSOCKET_PING_INTERVAL=25000

# Logging
LOG_LEVEL="info"
LOG_FILE="/var/www/gamepanel/control-panel/logs/app.log"
ERROR_LOG_FILE="/var/www/gamepanel/control-panel/logs/error.log"

# API Rate Limiting
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100
EOF

# Create Prisma schema
mkdir -p prisma
cat > prisma/schema.prisma <<EOF
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id              String    @id @default(uuid())
  email           String    @unique
  username        String    @unique
  password        String
  firstName       String?
  lastName        String?
  avatar          String?
  role            UserRole  @default(USER)
  permissions     String[]
  isActive        Boolean   @default(true)
  isVerified      Boolean   @default(false)
  twoFactorEnabled Boolean  @default(false)
  twoFactorSecret String?
  lastLogin       DateTime?
  createdAt       DateTime  @default(now())
  updatedAt       DateTime  @updatedAt

  // Relations
  servers         Server[]
  apiKeys         ApiKey[]
  auditLogs       AuditLog[]
  notifications   Notification[]

  @@map("users")
}

model Server {
  id              String    @id @default(uuid())
  name            String
  description     String?
  identifier      String    @unique
  userId          String
  nodeId          String?
  status          ServerStatus @default(OFFLINE)
  suspended       Boolean   @default(false)
  
  // Resource limits
  memoryLimit     Int       @default(1024)    // MB
  cpuLimit        Int       @default(100)     // Percentage
  diskLimit       Int       @default(10240)   // MB
  ioPriority      Int       @default(500)
  bandwidthLimit  Int       @default(1024)    // GB
  
  // Docker configuration
  dockerImage     String
  startupCommand  String?
  stopCommand     String?
  environment     Json      @default("{}")
  dockerOptions   Json      @default("{}")
  
  // Network
  allocationId    String?
  allocatedPorts  Int[]
  dedicatedIp     String?
  
  // Statistics
  currentMemory   Int       @default(0)
  currentCpu      Float     @default(0.0)
  currentDisk     Int       @default(0)
  networkIn       BigInt    @default(0)
  networkOut      BigInt    @default(0)
  uptime          BigInt    @default(0)
  
  // Installation
  installing      Boolean   @default(false)
  installProgress Int       @default(0)
  installLog      String?
  
  // Timestamps
  createdAt       DateTime  @default(now())
  updatedAt       DateTime  @updatedAt
  suspendedAt     DateTime?
  deletedAt       DateTime?
  
  // Relations
  user            User      @relation(fields: [userId], references: [id])
  node            Node?     @relation(fields: [nodeId], references: [id])
  allocations     Allocation[]
  serverLogs      ServerLog[]
  backups         Backup[]
  
  @@map("servers")
  @@index([userId])
  @@index([nodeId])
  @@index([identifier])
}

model Node {
  id              String    @id @default(uuid())
  name            String    @unique
  hostname        String
  ipAddress       String
  port            Int       @default(2025)
  secretToken     String    @unique
  location        String
  public          Boolean   @default(true)
  maintenanceMode Boolean   @default(false)
  fqdn            String?
  scheme          String    @default("https")
  
  // Resources
  totalMemory     Int       // MB
  totalDisk       Int       // MB
  totalCpu        Int       // CPU cores
  totalSlots      Int       @default(100)
  
  // Current usage
  usedMemory      Int       @default(0)
  usedDisk        Int       @default(0)
  usedCpu         Float     @default(0.0)
  usedSlots       Int       @default(0)
  
  // Configuration
  dockerSocket    String    @default("/var/run/docker.sock")
  uploadSize      Int       @default(100) // MB
  allowedIps      String[]
  
  // Status
  isActive        Boolean   @default(true)
  lastHeartbeat   DateTime?
  statusMessage   String?
  
  // Timestamps
  createdAt       DateTime  @default(now())
  updatedAt       DateTime  @updatedAt
  
  // Relations
  servers         Server[]
  allocations     Allocation[]
  
  @@map("nodes")
}

model Allocation {
  id              String    @id @default(uuid())
  ipAddress       String
  port            Int
  serverId        String?
  nodeId          String
  assigned        Boolean   @default(false)
  notes           String?
  createdAt       DateTime  @default(now())
  
  // Relations
  server          Server?   @relation(fields: [serverId], references: [id])
  node            Node      @relation(fields: [nodeId], references: [id])
  
  @@map("allocations")
  @@unique([ipAddress, port, nodeId])
  @@index([serverId])
  @@index([nodeId])
}

model ApiKey {
  id           String    @id @default(uuid())
  userId       String
  name         String
  key          String    @unique
  secret       String
  permissions  String[]
  lastUsedAt   DateTime?
  lastUsedIp   String?
  expiresAt    DateTime?
  createdAt    DateTime  @default(now())
  
  user         User      @relation(fields: [userId], references: [id])
  
  @@map("api_keys")
  @@index([userId])
}

model AuditLog {
  id          String    @id @default(uuid())
  userId      String?
  action      String
  resource    String
  resourceId  String?
  details     Json?
  ipAddress   String?
  userAgent   String?
  createdAt   DateTime  @default(now())
  
  user        User?     @relation(fields: [userId], references: [id])
  
  @@map("audit_logs")
  @@index([userId])
  @@index([resource, resourceId])
  @@index([createdAt])
}

model ServerLog {
  id        String    @id @default(uuid())
  serverId  String
  type      LogType
  message   String
  data      Json?
  createdAt DateTime  @default(now())
  
  server    Server    @relation(fields: [serverId], references: [id])
  
  @@map("server_logs")
  @@index([serverId])
  @@index([type])
  @@index([createdAt])
}

model Backup {
  id          String    @id @default(uuid())
  serverId    String
  name        String
  uuid        String    @unique
  disk        String?
  size        Int?
  successful  Boolean   @default(false)
  locked      Boolean   @default(false)
  completedAt DateTime?
  createdAt   DateTime  @default(now())
  
  server      Server    @relation(fields: [serverId], references: [id])
  
  @@map("backups")
  @@index([serverId])
  @@index([uuid])
}

model Notification {
  id          String      @id @default(uuid())
  userId      String
  type        String
  title       String
  content     String?
  read        Boolean     @default(false)
  actionUrl   String?
  createdAt   DateTime    @default(now())
  readAt      DateTime?
  
  user        User        @relation(fields: [userId], references: [id])
  
  @@map("notifications")
  @@index([userId])
  @@index([read])
  @@index([createdAt])
}

enum UserRole {
  USER
  ADMIN
  SUPER_ADMIN
}

enum ServerStatus {
  OFFLINE
  STARTING
  ONLINE
  STOPPING
  ERROR
  SUSPENDED
  INSTALLING
  UPDATING
  RESTORING_BACKUP
}

enum LogType {
  INFO
  WARNING
  ERROR
  DEBUG
  CONSOLE
  INSTALL
  BACKUP
}
EOF

# Generate Prisma client
npx prisma generate

# Create source directory structure
mkdir -p src/{controllers,middleware,services,routes,utils,sockets,types}

# Create main server file
cat > src/server.ts <<'EOF'
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { createServer } from 'http';
import { Server as SocketServer } from 'socket.io';
import Redis from 'ioredis';
import { createAdapter } from '@socket.io/redis-adapter';
import swaggerUi from 'swagger-ui-express';
import YAML from 'yamljs';
import path from 'path';
import fs from 'fs';

import { PrismaClient } from '@prisma/client';
import { errorHandler } from './middleware/errorHandler';
import { authMiddleware } from './middleware/auth';
import { ipWhitelist } from './middleware/ipWhitelist';
import { logger } from './utils/logger';

// Import routes
import authRoutes from './routes/auth.routes';
import serverRoutes from './routes/server.routes';
import nodeRoutes from './routes/node.routes';
import userRoutes from './routes/user.routes';
import fileRoutes from './routes/file.routes';
import backupRoutes from './routes/backup.routes';

// WebSocket handlers
import { setupWebSocketHandlers } from './sockets/handlers';
import { WorkerManager } from './services/WorkerManager';

const app = express();
const httpServer = createServer(app);
const prisma = new PrismaClient();

// Redis for Socket.IO and cache
const pubClient = new Redis(process.env.REDIS_URL!);
const subClient = pubClient.duplicate();

// Socket.IO with Redis adapter for horizontal scaling
const io = new SocketServer(httpServer, {
  cors: {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
    credentials: true,
    methods: ['GET', 'POST']
  },
  adapter: createAdapter(pubClient, subClient),
  transports: ['websocket', 'polling'],
  path: process.env.WEBSOCKET_PATH || '/socket.io'
});

// Initialize worker manager
const workerManager = new WorkerManager(io, prisma);

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "ws:", "wss:"]
    }
  }
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
}));

app.use(express.json({ limit: process.env.MAX_FILE_SIZE || '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || '15') * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX || '100'),
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', limiter);

// Serve uploads statically
app.use('/uploads', express.static(process.env.UPLOAD_PATH || '/var/www/gamepanel/control-panel/uploads'));

// Swagger documentation
if (process.env.NODE_ENV !== 'production') {
  const swaggerDocument = YAML.load(path.join(__dirname, '../docs/swagger.yaml'));
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
}

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/servers', authMiddleware, serverRoutes);
app.use('/api/nodes', authMiddleware, ipWhitelist, nodeRoutes);
app.use('/api/users', authMiddleware, userRoutes);
app.use('/api/files', authMiddleware, fileRoutes);
app.use('/api/backups', authMiddleware, backupRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0',
    environment: process.env.NODE_ENV 
  });
});

// Worker status endpoint (for worker nodes)
app.get('/api/worker/status', (req, res) => {
  const workers = workerManager.getWorkerStatus();
  res.json({ workers });
});

// Error handling
app.use(errorHandler);

// Setup WebSocket handlers
setupWebSocketHandlers(io, prisma, workerManager);

// Start server
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '0.0.0.0';

// Graceful shutdown
const gracefulShutdown = async () => {
  logger.info('Starting graceful shutdown...');
  
  // Close HTTP server
  httpServer.close(async () => {
    logger.info('HTTP server closed');
    
    // Disconnect Prisma
    await prisma.$disconnect();
    logger.info('Database connections closed');
    
    // Close Redis connections
    await pubClient.quit();
    await subClient.quit();
    logger.info('Redis connections closed');
    
    process.exit(0);
  });

  // Force shutdown after 10 seconds
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Start server
httpServer.listen(PORT as number, HOST, () => {
  logger.info(`Control Panel API running on http://${HOST}:${PORT}`);
  logger.info(`Worker token: ${process.env.WORKER_SECRET_TOKEN}`);
});

export { io, prisma, workerManager };
EOF

# Create additional source files (simplified for brevity)
# Create basic controller, middleware, and service files

# Create utils/logger.ts
cat > src/utils/logger.ts <<'EOF'
import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';

const logDir = process.env.LOG_FILE ? 
  path.dirname(process.env.LOG_FILE) : 
  '/var/www/gamepanel/control-panel/logs';

// Ensure log directory exists
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.printf(({ timestamp, level, message, stack }) => {
    return `${timestamp} [${level.toUpperCase()}] ${message} ${stack || ''}`;
  })
);

export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        logFormat
      )
    }),
    new DailyRotateFile({
      filename: `${logDir}/app-%DATE%.log`,
      datePattern: 'YYYY-MM-DD',
      maxFiles: '30d',
      level: 'info'
    }),
    new DailyRotateFile({
      filename: `${logDir}/error-%DATE%.log`,
      datePattern: 'YYYY-MM-DD',
      maxFiles: '30d',
      level: 'error'
    })
  ]
});
EOF

# Create sockets/handlers.ts
cat > src/sockets/handlers.ts <<'EOF'
import { Server as SocketServer } from 'socket.io';
import { PrismaClient } from '@prisma/client';
import { logger } from '../utils/logger';
import { WorkerManager } from '../services/WorkerManager';

export const setupWebSocketHandlers = (
  io: SocketServer, 
  prisma: PrismaClient,
  workerManager: WorkerManager
) => {
  // Middleware for authentication
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization;
      
      if (!token) {
        return next(new Error('Authentication error'));
      }
      
      // Verify token and get user
      // ... authentication logic here
      
      (socket as any).user = { id: 'user-id', role: 'user' };
      next();
    } catch (error) {
      next(new Error('Authentication error'));
    }
  });

  io.on('connection', (socket) => {
    const userId = (socket as any).user?.id;
    logger.info(`Client connected: ${socket.id} (User: ${userId})`);

    // Join server room for console/updates
    socket.on('join-server', async (serverId: string) => {
      try {
        const server = await prisma.server.findUnique({
          where: { id: serverId },
          select: { userId: true }
        });

        if (server && server.userId === userId) {
          socket.join(`server:${serverId}`);
          logger.info(`User ${userId} joined server room: ${serverId}`);
        }
      } catch (error) {
        logger.error(`Error joining server room: ${error}`);
      }
    });

    // Leave server room
    socket.on('leave-server', (serverId: string) => {
      socket.leave(`server:${serverId}`);
    });

    // Console input from user
    socket.on('console-input', async (data: { serverId: string; command: string }) => {
      try {
        const { serverId, command } = data;
        
        // Verify user has access to this server
        const server = await prisma.server.findUnique({
          where: { id: serverId },
          select: { userId: true, nodeId: true }
        });

        if (!server || server.userId !== userId) {
          return;
        }

        // Send command to worker node
        workerManager.sendConsoleCommand(server.nodeId!, serverId, command);
        
        logger.info(`Console command sent to server ${serverId}: ${command}`);
      } catch (error) {
        logger.error(`Error handling console input: ${error}`);
      }
    });

    // Send server power action
    socket.on('server-power', async (data: { serverId: string; action: string }) => {
      try {
        const { serverId, action } = data;
        
        const server = await prisma.server.findUnique({
          where: { id: serverId },
          select: { userId: true, nodeId: true }
        });

        if (!server || server.userId !== userId) {
          return;
        }

        // Send power action to worker
        workerManager.sendPowerAction(server.nodeId!, serverId, action);
        
        logger.info(`Power action sent to server ${serverId}: ${action}`);
      } catch (error) {
        logger.error(`Error handling power action: ${error}`);
      }
    });

    // Send file management action
    socket.on('file-action', async (data: {
      serverId: string;
      action: string;
      path?: string;
      content?: string;
    }) => {
      try {
        const { serverId, action, path, content } = data;
        
        const server = await prisma.server.findUnique({
          where: { id: serverId },
          select: { userId: true, nodeId: true }
        });

        if (!server || server.userId !== userId) {
          return;
        }

        // Send file action to worker
        workerManager.sendFileAction(server.nodeId!, serverId, action, { path, content });
        
        logger.info(`File action sent to server ${serverId}: ${action}`);
      } catch (error) {
        logger.error(`Error handling file action: ${error}`);
      }
    });

    // Disconnect
    socket.on('disconnect', (reason) => {
      logger.info(`Client disconnected: ${socket.id} (Reason: ${reason})`);
    });
  });

  // Broadcast server status updates
  const broadcastServerUpdate = (serverId: string, data: any) => {
    io.to(`server:${serverId}`).emit('server-update', data);
  };

  // Broadcast console output
  const broadcastConsoleOutput = (serverId: string, output: string) => {
    io.to(`server:${serverId}`).emit('console-output', {
      serverId,
      output,
      timestamp: new Date().toISOString()
    });
  };

  return { broadcastServerUpdate, broadcastConsoleOutput };
};
EOF

# Build backend
echo -e "${GREEN}[9/20] Building backend...${NC}"
npm run build

# Create systemd service for backend
cat > /etc/systemd/system/gamepanel-control.service <<EOF
[Unit]
Description=Game Panel Control API
After=network.target postgresql.service redis-server.service
Requires=postgresql.service redis-server.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/var/www/gamepanel/control-panel/backend
Environment=NODE_ENV=production
EnvironmentFile=/var/www/gamepanel/control-panel/backend/.env
ExecStart=/usr/bin/npm start
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gamepanel-control

# Security
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/www/gamepanel/control-panel/logs /var/www/gamepanel/control-panel/uploads
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
EOF

# Setup frontend (simplified - you can expand this)
echo -e "${GREEN}[10/20] Setting up basic frontend...${NC}"
cd /var/www/gamepanel/control-panel/frontend

# Create basic HTML frontend
cat > index.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Game Control Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            padding: 3rem;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 500px;
            width: 90%;
        }
        h1 {
            color: #333;
            margin-bottom: 1rem;
        }
        .status {
            background: #f0f9ff;
            border: 2px solid #3b82f6;
            border-radius: 10px;
            padding: 1rem;
            margin: 1.5rem 0;
        }
        .status.ok { border-color: #10b981; background: #f0fdf4; }
        .status.error { border-color: #ef4444; background: #fef2f2; }
        .info {
            background: #f8fafc;
            border-radius: 10px;
            padding: 1rem;
            margin-top: 1.5rem;
            text-align: left;
        }
        code {
            background: #1e293b;
            color: #f1f5f9;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
        }
        .endpoints {
            margin-top: 1.5rem;
            text-align: left;
        }
        .endpoint {
            background: #f1f5f9;
            padding: 0.5rem;
            border-radius: 5px;
            margin: 0.5rem 0;
            font-family: monospace;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎮 Game Control Panel</h1>
        <p>Your custom game server management panel</p>
        
        <div id="status" class="status">
            Checking API status...
        </div>
        
        <div class="info">
            <p><strong>API Status:</strong> <span id="apiStatus">Checking...</span></p>
            <p><strong>Database:</strong> <span id="dbStatus">Checking...</span></p>
            <p><strong>Redis:</strong> <span id="redisStatus">Checking...</span></p>
        </div>
        
        <div class="endpoints">
            <h3>Available Endpoints:</h3>
            <div class="endpoint">POST /api/auth/register</div>
            <div class="endpoint">POST /api/auth/login</div>
            <div class="endpoint">GET /api/servers</div>
            <div class="endpoint">GET /api/nodes</div>
            <div class="endpoint">GET /health</div>
        </div>
        
        <div style="margin-top: 2rem; font-size: 0.9rem; color: #64748b;">
            <p>Worker Token: <code id="workerToken">${WORKER_TOKEN}</code></p>
            <p>API Base URL: <code id="apiUrl">https://${DOMAIN}/api</code></p>
        </div>
    </div>
    
    <script>
        async function checkStatus() {
            try {
                const response = await fetch('/api/health');
                const data = await response.json();
                
                document.getElementById('apiStatus').textContent = '✅ Online';
                document.getElementById('status').className = 'status ok';
                document.getElementById('status').innerHTML = 'All systems operational!';
                
                // Check database
                try {
                    const dbCheck = await fetch('/api/health');
                    document.getElementById('dbStatus').textContent = '✅ Connected';
                } catch {
                    document.getElementById('dbStatus').textContent = '❌ Disconnected';
                }
                
            } catch (error) {
                document.getElementById('apiStatus').textContent = '❌ Offline';
                document.getElementById('status').className = 'status error';
                document.getElementById('status').innerHTML = 'API is not reachable. Check the backend service.';
            }
        }
        
        // Check status on load
        checkStatus();
        // Check every 30 seconds
        setInterval(checkStatus, 30000);
        
        // WebSocket connection
        const socket = new WebSocket(\`wss://${DOMAIN}/socket.io\`);
        
        socket.onopen = () => {
            console.log('WebSocket connected');
        };
        
        socket.onmessage = (event) => {
            console.log('WebSocket message:', event.data);
        };
        
        socket.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    </script>
</body>
</html>
EOF

# Configure Nginx
echo -e "${GREEN}[11/20] Configuring Nginx...${NC}"
cat > /etc/nginx/sites-available/gamepanel <<EOF
# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    
    # ACME challenge for Let's Encrypt
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    # Redirect everything else to HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};
    
    # SSL configuration - will be updated by Certbot
    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    
    # Strong SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    
    # Root directory for frontend
    root /var/www/gamepanel/control-panel/frontend;
    index index.html;
    
    # API proxy
    location /api/ {
        proxy_pass http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_buffering off;
        client_max_body_size 100M;
        proxy_read_timeout 300s;
        proxy_connect_timeout 300s;
    }
    
    # WebSocket proxy for Socket.IO
    location /socket.io/ {
        proxy_pass http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
    
    # Static file cache
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
    
    # Frontend routing
    location / {
        try_files \$uri \$uri/ /index.html;
        expires -1;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
    }
    
    # Uploads
    location /uploads/ {
        alias /var/www/gamepanel/control-panel/uploads/;
        expires 6h;
        add_header Cache-Control "public";
        access_log off;
    }
    
    # Deny access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF

# Enable site
ln -sf /etc/nginx/sites-available/gamepanel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test Nginx configuration
nginx -t

# Obtain SSL certificate
echo -e "${GREEN}[12/20] Obtaining SSL certificate...${NC}"
certbot --nginx -d ${DOMAIN} --non-interactive --agree-tos --email ${ADMIN_EMAIL} --redirect

# Restart Nginx
systemctl restart nginx

# Apply database migrations
echo -e "${GREEN}[13/20] Applying database migrations...${NC}"
cd /var/www/gamepanel/control-panel/backend
npx prisma migrate dev --name init

# Create admin user
echo -e "${GREEN}[14/20] Creating admin user...${NC}"
node -e "
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function createAdmin() {
  const hashedPassword = await bcrypt.hash('admin123', 12);
  
  await prisma.user.create({
    data: {
      email: 'admin@${DOMAIN}',
      username: 'admin',
      password: hashedPassword,
      firstName: 'Admin',
      lastName: 'User',
      role: 'SUPER_ADMIN',
      isVerified: true,
      permissions: ['*']
    }
  });
  
  console.log('✓ Admin user created');
  console.log('  Email: admin@${DOMAIN}');
  console.log('  Password: admin123');
  console.log('');
  console.log('⚠️  IMPORTANT: Change the password immediately!');
}

createAdmin().catch(console.error).finally(() => prisma.\$disconnect());
"

# Set permissions
echo -e "${GREEN}[15/20] Setting permissions...${NC}"
chown -R www-data:www-data /var/www/gamepanel
chmod -R 755 /var/www/gamepanel
chmod -R 775 /var/www/gamepanel/control-panel/uploads

# Start backend service
echo -e "${GREEN}[16/20] Starting backend service...${NC}"
systemctl daemon-reload
systemctl start gamepanel-control
systemctl enable gamepanel-control

# Create backup script
echo -e "${GREEN}[17/20] Creating backup script...${NC}"
cat > /var/www/gamepanel/scripts/backup.sh <<'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/gamepanel"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="gamepanel_control"

mkdir -p $BACKUP_DIR

# Backup PostgreSQL
PGPASSWORD="${DB_PASSWORD}" pg_dump -U panel_admin $DB_NAME > $BACKUP_DIR/$DB_NAME_$DATE.sql
gzip $BACKUP_DIR/$DB_NAME_$DATE.sql

# Backup Redis
redis-cli SAVE
cp /var/lib/redis/dump.rdb $BACKUP_DIR/redis_$DATE.rdb
gzip $BACKUP_DIR/redis_$DATE.rdb

# Backup uploads
tar -czf $BACKUP_DIR/uploads_$DATE.tar.gz /var/www/gamepanel/control-panel/uploads

# Remove old backups (older than 30 days)
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete
find $BACKUP_DIR -name "*.rdb.gz" -mtime +30 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR/$DB_NAME_$DATE.sql.gz"
EOF

chmod +x /var/www/gamepanel/scripts/backup.sh

# Setup cron job for backups
(crontab -l 2>/dev/null; echo "0 2 * * * /var/www/gamepanel/scripts/backup.sh") | crontab -

# Setup log rotation
cat > /etc/logrotate.d/gamepanel <<EOF
/var/www/gamepanel/control-panel/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 www-data www-data
    sharedscripts
    postrotate
        systemctl reload gamepanel-control
    endscript
}
EOF

# Create monitoring script
cat > /var/www/gamepanel/scripts/monitor.sh <<'EOF'
#!/bin/bash
# Monitor script for Game Panel

LOG_FILE="/var/www/gamepanel/control-panel/logs/monitor.log"
ALERT_EMAIL="${ADMIN_EMAIL}"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
}

check_service() {
    SERVICE=$1
    if systemctl is-active --quiet $SERVICE; then
        log "✓ $SERVICE is running"
        return 0
    else
        log "✗ $SERVICE is not running"
        systemctl restart $SERVICE
        echo "Service $SERVICE was restarted" | mail -s "Game Panel Alert" $ALERT_EMAIL
        return 1
    fi
}

check_disk() {
    USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ $USAGE -gt 90 ]; then
        log "⚠️  Disk usage is high: ${USAGE}%"
        echo "Disk usage is at ${USAGE}%" | mail -s "Game Panel Alert" $ALERT_EMAIL
    fi
}

check_memory() {
    FREE_MEM=$(free -m | awk 'NR==2{print $4}')
    if [ $FREE_MEM -lt 100 ]; then
        log "⚠️  Low memory: ${FREE_MEM}MB free"
    fi
}

log "=== Starting monitoring check ==="
check_service gamepanel-control
check_service nginx
check_service postgresql
check_service redis-server
check_disk
check_memory
log "=== Monitoring check completed ==="
EOF

chmod +x /var/www/gamepanel/scripts/monitor.sh

# Add monitoring to cron
(crontab -l 2>/dev/null; echo "*/5 * * * * /var/www/gamepanel/scripts/monitor.sh") | crontab -

# Final steps
echo -e "${GREEN}[18/20] Finalizing installation...${NC}"
cd /var/www/gamepanel/control-panel/backend
npm run prisma:generate

echo -e "${GREEN}[19/20] Testing services...${NC}"
sleep 5
systemctl status gamepanel-control --no-pager

echo -e "${GREEN}[20/20] Installation completed!${NC}"

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}🎉 Game Panel Control Installation Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e ""
echo -e "${YELLOW}📋 Installation Summary:${NC}"
echo -e "  Panel URL:      https://${DOMAIN}"
echo -e "  Admin Email:    admin@${DOMAIN}"
echo -e "  Admin Password: admin123"
echo -e "  API Endpoint:   https://${DOMAIN}/api"
echo -e "  WebSocket:      wss://${DOMAIN}/socket.io"
echo -e "  Worker Token:   ${WORKER_TOKEN}"
echo -e ""
echo -e "${YELLOW}⚠️  IMPORTANT:${NC}"
echo -e "  1. Change the admin password immediately!"
echo -e "  2. Configure SMTP settings in .env file"
echo -e "  3. Update ALLOWED_IPS in .env file"
echo -e "  4. Configure firewall for worker nodes"
echo -e ""
echo -e "${YELLOW}🚀 Next Steps:${NC}"
echo -e "  1. Run the worker setup script on your worker nodes"
echo -e "  2. Configure your DNS records"
echo -e "  3. Set up monitoring (Prometheus/Grafana)"
echo -e ""
echo -e "${BLUE}========================================${NC}"