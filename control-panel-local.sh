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
echo -e "${BLUE}    Local Installation for Testing      ${NC}"
echo -e "${BLUE}========================================${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root${NC}" 
    exit 1
fi

# Configuration for local installation
DOMAIN="localhost"
ADMIN_EMAIL="admin@localhost"
read -p "Enter database password for PostgreSQL: " DB_PASSWORD
read -p "Enter JWT secret key (minimum 32 characters, press Enter to generate): " JWT_SECRET

# Generate random secrets if not provided
DB_PASSWORD=${DB_PASSWORD:-$(openssl rand -base64 32)}
JWT_SECRET=${JWT_SECRET:-$(openssl rand -base64 48)}
WORKER_TOKEN=$(openssl rand -base64 32)
ENCRYPTION_KEY=$(openssl rand -base64 32)
LOCAL_IP=$(hostname -I | awk '{print $1}')

# Log configuration
echo -e "${YELLOW}Configuration Summary:${NC}"
echo -e "Domain: ${DOMAIN}"
echo -e "Local IP: ${LOCAL_IP}"
echo -e "Worker Token: ${WORKER_TOKEN}"

# Update system
echo -e "${GREEN}[1/20] Updating system packages...${NC}"
apt update && apt upgrade -y

# Install required packages
echo -e "${GREEN}[2/20] Installing required packages...${NC}"
apt install -y curl wget git gnupg lsb-release ca-certificates apt-transport-https \
    software-properties-common ufw nginx \
    postgresql postgresql-contrib redis-server build-essential \
    python3 python3-pip python3-venv dos2unix docker.io docker-compose \
    libssl-dev pkg-config

# Install Node.js 20.x
echo -e "${GREEN}[3/20] Installing Node.js...${NC}"
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs

# Verify installations
node --version
npm --version

# Start and enable Docker
echo -e "${GREEN}[4/20] Configuring Docker...${NC}"
systemctl start docker
systemctl enable docker
usermod -aG docker www-data

# Místo aktuálního kódu použij:
echo -e "${GREEN}[5/20] Configuring PostgreSQL...${NC}"
sudo -u postgres psql -c "CREATE USER panel_admin WITH PASSWORD '$DB_PASSWORD';"
sudo -u postgres psql -c "ALTER USER panel_admin WITH SUPERUSER;"
sudo -u postgres psql -c "CREATE DATABASE gamepanel_control OWNER panel_admin;"
sudo -u postgres psql -d gamepanel_control -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"

# Po verify installations přidej:
echo -e "${GREEN}Installing TypeScript globally...${NC}"
npm install -g typescript ts-node

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
mkdir -p {backend,frontend,uploads,scripts,logs,ssl,worker}

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
    "node-cron": "^3.0.2",
    "axios": "^1.6.0"
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

# Create environment file for LOCALHOST
cat > .env <<EOF
# Database
DATABASE_URL="postgresql://panel_admin:${DB_PASSWORD}@localhost:5432/gamepanel_control?schema=public"

# Redis
REDIS_URL="redis://localhost:6379"

# Application
NODE_ENV=development
PORT=3001
HOST=0.0.0.0
API_VERSION=v1
JWT_SECRET="${JWT_SECRET}"
JWT_EXPIRES_IN=7d
BCRYPT_SALT_ROUNDS=12

# Security
ENCRYPTION_KEY="${ENCRYPTION_KEY}"
ALLOWED_ORIGINS="http://localhost:3000,http://${LOCAL_IP}:3000,http://127.0.0.1:3000"
ALLOWED_IPS="192.168.1.0/24,10.0.0.0/8,127.0.0.1,${LOCAL_IP}"

# Worker Communication
WORKER_SECRET_TOKEN="${WORKER_TOKEN}"
WORKER_HEARTBEAT_INTERVAL=30000
WORKER_CONTROL_PANEL_URL="http://${LOCAL_IP}:3001"

# File Upload
MAX_FILE_SIZE=104857600
UPLOAD_PATH="/var/www/gamepanel/control-panel/uploads"
MAX_UPLOAD_FILES=50

# Email (configure as needed)
SMTP_HOST="localhost"
SMTP_PORT=25
SMTP_SECURE=false
SMTP_USER=""
SMTP_PASS=""
EMAIL_FROM="noreply@localhost"

# WebSocket
WEBSOCKET_PATH="/socket.io"
WEBSOCKET_PING_TIMEOUT=60000
WEBSOCKET_PING_INTERVAL=25000

# Logging
LOG_LEVEL="debug"
LOG_FILE="/var/www/gamepanel/control-panel/logs/app.log"
ERROR_LOG_FILE="/var/www/gamepanel/control-panel/logs/error.log"

# API Rate Limiting
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=1000

# Local Node Configuration
NODE_NAME="local-node"
NODE_HOSTNAME="$(hostname)"
NODE_IP="${LOCAL_IP}"
NODE_PORT=2025
NODE_SECRET_TOKEN="${WORKER_TOKEN}"
NODE_LOCATION="Local"
NODE_TOTAL_MEMORY=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 ))
NODE_TOTAL_DISK=$(( $(df / --output=size | tail -1) / 1024 ))
NODE_TOTAL_CPU=$(nproc)
EOF

# Create Prisma schema (stejné jako předtím)
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

# Create source directory structure (stejné jako předtím, ale upravíme server.ts pro localhost)
mkdir -p src/{controllers,middleware,services,routes,utils,sockets,types}
# Po mkdir -p src/{controllers,middleware,services,routes,utils,sockets,types}
# Přidej:
mkdir -p src/{controllers,middleware,services,routes,utils,sockets,types}
cd /var/www/gamepanel/control-panel/backend
# Vytvoř základní middleware
cat > src/middleware/auth.ts <<'EOF'
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!);
    (req as any).user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};
EOF

cat > src/middleware/errorHandler.ts <<'EOF'
import { Request, Response, NextFunction } from 'express';

export const errorHandler = (
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  console.error(err.stack);
  
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';
  
  res.status(statusCode).json({
    success: false,
    error: message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
};
EOF

cat > src/utils/logger.ts <<'EOF'
import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';

const { combine, timestamp, printf, colorize, json } = winston.format;

const logFormat = printf(({ level, message, timestamp }) => {
  return `${timestamp} ${level}: ${message}`;
});

export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: combine(
    timestamp(),
    logFormat
  ),
  transports: [
    new winston.transports.Console({
      format: combine(colorize(), logFormat)
    }),
    new DailyRotateFile({
      filename: process.env.LOG_FILE || 'logs/app-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxFiles: '30d'
    }),
    new DailyRotateFile({
      filename: process.env.ERROR_LOG_FILE || 'logs/error-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      level: 'error',
      maxFiles: '30d'
    })
  ]
});
EOF
# Auth routes
cat > src/routes/auth.routes.ts <<'EOF'
import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';

const router = Router();
const prisma = new PrismaClient();

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const user = await prisma.user.findUnique({
      where: { email }
    });
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET!,
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );
    
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
        firstName: user.firstName,
        lastName: user.lastName
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

router.post('/register', async (req, res) => {
  // Simplified registration for local
  const { email, password, username } = req.body;
  
  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const user = await prisma.user.create({
      data: {
        email,
        username,
        password: hashedPassword,
        role: 'USER'
      }
    });
    
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET!,
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );
    
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role
      }
    });
  } catch (error) {
    res.status(400).json({ error: 'Registration failed' });
  }
});

export default router;
EOF

# Server routes
cat > src/routes/server.routes.ts <<'EOF'
import { Router } from 'express';

const router = Router();

router.get('/', (req, res) => {
  res.json({ message: 'Servers endpoint' });
});

router.post('/', (req, res) => {
  res.json({ message: 'Create server' });
});

export default router;
EOF

# Similar for other routes - vytvoř zjednodušené verze
# Create all the source files (stejné jako předtím, ale upravíme některé pro localhost)
# ZDE VLOŽ VŠECHNY SOUBORY Z PŘEDCHOZÍHO OPRAVENÉHO SKRIPTU (WorkerManager.ts, file.routes.ts, backup.routes.ts, atd.)
# Pro stručnost zde nekopíruji všechny soubory, ale použiju tvůj původní kód s úpravami pro localhost

# Vytvořím zkrácenou verzi - vytvoříme hlavní soubory:

# 1. Vytvoř základní server.ts s localhost úpravami
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
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://127.0.0.1:3000'],
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
  contentSecurityPolicy: false // Disable for local development
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
}));

app.use(express.json({ limit: process.env.MAX_FILE_SIZE || '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting (more generous for local development)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // Increased for local development
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', limiter);

// Serve uploads statically
app.use('/uploads', express.static(process.env.UPLOAD_PATH || '/var/www/gamepanel/control-panel/uploads'));

// Swagger documentation
if (process.env.NODE_ENV !== 'production') {
  const swaggerPath = path.join(__dirname, '../docs/swagger.yaml');
  if (fs.existsSync(swaggerPath)) {
    const swaggerDocument = YAML.load(swaggerPath);
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
  }
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
  logger.info(`Access the panel at: http://localhost:3000`);
  
  // Clean up offline workers every minute
  setInterval(() => {
    workerManager.cleanupOfflineWorkers();
  }, 60000);
});

export { io, prisma, workerManager };
EOF
# Před "npm run build" přidej:
echo -e "${GREEN}[9/20] Installing backend dependencies...${NC}"
cd /var/www/gamepanel/control-panel/backend
npm install

echo -e "${GREEN}[9.5/20] Generating Prisma client...${NC}"
npx prisma generate

# Build backend
echo -e "${GREEN}[9.8/20] Building backend...${NC}"
npm run build

# Create systemd service for backend
cat > /etc/systemd/system/gamepanel-control.service <<EOF
[Unit]
Description=Game Panel Control API
After=network.target postgresql.service redis-server.service docker.service
Requires=postgresql.service redis-server.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/var/www/gamepanel/control-panel/backend
Environment=NODE_ENV=development
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
ReadWritePaths=/var/www/gamepanel/control-panel/logs /var/www/gamepanel/control-panel/uploads

[Install]
WantedBy=multi-user.target
EOF

# Setup frontend for localhost
echo -e "${GREEN}[10/20] Setting up frontend for localhost...${NC}"
cd /var/www/gamepanel/control-panel/frontend

# Create basic HTML frontend for localhost
cat > index.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Game Control Panel - Local</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            padding: 2rem;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 800px;
            width: 100%;
        }
        h1 {
            color: #333;
            margin-bottom: 1rem;
        }
        .panel {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin: 2rem 0;
        }
        .card {
            flex: 1;
            min-width: 250px;
            background: #f8fafc;
            border-radius: 10px;
            padding: 1.5rem;
            text-align: left;
        }
        .card h3 {
            color: #3b82f6;
            margin-bottom: 1rem;
        }
        .status {
            background: #f0f9ff;
            border: 2px solid #3b82f6;
            border-radius: 10px;
            padding: 1rem;
            margin: 1rem 0;
        }
        .status.ok { border-color: #10b981; background: #f0fdf4; }
        .status.error { border-color: #ef4444; background: #fef2f2; }
        .buttons {
            display: flex;
            gap: 10px;
            margin-top: 1rem;
            flex-wrap: wrap;
        }
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            text-decoration: none;
            display: inline-block;
        }
        .btn-primary {
            background: #3b82f6;
            color: white;
        }
        .btn-secondary {
            background: #6b7280;
            color: white;
        }
        .btn-success {
            background: #10b981;
            color: white;
        }
        code {
            background: #1e293b;
            color: #f1f5f9;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            display: block;
            margin: 0.5rem 0;
            word-break: break-all;
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
        .log {
            background: #1e293b;
            color: #f1f5f9;
            padding: 1rem;
            border-radius: 5px;
            font-family: monospace;
            font-size: 0.8rem;
            max-height: 200px;
            overflow-y: auto;
            text-align: left;
            margin-top: 1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎮 Game Control Panel - Local Development</h1>
        <p>Running on: http://localhost:3000</p>
        
        <div id="status" class="status">
            Checking API status...
        </div>
        
        <div class="panel">
            <div class="card">
                <h3>Control Panel</h3>
                <p><strong>API:</strong> <span id="apiStatus">Checking...</span></p>
                <p><strong>Database:</strong> <span id="dbStatus">Checking...</span></p>
                <p><strong>Redis:</strong> <span id="redisStatus">Checking...</span></p>
                <div class="buttons">
                    <a href="http://localhost:3000/api-docs" class="btn btn-primary" target="_blank">API Docs</a>
                    <a href="http://localhost:3000/health" class="btn btn-secondary" target="_blank">Health Check</a>
                </div>
            </div>
            
            <div class="card">
                <h3>Worker Node</h3>
                <p><strong>Status:</strong> <span id="workerStatus">Not connected</span></p>
                <p><strong>Token:</strong> <code id="workerToken">${WORKER_TOKEN}</code></p>
                <div class="buttons">
                    <button onclick="startWorker()" class="btn btn-success">Start Local Worker</button>
                    <button onclick="checkWorker()" class="btn btn-secondary">Check Worker</button>
                </div>
            </div>
            
            <div class="card">
                <h3>Quick Access</h3>
                <p><strong>API Base URL:</strong> <code>http://localhost:3000/api</code></p>
                <p><strong>WebSocket:</strong> <code>ws://localhost:3000/socket.io</code></p>
                <p><strong>Admin Login:</strong> admin@localhost / admin123</p>
            </div>
        </div>
        
        <div class="endpoints">
            <h3>Quick Links:</h3>
            <div class="endpoint"><a href="http://localhost:3000/api/auth/login" target="_blank">POST /api/auth/login</a></div>
            <div class="endpoint"><a href="http://localhost:3000/api/servers" target="_blank">GET /api/servers</a></div>
            <div class="endpoint"><a href="http://localhost:3000/api/nodes" target="_blank">GET /api/nodes</a></div>
            <div class="endpoint"><a href="http://localhost:3000/health" target="_blank">GET /health</a></div>
        </div>
        
        <div class="log" id="logOutput">
            System log will appear here...
        </div>
    </div>
    
    <script>
        const logOutput = document.getElementById('logOutput');
        const workerToken = '${WORKER_TOKEN}';
        const localIp = '${LOCAL_IP}';
        
        function log(message) {
            const timestamp = new Date().toLocaleTimeString();
            logOutput.innerHTML = `[\${timestamp}] \${message}<br>` + logOutput.innerHTML;
        }
        
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
                
                log('API status check: OK');
            } catch (error) {
                document.getElementById('apiStatus').textContent = '❌ Offline';
                document.getElementById('status').className = 'status error';
                document.getElementById('status').innerHTML = 'API is not reachable. Check the backend service.';
                log('API status check: FAILED');
            }
        }
        
        async function checkWorker() {
            try {
                const response = await fetch('/api/worker/status');
                const data = await response.json();
                
                if (data.workers && data.workers.length > 0) {
                    document.getElementById('workerStatus').textContent = '✅ Connected';
                    document.getElementById('workerStatus').style.color = '#10b981';
                    log('Worker check: Connected');
                } else {
                    document.getElementById('workerStatus').textContent = '❌ Not connected';
                    document.getElementById('workerStatus').style.color = '#ef4444';
                    log('Worker check: No workers connected');
                }
            } catch (error) {
                document.getElementById('workerStatus').textContent = '❌ Error';
                log('Worker check error: ' + error.message);
            }
        }
        
        async function startWorker() {
            log('Starting local worker...');
            
            try {
                const response = await fetch('/api/nodes', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + localStorage.getItem('token')
                    },
                    body: JSON.stringify({
                        name: 'local-node',
                        hostname: window.location.hostname,
                        ipAddress: localIp,
                        port: 2025,
                        location: 'Local',
                        totalMemory: 8192,
                        totalDisk: 51200,
                        totalCpu: 4
                    })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    log('Worker node created: ' + data.node.name);
                    log('Worker token: ' + data.secretToken);
                    
                    // Automatically register the worker
                    registerWorker(data.secretToken);
                } else {
                    log('Failed to create worker node');
                }
            } catch (error) {
                log('Error creating worker: ' + error.message);
            }
        }
        
        async function registerWorker(token) {
            try {
                const response = await fetch('http://' + localIp + ':2025/api/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    },
                    body: JSON.stringify({
                        controlPanelUrl: 'http://' + localIp + ':3001',
                        secretToken: token
                    })
                });
                
                if (response.ok) {
                    log('Worker registered successfully');
                    checkWorker();
                }
            } catch (error) {
                log('Worker registration error: ' + error.message);
            }
        }
        
        // WebSocket connection
        const socket = new WebSocket('ws://localhost:3000/socket.io');
        
        socket.onopen = () => {
            log('WebSocket connected');
        };
        
        socket.onmessage = (event) => {
            log('WebSocket: ' + event.data);
        };
        
        socket.onerror = (error) => {
            log('WebSocket error: ' + error.message);
        };
        
        // Check status on load
        checkStatus();
        checkWorker();
        
        // Check every 30 seconds
        setInterval(checkStatus, 30000);
        setInterval(checkWorker, 10000);
        
        // Try to auto-login for convenience
        async function autoLogin() {
            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        username: 'admin@localhost',
                        password: 'admin123'
                    })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    localStorage.setItem('token', data.token);
                    log('Auto-login successful');
                }
            } catch (error) {
                // Ignore auto-login errors
            }
        }
        
        autoLogin();
    </script>
</body>
</html>
EOF

# Configure Nginx for localhost (HTTP only, no SSL)
echo -e "${GREEN}[11/20] Configuring Nginx for localhost...${NC}"
cat > /etc/nginx/sites-available/gamepanel-local <<EOF
# Local development server
server {
    listen 3000;
    listen [::]:3000;
    server_name localhost 127.0.0.1 ${LOCAL_IP};
    
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
    
    # Uploads
    location /uploads/ {
        alias /var/www/gamepanel/control-panel/uploads/;
        expires 6h;
        add_header Cache-Control "public";
        access_log off;
    }
    
    # Frontend routing
    location / {
        try_files \$uri \$uri/ /index.html;
        expires -1;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
    }
    
    # Deny access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF

# Enable local site and disable default
ln -sf /etc/nginx/sites-available/gamepanel-local /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test Nginx configuration
nginx -t

# Restart Nginx
systemctl restart nginx

# Apply database migrations
echo -e "${GREEN}[12/20] Applying database migrations...${NC}"
cd /var/www/gamepanel/control-panel/backend
npx prisma db push --accept-data-loss

# Create admin user
echo -e "${GREEN}[13/20] Creating admin user...${NC}"
node -e "
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function createAdmin() {
  const hashedPassword = await bcrypt.hash('admin123', 12);
  
  await prisma.user.create({
    data: {
      email: 'admin@localhost',
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
  console.log('  Email: admin@localhost');
  console.log('  Password: admin123');
  console.log('');
  console.log('⚠️  IMPORTANT: Change the password immediately!');
}

createAdmin().catch(console.error).finally(() => prisma.\$disconnect());
"
# Po vytvoření admin usera přidej:
systemctl restart gamepanel-control
sleep 5

# Create local node in database
echo -e "${GREEN}[14/20] Creating local node in database...${NC}"
node -e "
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function createLocalNode() {
  const totalMemory = Math.floor(require('os').totalmem() / 1024 / 1024);
  const totalDisk = Math.floor(require('fs').statSync('/').size / 1024 / 1024);
  const totalCpu = require('os').cpus().length;
  
  const node = await prisma.node.create({
    data: {
      name: 'local-node',
      hostname: require('os').hostname(),
      ipAddress: '${LOCAL_IP}',
      port: 2025,
      secretToken: '${WORKER_TOKEN}',
      location: 'Local',
      totalMemory: totalMemory,
      totalDisk: totalDisk,
      totalCpu: totalCpu,
      totalSlots: 100,
      allowedIps: ['127.0.0.1', '${LOCAL_IP}'],
      isActive: true
    }
  });
  
  console.log('✓ Local node created:');
  console.log('  Name: ' + node.name);
  console.log('  IP: ' + node.ipAddress + ':' + node.port);
  console.log('  Token: ' + node.secretToken);
  console.log('  Resources: ' + totalMemory + 'MB RAM, ' + totalDisk + 'MB Disk, ' + totalCpu + ' CPUs');
}

createLocalNode().catch(console.error).finally(() => prisma.\$disconnect());
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

# CREATE WORKER NODE SCRIPT (na stejném stroji)
echo -e "${GREEN}[17/20] Creating local worker node...${NC}"
cd /var/www/gamepanel/control-panel/worker

# Create simple worker node in Python (jednodušší než Node.js)
cat > worker.py <<EOF
#!/usr/bin/env python3
import requests
import time
import json
import socket
import threading
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

# Configuration
CONTROL_PANEL_URL = "http://${LOCAL_IP}:3001"
WORKER_TOKEN = "${WORKER_TOKEN}"
WORKER_PORT = 2025
NODE_ID = "local-worker-$(hostname)"

class WorkerHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/register':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            # Verify token
            if data.get('secretToken') == WORKER_TOKEN:
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {
                    'success': True,
                    'message': 'Worker registered successfully',
                    'workerId': NODE_ID
                }
                self.wfile.write(json.dumps(response).encode('utf-8'))
                print(f"[{time.strftime('%H:%M:%S')}] Worker registered with control panel")
            else:
                self.send_response(401)
                self.end_headers()
        
        elif self.path == '/api/heartbeat':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {
                'success': True,
                'timestamp': time.time()
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {
                'status': 'online',
                'workerId': NODE_ID,
                'timestamp': time.time()
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
        
        elif self.path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            # Get system stats (simplified)
            import psutil
            stats = {
                'memory': {
                    'total': psutil.virtual_memory().total // (1024 * 1024),
                    'used': psutil.virtual_memory().used // (1024 * 1024),
                    'free': psutil.virtual_memory().free // (1024 * 1024)
                },
                'cpu': {
                    'percent': psutil.cpu_percent(),
                    'cores': psutil.cpu_count()
                },
                'disk': {
                    'total': psutil.disk_usage('/').total // (1024 * 1024),
                    'used': psutil.disk_usage('/').used // (1024 * 1024),
                    'free': psutil.disk_usage('/').free // (1024 * 1024)
                }
            }
            self.wfile.write(json.dumps(stats).encode('utf-8'))
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass

def send_heartbeat():
    """Send heartbeat to control panel"""
    while True:
        try:
            response = requests.post(
                f"{CONTROL_PANEL_URL}/api/worker/heartbeat",
                headers={
                    'Authorization': f'Bearer {WORKER_TOKEN}',
                    'Content-Type': 'application/json'
                },
                json={
                    'workerId': NODE_ID,
                    'status': 'online'
                },
                timeout=5
            )
            if response.status_code == 200:
                print(f"[{time.strftime('%H:%M:%S')}] Heartbeat sent successfully")
            else:
                print(f"[{time.strftime('%H:%M:%S')}] Heartbeat failed: {response.status_code}")
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] Heartbeat error: {e}")
        
        time.sleep(30)  # Send heartbeat every 30 seconds

def register_with_control_panel():
    """Register this worker with the control panel"""
    try:
        response = requests.post(
            f"{CONTROL_PANEL_URL}/api/worker/register",
            headers={
                'Authorization': f'Bearer {WORKER_TOKEN}',
                'Content-Type': 'application/json'
            },
            json={
                'workerId': NODE_ID,
                'name': 'Local Worker',
                'ip': '${LOCAL_IP}',
                'port': WORKER_PORT,
                'secretToken': WORKER_TOKEN,
                'capabilities': ['docker', 'backup', 'file-management']
            },
            timeout=10
        )
        
        if response.status_code == 200:
            print(f"[{time.strftime('%H:%M:%S')}] Successfully registered with control panel")
            return True
        else:
            print(f"[{time.strftime('%H:%M:%S')}] Registration failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] Registration error: {e}")
        return False

def start_worker_server():
    """Start the worker HTTP server"""
    server = HTTPServer(('0.0.0.0', WORKER_PORT), WorkerHandler)
    print(f"[{time.strftime('%H:%M:%S')}] Worker node started on port {WORKER_PORT}")
    print(f"[{time.strftime('%H:%M:%S')}] Worker ID: {NODE_ID}")
    print(f"[{time.strftime('%H:%M:%S')}] Control Panel: {CONTROL_PANEL_URL}")
    
    # Start heartbeat thread
    heartbeat_thread = threading.Thread(target=send_heartbeat, daemon=True)
    heartbeat_thread.start()
    
    # Try to register with control panel
    if register_with_control_panel():
        print(f"[{time.strftime('%H:%M:%S')}] Worker fully initialized and registered")
    else:
        print(f"[{time.strftime('%H:%M:%S')}] Worker running in standalone mode")
    
    # Start server
    server.serve_forever()

if __name__ == '__main__':
    # Install required Python packages if not present
    try:
        import psutil
        import requests
    except ImportError:
        print("Installing required packages...")
        os.system('pip3 install psutil requests')
    
    start_worker_server()
EOF

# Make worker script executable
chmod +x worker.py

# Create systemd service for worker
cat > /etc/systemd/system/gamepanel-worker.service <<EOF
[Unit]
Description=Game Panel Worker Node
After=network.target docker.service gamepanel-control.service
Requires=docker.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/var/www/gamepanel/control-panel/worker
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 worker.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gamepanel-worker

[Install]
WantedBy=multi-user.target
EOF

# Install Python dependencies for worker
echo -e "${GREEN}[18/20] Installing Python dependencies for worker...${NC}"
pip3 install psutil requests

# Start worker service
echo -e "${GREEN}[19/20] Starting worker service...${NC}"
systemctl daemon-reload
systemctl start gamepanel-worker
systemctl enable gamepanel-worker

# Create test server script
echo -e "${GREEN}[20/20] Creating test scripts...${NC}"
cat > /var/www/gamepanel/scripts/test-local.sh <<EOF
#!/bin/bash
echo "=== Game Panel Local Test ==="
echo ""
echo "1. Control Panel:"
echo "   Frontend: http://localhost:3000"
echo "   API:      http://localhost:3001"
echo "   API Docs: http://localhost:3000/api-docs"
echo ""
echo "2. Worker Node:"
echo "   Port:     2025"
echo "   Health:   http://localhost:2025/health"
echo "   Stats:    http://localhost:2025/api/stats"
echo ""
echo "3. Services Status:"
systemctl status gamepanel-control --no-pager | grep -A 3 "Active:"
systemctl status gamepanel-worker --no-pager | grep -A 3 "Active:"
echo ""
echo "4. Test API:"
curl -s http://localhost:3001/health | python3 -m json.tool
echo ""
echo "5. Test Worker:"
curl -s http://localhost:2025/health | python3 -m json.tool
echo ""
echo "=== Login Credentials ==="
echo "Email:    admin@localhost"
echo "Password: admin123"
echo ""
echo "=== Quick Start ==="
echo "1. Open http://localhost:3000 in your browser"
echo "2. Login with admin credentials"
echo "3. Check if worker is connected"
echo "4. Create a test server"
EOF

chmod +x /var/www/gamepanel/scripts/test-local.sh

# Create Docker test container script
cat > /var/www/gamepanel/scripts/create-test-server.sh <<EOF
#!/bin/bash
# Create a test game server using Docker
SERVER_NAME="test-server-\$(date +%s)"
DOCKER_IMAGE="itzg/minecraft-server:latest"

echo "Creating test server: \$SERVER_NAME"
echo "Using image: \$DOCKER_IMAGE"

# Create Docker container
docker run -d \
  --name "\$SERVER_NAME" \
  -e EULA=TRUE \
  -e TYPE=PAPER \
  -e VERSION=1.20.1 \
  -p 25565:25565 \
  -v "/var/lib/gamepanel/servers/\$SERVER_NAME:/data" \
  "\$DOCKER_IMAGE"

echo "Test server created:"
echo "Name: \$SERVER_NAME"
echo "Port: 25565"
echo "Connect: localhost:25565"
echo ""
echo "To stop: docker stop \$SERVER_NAME"
echo "To remove: docker rm \$SERVER_NAME"
EOF

chmod +x /var/www/gamepanel/scripts/create-test-server.sh
# Přidej po řádku 1400:
echo -e "${GREEN}Checking services...${NC}"
sleep 3

if systemctl is-active --quiet gamepanel-control; then
    echo -e "✓ Control Panel service is running"
else
    echo -e "${RED}✗ Control Panel service failed to start${NC}"
    journalctl -u gamepanel-control --no-pager -n 20
fi

if systemctl is-active --quiet gamepanel-worker; then
    echo -e "✓ Worker service is running"
else
    echo -e "${YELLOW}⚠ Worker service may need manual configuration${NC}"
fi
# Final message
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}🎉 Local Game Panel Installation Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e ""
echo -e "${YELLOW}📋 Installation Summary:${NC}"
echo -e "  Control Panel:    http://localhost:3000"
echo -e "  API:              http://localhost:3001"
echo -e "  Worker Node:      http://localhost:2025"
echo -e "  Admin Email:      admin@localhost"
echo -e "  Admin Password:   admin123"
echo -e "  Worker Token:     ${WORKER_TOKEN}"
echo -e ""
echo -e "${YELLOW}🔧 Services:${NC}"
echo -e "  Control Panel:    systemctl status gamepanel-control"
echo -e "  Worker Node:      systemctl status gamepanel-worker"
echo -e "  Nginx:            systemctl status nginx"
echo -e "  PostgreSQL:       systemctl status postgresql"
echo -e "  Redis:            systemctl status redis-server"
echo -e "  Docker:           systemctl status docker"
echo -e ""
echo -e "${YELLOW}🚀 Quick Test:${NC}"
echo -e "  Run: /var/www/gamepanel/scripts/test-local.sh"
echo -e ""
echo -e "${YELLOW}⚠️  IMPORTANT:${NC}"
echo -e "  1. Change the admin password immediately!"
echo -e "  2. All services run on HTTP (no SSL) for local development"
echo -e "  3. Firewall is NOT configured for local installation"
echo -e ""
echo -e "${BLUE}========================================${NC}"
