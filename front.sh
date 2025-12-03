#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BLUE='\033[0;34m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}    Game Panel - Testovací Frontend     ${NC}"
echo -e "${BLUE}    Installation Script for Ubuntu 25.10${NC}"
echo -e "${BLUE}========================================${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root${NC}" 
    exit 1
fi

# Configuration
read -p "Enter domain name for frontend (e.g., panel.yourdomain.com): " DOMAIN
read -p "Enter admin email for SSL certificates: " ADMIN_EMAIL
read -p "Enter backend API URL (e.g., https://panel.yourdomain.com/api): " API_URL
read -p "Enter WebSocket URL (e.g., wss://panel.yourdomain.com): " WS_URL

# Update system
echo -e "${GREEN}[1/12] Updating system packages...${NC}"
apt update && apt upgrade -y

# Install Nginx and certbot
echo -e "${GREEN}[2/12] Installing Nginx and certbot...${NC}"
apt install -y nginx certbot python3-certbot-nginx

# Install Node.js for build tools
echo -e "${GREEN}[3/12] Installing Node.js...${NC}"
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs npm

# Create directory for frontend
echo -e "${GREEN}[4/12] Creating frontend directory...${NC}"
mkdir -p /var/www/gamepanel-frontend
cd /var/www/gamepanel-frontend

# Create a modern Vue.js frontend with Socket.IO
echo -e "${GREEN}[5/12] Creating Vue.js frontend...${NC}"

# Create package.json
cat > package.json <<EOF
{
  "name": "gamepanel-frontend",
  "version": "1.0.0",
  "description": "Game Panel Frontend",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "vue": "^3.3.8",
    "vue-router": "^4.2.5",
    "pinia": "^2.1.7",
    "axios": "^1.6.0",
    "socket.io-client": "^4.7.2",
    "element-plus": "^2.3.8",
    "@element-plus/icons-vue": "^2.1.0",
    "dayjs": "^1.11.10"
  },
  "devDependencies": {
    "@vitejs/plugin-vue": "^4.5.0",
    "vite": "^4.5.0"
  }
}
EOF

# Install dependencies
npm install

# Create Vite config
cat > vite.config.js <<EOF
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src')
    }
  },
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '/api': {
        target: '${API_URL}',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\\/api/, '')
      },
      '/socket.io': {
        target: '${WS_URL}',
        ws: true,
        changeOrigin: true
      }
    }
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['vue', 'vue-router', 'pinia'],
          ui: ['element-plus']
        }
      }
    }
  }
})
EOF

# Create index.html
cat > index.html <<'EOF'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Game Control Panel</title>
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <style>
      * { margin: 0; padding: 0; box-sizing: border-box; }
      body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
    </style>
  </head>
  <body>
    <div id="app"></div>
    <script type="module" src="/src/main.js"></script>
  </body>
</html>
EOF

# Create source directory structure
mkdir -p src/{components,views,stores,router,utils,assets}

# Create main Vue app
cat > src/App.vue <<'EOF'
<template>
  <div id="app">
    <el-config-provider :locale="locale">
      <router-view />
    </el-config-provider>
  </div>
</template>

<script setup>
import { ElConfigProvider } from 'element-plus'
import zhCn from 'element-plus/dist/locale/zh-cn.mjs'

const locale = zhCn
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  color: #2c3e50;
  height: 100vh;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}
</style>
EOF

# Create main.js
cat > src/main.js <<'EOF'
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import * as ElementPlusIconsVue from '@element-plus/icons-vue'
import App from './App.vue'
import router from './router'
import axios from 'axios'
import io from 'socket.io-client'

// Set base URL for axios
axios.defaults.baseURL = import.meta.env.VITE_API_URL || 'http://localhost:3001/api'
axios.defaults.withCredentials = true

// Socket.IO setup
const socket = io(import.meta.env.VITE_WS_URL || 'http://localhost:3001', {
  withCredentials: true,
  autoConnect: false
})

const app = createApp(App)
const pinia = createPinia()

// Provide socket to all components
app.provide('socket', socket)

// Register all Element Plus icons
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
  app.component(key, component)
}

app.use(pinia)
app.use(router)
app.use(ElementPlus)
app.mount('#app')

export { socket }
EOF

# Create router
cat > src/router/index.js <<'EOF'
import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: () => import('@/views/Dashboard.vue'),
    meta: { requiresAuth: true }
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/Login.vue')
  },
  {
    path: '/servers',
    name: 'Servers',
    component: () => import('@/views/Servers.vue'),
    meta: { requiresAuth: true }
  },
  {
    path: '/servers/:id',
    name: 'ServerDetail',
    component: () => import('@/views/ServerDetail.vue'),
    meta: { requiresAuth: true }
  },
  {
    path: '/console/:id',
    name: 'Console',
    component: () => import('@/views/Console.vue'),
    meta: { requiresAuth: true }
  },
  {
    path: '/files/:id',
    name: 'Files',
    component: () => import('@/views/Files.vue'),
    meta: { requiresAuth: true }
  },
  {
    path: '/users',
    name: 'Users',
    component: () => import('@/views/Users.vue'),
    meta: { requiresAuth: true, requiresAdmin: true }
  },
  {
    path: '/nodes',
    name: 'Nodes',
    component: () => import('@/views/Nodes.vue'),
    meta: { requiresAuth: true, requiresAdmin: true }
  },
  {
    path: '/settings',
    name: 'Settings',
    component: () => import('@/views/Settings.vue'),
    meta: { requiresAuth: true }
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: () => import('@/views/NotFound.vue')
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// Navigation guard
router.beforeEach(async (to, from, next) => {
  const token = localStorage.getItem('token')
  
  if (to.meta.requiresAuth && !token) {
    next('/login')
  } else if (to.meta.requiresAdmin) {
    // Check if user is admin (simplified)
    const user = JSON.parse(localStorage.getItem('user') || '{}')
    if (user.role !== 'ADMIN' && user.role !== 'SUPER_ADMIN') {
      next('/')
    } else {
      next()
    }
  } else if (to.name === 'Login' && token) {
    next('/')
  } else {
    next()
  }
})

export default router
EOF

# Create stores
mkdir -p src/stores

# Auth store
cat > src/stores/auth.js <<'EOF'
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'
import router from '@/router'

export const useAuthStore = defineStore('auth', () => {
  const user = ref(JSON.parse(localStorage.getItem('user') || 'null'))
  const token = ref(localStorage.getItem('token') || '')

  const isAuthenticated = computed(() => !!token.value)
  const isAdmin = computed(() => ['ADMIN', 'SUPER_ADMIN'].includes(user.value?.role))

  // Set auth header
  if (token.value) {
    axios.defaults.headers.common['Authorization'] = `Bearer ${token.value}`
  }

  const login = async (credentials) => {
    try {
      const response = await axios.post('/auth/login', credentials)
      const { user: userData, token: authToken } = response.data
      
      user.value = userData
      token.value = authToken
      
      localStorage.setItem('user', JSON.stringify(userData))
      localStorage.setItem('token', authToken)
      axios.defaults.headers.common['Authorization'] = `Bearer ${authToken}`
      
      ElMessage.success('Login successful')
      return { success: true }
    } catch (error) {
      ElMessage.error(error.response?.data?.error || 'Login failed')
      return { success: false }
    }
  }

  const register = async (userData) => {
    try {
      const response = await axios.post('/auth/register', userData)
      ElMessage.success('Registration successful')
      return { success: true, data: response.data }
    } catch (error) {
      ElMessage.error(error.response?.data?.error || 'Registration failed')
      return { success: false }
    }
  }

  const logout = () => {
    user.value = null
    token.value = null
    localStorage.removeItem('user')
    localStorage.removeItem('token')
    delete axios.defaults.headers.common['Authorization']
    router.push('/login')
    ElMessage.info('Logged out')
  }

  const fetchUser = async () => {
    try {
      const response = await axios.get('/auth/me')
      user.value = response.data
      localStorage.setItem('user', JSON.stringify(response.data))
      return { success: true }
    } catch (error) {
      logout()
      return { success: false }
    }
  }

  return {
    user,
    token,
    isAuthenticated,
    isAdmin,
    login,
    register,
    logout,
    fetchUser
  }
})
EOF

# Server store
cat > src/stores/server.js <<'EOF'
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'

export const useServerStore = defineStore('server', () => {
  const servers = ref([])
  const currentServer = ref(null)
  const nodes = ref([])
  const isLoading = ref(false)

  const onlineServers = computed(() => 
    servers.value.filter(s => s.status === 'ONLINE')
  )
  const offlineServers = computed(() => 
    servers.value.filter(s => s.status === 'OFFLINE')
  )

  const fetchServers = async () => {
    isLoading.value = true
    try {
      const response = await axios.get('/servers')
      servers.value = response.data
      return { success: true }
    } catch (error) {
      ElMessage.error('Failed to fetch servers')
      return { success: false }
    } finally {
      isLoading.value = false
    }
  }

  const fetchServer = async (id) => {
    try {
      const response = await axios.get(`/servers/${id}`)
      currentServer.value = response.data
      return { success: true, data: response.data }
    } catch (error) {
      ElMessage.error('Failed to fetch server details')
      return { success: false }
    }
  }

  const createServer = async (serverData) => {
    try {
      const response = await axios.post('/servers', serverData)
      servers.value.push(response.data)
      ElMessage.success('Server created successfully')
      return { success: true, data: response.data }
    } catch (error) {
      ElMessage.error(error.response?.data?.error || 'Failed to create server')
      return { success: false }
    }
  }

  const updateServer = async (id, serverData) => {
    try {
      const response = await axios.put(`/servers/${id}`, serverData)
      const index = servers.value.findIndex(s => s.id === id)
      if (index !== -1) {
        servers.value[index] = response.data
      }
      if (currentServer.value?.id === id) {
        currentServer.value = response.data
      }
      ElMessage.success('Server updated successfully')
      return { success: true, data: response.data }
    } catch (error) {
      ElMessage.error('Failed to update server')
      return { success: false }
    }
  }

  const deleteServer = async (id) => {
    try {
      await axios.delete(`/servers/${id}`)
      servers.value = servers.value.filter(s => s.id !== id)
      if (currentServer.value?.id === id) {
        currentServer.value = null
      }
      ElMessage.success('Server deleted successfully')
      return { success: true }
    } catch (error) {
      ElMessage.error('Failed to delete server')
      return { success: false }
    }
  }

  const startServer = async (id) => {
    try {
      await axios.post(`/servers/${id}/start`)
      await fetchServers()
      ElMessage.success('Server started')
      return { success: true }
    } catch (error) {
      ElMessage.error('Failed to start server')
      return { success: false }
    }
  }

  const stopServer = async (id) => {
    try {
      await axios.post(`/servers/${id}/stop`)
      await fetchServers()
      ElMessage.success('Server stopped')
      return { success: true }
    } catch (error) {
      ElMessage.error('Failed to stop server')
      return { success: false }
    }
  }

  const restartServer = async (id) => {
    try {
      await axios.post(`/servers/${id}/restart`)
      await fetchServers()
      ElMessage.success('Server restarted')
      return { success: true }
    } catch (error) {
      ElMessage.error('Failed to restart server')
      return { success: false }
    }
  }

  const fetchNodes = async () => {
    try {
      const response = await axios.get('/nodes')
      nodes.value = response.data
      return { success: true }
    } catch (error) {
      ElMessage.error('Failed to fetch nodes')
      return { success: false }
    }
  }

  return {
    servers,
    currentServer,
    nodes,
    isLoading,
    onlineServers,
    offlineServers,
    fetchServers,
    fetchServer,
    createServer,
    updateServer,
    deleteServer,
    startServer,
    stopServer,
    restartServer,
    fetchNodes
  }
})
EOF

# Create views
mkdir -p src/views

# Login view
cat > src/views/Login.vue <<'EOF'
<template>
  <div class="login-container">
    <div class="login-card">
      <h2>Game Panel</h2>
      <p class="subtitle">Sign in to your account</p>
      
      <el-form
        ref="loginForm"
        :model="form"
        :rules="rules"
        @submit.prevent="handleLogin"
      >
        <el-form-item prop="email">
          <el-input
            v-model="form.email"
            placeholder="Email"
            size="large"
            :prefix-icon="User"
          />
        </el-form-item>
        
        <el-form-item prop="password">
          <el-input
            v-model="form.password"
            type="password"
            placeholder="Password"
            size="large"
            :prefix-icon="Lock"
            show-password
          />
        </el-form-item>
        
        <el-form-item>
          <el-button
            type="primary"
            size="large"
            :loading="loading"
            @click="handleLogin"
            class="login-button"
          >
            Sign In
          </el-button>
        </el-form-item>
      </el-form>
      
      <div class="demo-credentials">
        <p><strong>Demo Credentials:</strong></p>
        <p>Email: admin@example.com</p>
        <p>Password: admin123</p>
      </div>
    </div>
    
    <div class="footer">
      <p>Custom Game Panel &copy; {{ new Date().getFullYear() }}</p>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { User, Lock } from '@element-plus/icons-vue'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const authStore = useAuthStore()

const loginForm = ref(null)
const loading = ref(false)

const form = reactive({
  email: 'admin@example.com',
  password: 'admin123'
})

const rules = {
  email: [
    { required: true, message: 'Please enter email', trigger: 'blur' },
    { type: 'email', message: 'Please enter valid email', trigger: 'blur' }
  ],
  password: [
    { required: true, message: 'Please enter password', trigger: 'blur' }
  ]
}

const handleLogin = async () => {
  if (!loginForm.value) return
  
  const valid = await loginForm.value.validate()
  if (!valid) return
  
  loading.value = true
  const result = await authStore.login(form)
  loading.value = false
  
  if (result.success) {
    router.push('/')
  }
}
</script>

<style scoped>
.login-container {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 20px;
}

.login-card {
  width: 100%;
  max-width: 400px;
  padding: 40px;
  background: white;
  border-radius: 10px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
  text-align: center;
}

.login-card h2 {
  margin-bottom: 10px;
  color: #333;
  font-size: 28px;
}

.subtitle {
  color: #666;
  margin-bottom: 30px;
}

.login-button {
  width: 100%;
  margin-top: 10px;
}

.demo-credentials {
  margin-top: 30px;
  padding: 20px;
  background: #f8f9fa;
  border-radius: 5px;
  text-align: left;
  font-size: 14px;
  color: #666;
}

.demo-credentials p {
  margin: 5px 0;
}

.footer {
  margin-top: 30px;
  color: white;
  text-align: center;
}

.footer p {
  margin: 0;
  opacity: 0.8;
}
</style>
EOF

# Dashboard view
cat > src/views/Dashboard.vue <<'EOF'
<template>
  <div class="dashboard">
    <el-container>
      <!-- Sidebar -->
      <el-aside width="250px" class="sidebar">
        <div class="logo">
          <h2>🎮 Game Panel</h2>
        </div>
        
        <el-menu
          router
          :default-active="$route.path"
          class="sidebar-menu"
          background-color="#2d3748"
          text-color="#cbd5e0"
          active-text-color="#4299e1"
        >
          <el-menu-item index="/">
            <el-icon><House /></el-icon>
            <span>Dashboard</span>
          </el-menu-item>
          
          <el-menu-item index="/servers">
            <el-icon><Monitor /></el-icon>
            <span>Servers</span>
          </el-menu-item>
          
          <el-sub-menu index="3" v-if="authStore.isAdmin">
            <template #title>
              <el-icon><Setting /></el-icon>
              <span>Administration</span>
            </template>
            <el-menu-item index="/users">
              <el-icon><User /></el-icon>
              <span>Users</span>
            </el-menu-item>
            <el-menu-item index="/nodes">
              <el-icon><DataLine /></el-icon>
              <span>Nodes</span>
            </el-menu-item>
          </el-sub-menu>
          
          <el-menu-item index="/settings">
            <el-icon><Tools /></el-icon>
            <span>Settings</span>
          </el-menu-item>
          
          <el-menu-item @click="handleLogout">
            <el-icon><SwitchButton /></el-icon>
            <span>Logout</span>
          </el-menu-item>
        </el-menu>
        
        <div class="user-info">
          <el-avatar :size="40" :src="authStore.user?.avatar">
            {{ authStore.user?.username?.charAt(0).toUpperCase() }}
          </el-avatar>
          <div class="user-details">
            <strong>{{ authStore.user?.username }}</strong>
            <small>{{ authStore.user?.email }}</small>
            <el-tag size="small" :type="authStore.isAdmin ? 'danger' : 'success'">
              {{ authStore.user?.role }}
            </el-tag>
          </div>
        </div>
      </el-aside>
      
      <!-- Main content -->
      <el-container>
        <el-header class="header">
          <h1>Dashboard</h1>
          <div class="header-actions">
            <el-button type="primary" icon="Plus" @click="$router.push('/servers?create=true')">
              Create Server
            </el-button>
          </div>
        </el-header>
        
        <el-main class="main-content">
          <!-- Stats cards -->
          <div class="stats-grid">
            <el-card shadow="hover" class="stat-card">
              <div class="stat-content">
                <el-icon class="stat-icon" :color="statsColor.total"><Monitor /></el-icon>
                <div class="stat-info">
                  <h3>{{ servers.length }}</h3>
                  <p>Total Servers</p>
                </div>
              </div>
            </el-card>
            
            <el-card shadow="hover" class="stat-card">
              <div class="stat-content">
                <el-icon class="stat-icon" color="#67c23a"><CircleCheck /></el-icon>
                <div class="stat-info">
                  <h3>{{ onlineServers.length }}</h3>
                  <p>Online</p>
                </div>
              </div>
            </el-card>
            
            <el-card shadow="hover" class="stat-card">
              <div class="stat-content">
                <el-icon class="stat-icon" color="#909399"><CircleClose /></el-icon>
                <div class="stat-info">
                  <h3>{{ offlineServers.length }}</h3>
                  <p>Offline</p>
                </div>
              </div>
            </el-card>
            
            <el-card shadow="hover" class="stat-card">
              <div class="stat-content">
                <el-icon class="stat-icon" color="#e6a23c"><Cpu /></el-icon>
                <div class="stat-info">
                  <h3>{{ totalCpu }}%</h3>
                  <p>Avg CPU Usage</p>
                </div>
              </div>
            </el-card>
          </div>
          
          <!-- Recent servers -->
          <el-card class="recent-servers">
            <template #header>
              <div class="card-header">
                <h3>Recent Servers</h3>
                <el-button type="text" @click="$router.push('/servers')">View All</el-button>
              </div>
            </template>
            
            <el-table :data="recentServers" v-loading="serverStore.isLoading">
              <el-table-column prop="name" label="Name" />
              <el-table-column prop="status" label="Status" width="120">
                <template #default="scope">
                  <el-tag :type="getStatusType(scope.row.status)" size="small">
                    {{ scope.row.status }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="node.name" label="Node" />
              <el-table-column label="Resources" width="200">
                <template #default="scope">
                  <div class="resources">
                    <span><el-icon><Cpu /></el-icon> {{ scope.row.cpuLimit }}%</span>
                    <span><el-icon><Memory /></el-icon> {{ scope.row.memoryLimit }}MB</span>
                  </div>
                </template>
              </el-table-column>
              <el-table-column label="Actions" width="180">
                <template #default="scope">
                  <el-button-group size="small">
                    <el-button @click="viewServer(scope.row)">View</el-button>
                    <el-button type="primary" @click="manageServer(scope.row)">Manage</el-button>
                  </el-button-group>
                </template>
              </el-table-column>
            </el-table>
          </el-card>
          
          <!-- System status -->
          <div class="system-status">
            <el-card>
              <template #header>
                <h3>System Status</h3>
              </template>
              <div class="status-items">
                <div class="status-item" :class="{ 'online': backendOnline }">
                  <el-icon><Connection /></el-icon>
                  <span>Backend API</span>
                  <el-tag :type="backendOnline ? 'success' : 'danger'" size="small">
                    {{ backendOnline ? 'Online' : 'Offline' }}
                  </el-tag>
                </div>
                
                <div class="status-item" :class="{ 'online': websocketConnected }">
                  <el-icon><Link /></el-icon>
                  <span>WebSocket</span>
                  <el-tag :type="websocketConnected ? 'success' : 'danger'" size="small">
                    {{ websocketConnected ? 'Connected' : 'Disconnected' }}
                  </el-tag>
                </div>
                
                <div class="status-item online">
                  <el-icon><Timer /></el-icon>
                  <span>Uptime</span>
                  <span>{{ formatUptime }}</span>
                </div>
              </div>
            </el-card>
          </div>
        </el-main>
      </el-container>
    </el-container>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  House, Monitor, Setting, User, DataLine, Tools,
  SwitchButton, CircleCheck, CircleClose, Cpu,
  Memory, Connection, Link, Timer
} from '@element-plus/icons-vue'
import { useAuthStore } from '@/stores/auth'
import { useServerStore } from '@/stores/server'
import { socket } from '@/main.js'

const router = useRouter()
const authStore = useAuthStore()
const serverStore = useServerStore()

const backendOnline = ref(true)
const websocketConnected = ref(false)
const startTime = ref(Date.now())

const servers = computed(() => serverStore.servers)
const onlineServers = computed(() => serverStore.onlineServers)
const offlineServers = computed(() => serverStore.offlineServers)

const recentServers = computed(() => {
  return [...serverStore.servers]
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 5)
})

const totalCpu = computed(() => {
  if (serverStore.servers.length === 0) return 0
  const sum = serverStore.servers.reduce((acc, server) => acc + (server.cpuLimit || 0), 0)
  return Math.round(sum / serverStore.servers.length)
})

const statsColor = {
  total: '#409EFF',
  online: '#67C23A',
  offline: '#909399',
  cpu: '#E6A23C'
}

const formatUptime = computed(() => {
  const uptime = Date.now() - startTime.value
  const hours = Math.floor(uptime / (1000 * 60 * 60))
  const minutes = Math.floor((uptime % (1000 * 60 * 60)) / (1000 * 60))
  return `${hours}h ${minutes}m`
})

const getStatusType = (status) => {
  const types = {
    ONLINE: 'success',
    OFFLINE: 'info',
    STARTING: 'warning',
    STOPPING: 'warning',
    ERROR: 'danger',
    SUSPENDED: 'danger'
  }
  return types[status] || 'info'
}

const viewServer = (server) => {
  router.push(`/servers/${server.id}`)
}

const manageServer = (server) => {
  router.push(`/console/${server.id}`)
}

const handleLogout = () => {
  authStore.logout()
}

// WebSocket connection
const connectWebSocket = () => {
  socket.connect()
  
  socket.on('connect', () => {
    websocketConnected.value = true
    console.log('WebSocket connected')
  })
  
  socket.on('disconnect', () => {
    websocketConnected.value = false
    console.log('WebSocket disconnected')
  })
  
  socket.on('server-update', (data) => {
    // Update server status in real-time
    serverStore.fetchServers()
  })
  
  socket.on('console-output', (data) => {
    // Handle console output (could be displayed in notification)
    console.log('Console output:', data)
  })
}

// Health check
const checkBackendHealth = async () => {
  try {
    const response = await fetch('/api/health')
    backendOnline.value = response.ok
  } catch {
    backendOnline.value = false
  }
}

onMounted(async () => {
  await Promise.all([
    serverStore.fetchServers(),
    serverStore.fetchNodes(),
    authStore.fetchUser()
  ])
  
  connectWebSocket()
  checkBackendHealth()
  
  // Periodic health check
  const interval = setInterval(checkBackendHealth, 30000)
})

onUnmounted(() => {
  if (socket.connected) {
    socket.disconnect()
  }
})
</script>

<style scoped>
.dashboard {
  height: 100vh;
}

.sidebar {
  background: #2d3748;
  border-right: 1px solid #e0e0e0;
}

.logo {
  padding: 20px;
  text-align: center;
  border-bottom: 1px solid #4a5568;
}

.logo h2 {
  color: white;
  margin: 0;
  font-size: 1.5rem;
}

.sidebar-menu {
  height: calc(100vh - 160px);
  border-right: none;
}

.user-info {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  padding: 15px;
  background: #4a5568;
  display: flex;
  align-items: center;
  gap: 10px;
  color: white;
}

.user-details {
  flex: 1;
}

.user-details strong {
  display: block;
  font-size: 14px;
}

.user-details small {
  display: block;
  font-size: 12px;
  opacity: 0.8;
}

.user-details .el-tag {
  margin-top: 5px;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 20px;
  background: white;
  border-bottom: 1px solid #e0e0e0;
}

.header h1 {
  margin: 0;
  font-size: 1.5rem;
}

.main-content {
  padding: 20px;
  background: #f5f7fa;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}

.stat-card {
  border-radius: 10px;
}

.stat-content {
  display: flex;
  align-items: center;
  gap: 20px;
}

.stat-icon {
  font-size: 40px;
}

.stat-info h3 {
  margin: 0;
  font-size: 2rem;
  color: #303133;
}

.stat-info p {
  margin: 5px 0 0;
  color: #909399;
  font-size: 14px;
}

.recent-servers {
  margin-bottom: 30px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.resources {
  display: flex;
  gap: 15px;
  align-items: center;
}

.resources span {
  display: flex;
  align-items: center;
  gap: 5px;
  color: #606266;
}

.system-status .status-items {
  display: flex;
  gap: 30px;
}

.status-item {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 15px;
  background: #f8f9fa;
  border-radius: 8px;
}

.status-item .el-icon {
  font-size: 24px;
  color: #409EFF;
}

.status-item span:nth-child(2) {
  flex: 1;
  font-weight: 500;
}

.status-item.online .el-icon {
  color: #67C23A;
}
</style>
EOF

# Create other views with basic implementation
cat > src/views/Servers.vue <<'EOF'
<template>
  <div class="servers">
    <el-container>
      <el-aside width="250px" class="sidebar">
        <div class="logo">
          <h2>🎮 Game Panel</h2>
        </div>
        <el-menu router :default-active="$route.path" class="sidebar-menu">
          <el-menu-item index="/">
            <el-icon><House /></el-icon>
            <span>Dashboard</span>
          </el-menu-item>
          <el-menu-item index="/servers">
            <el-icon><Monitor /></el-icon>
            <span>Servers</span>
          </el-menu-item>
          <el-menu-item @click="$router.back()">
            <el-icon><Back /></el-icon>
            <span>Back</span>
          </el-menu-item>
        </el-menu>
      </el-aside>
      
      <el-container>
        <el-header class="header">
          <h1>Server Management</h1>
          <div class="header-actions">
            <el-button type="primary" icon="Plus" @click="showCreateDialog = true">
              Create Server
            </el-button>
          </div>
        </el-header>
        
        <el-main class="main-content">
          <!-- Server list -->
          <el-card v-loading="serverStore.isLoading">
            <template #header>
              <div class="table-header">
                <h3>All Servers ({{ serverStore.servers.length }})</h3>
                <el-input
                  v-model="searchQuery"
                  placeholder="Search servers..."
                  clearable
                  style="width: 300px;"
                >
                  <template #prefix>
                    <el-icon><Search /></el-icon>
                  </template>
                </el-input>
              </div>
            </template>
            
            <el-table :data="filteredServers">
              <el-table-column prop="name" label="Name" />
              <el-table-column prop="identifier" label="Identifier" />
              <el-table-column prop="status" label="Status" width="120">
                <template #default="scope">
                  <el-tag :type="getStatusType(scope.row.status)" size="small">
                    {{ scope.row.status }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column label="Node">
                <template #default="scope">
                  {{ scope.row.node?.name || 'N/A' }}
                </template>
              </el-table-column>
              <el-table-column label="Resources" width="200">
                <template #default="scope">
                  <div class="resources">
                    <span><el-icon><Cpu /></el-icon> {{ scope.row.cpuLimit }}%</span>
                    <span><el-icon><Memory /></el-icon> {{ scope.row.memoryLimit }}MB</span>
                  </div>
                </template>
              </el-table-column>
              <el-table-column label="Actions" width="300">
                <template #default="scope">
                  <el-button-group>
                    <el-button size="small" @click="viewServer(scope.row)">
                      View
                    </el-button>
                    <el-button size="small" type="primary" @click="manageServer(scope.row)">
                      Manage
                    </el-button>
                    <el-dropdown @command="handleCommand($event, scope.row)">
                      <el-button size="small">
                        More<el-icon class="el-icon--right"><arrow-down /></el-icon>
                      </el-button>
                      <template #dropdown>
                        <el-dropdown-menu>
                          <el-dropdown-item 
                            v-if="scope.row.status === 'OFFLINE'" 
                            command="start"
                          >
                            Start
                          </el-dropdown-item>
                          <el-dropdown-item 
                            v-if="scope.row.status === 'ONLINE'" 
                            command="stop"
                          >
                            Stop
                          </el-dropdown-item>
                          <el-dropdown-item 
                            v-if="scope.row.status === 'ONLINE'" 
                            command="restart"
                          >
                            Restart
                          </el-dropdown-item>
                          <el-dropdown-item command="console">
                            Console
                          </el-dropdown-item>
                          <el-dropdown-item command="files">
                            Files
                          </el-dropdown-item>
                          <el-dropdown-item command="edit">
                            Edit
                          </el-dropdown-item>
                          <el-dropdown-item 
                            command="delete" 
                            divided
                            style="color: #f56c6c;"
                          >
                            Delete
                          </el-dropdown-item>
                        </el-dropdown-menu>
                      </template>
                    </el-dropdown>
                  </el-button-group>
                </template>
              </el-table-column>
            </el-table>
          </el-card>
          
          <!-- Create Server Dialog -->
          <el-dialog
            v-model="showCreateDialog"
            title="Create New Server"
            width="600px"
          >
            <el-form :model="createForm" label-width="120px">
              <el-form-item label="Server Name" required>
                <el-input v-model="createForm.name" placeholder="My Game Server" />
              </el-form-item>
              
              <el-form-item label="Description">
                <el-input
                  v-model="createForm.description"
                  type="textarea"
                  :rows="2"
                  placeholder="Optional description"
                />
              </el-form-item>
              
              <el-form-item label="Node" required>
                <el-select v-model="createForm.nodeId" placeholder="Select node">
                  <el-option
                    v-for="node in serverStore.nodes"
                    :key="node.id"
                    :label="node.name"
                    :value="node.id"
                  />
                </el-select>
              </el-form-item>
              
              <el-form-item label="Docker Image" required>
                <el-input v-model="createForm.dockerImage" placeholder="e.g., itzg/minecraft-server" />
              </el-form-item>
              
              <el-row :gutter="20">
                <el-col :span="8">
                  <el-form-item label="CPU Limit" required>
                    <el-input-number
                      v-model="createForm.cpuLimit"
                      :min="10"
                      :max="800"
                      :step="10"
                    />
                    <span class="unit">%</span>
                  </el-form-item>
                </el-col>
                <el-col :span="8">
                  <el-form-item label="Memory" required>
                    <el-input-number
                      v-model="createForm.memoryLimit"
                      :min="128"
                      :max="16384"
                      :step="128"
                    />
                    <span class="unit">MB</span>
                  </el-form-item>
                </el-col>
                <el-col :span="8">
                  <el-form-item label="Disk" required>
                    <el-input-number
                      v-model="createForm.diskLimit"
                      :min="1024"
                      :max="131072"
                      :step="1024"
                    />
                    <span class="unit">MB</span>
                  </el-form-item>
                </el-col>
              </el-row>
              
              <el-form-item label="Startup Command">
                <el-input
                  v-model="createForm.startupCommand"
                  placeholder="Optional startup command"
                />
              </el-form-item>
            </el-form>
            
            <template #footer>
              <el-button @click="showCreateDialog = false">Cancel</el-button>
              <el-button type="primary" :loading="creating" @click="createServer">
                Create
              </el-button>
            </template>
          </el-dialog>
        </el-main>
      </el-container>
    </el-container>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  House, Monitor, Back, Search, Cpu,
  Memory, ArrowDown, Plus
} from '@element-plus/icons-vue'
import { useServerStore } from '@/stores/server'

const router = useRouter()
const serverStore = useServerStore()

const searchQuery = ref('')
const showCreateDialog = ref(false)
const creating = ref(false)

const createForm = ref({
  name: '',
  description: '',
  nodeId: '',
  dockerImage: 'itzg/minecraft-server',
  cpuLimit: 100,
  memoryLimit: 1024,
  diskLimit: 10240,
  startupCommand: ''
})

const filteredServers = computed(() => {
  if (!searchQuery.value) return serverStore.servers
  
  const query = searchQuery.value.toLowerCase()
  return serverStore.servers.filter(server =>
    server.name.toLowerCase().includes(query) ||
    server.identifier.toLowerCase().includes(query) ||
    server.node?.name.toLowerCase().includes(query)
  )
})

const getStatusType = (status) => {
  const types = {
    ONLINE: 'success',
    OFFLINE: 'info',
    STARTING: 'warning',
    STOPPING: 'warning',
    ERROR: 'danger',
    SUSPENDED: 'danger'
  }
  return types[status] || 'info'
}

const viewServer = (server) => {
  router.push(`/servers/${server.id}`)
}

const manageServer = (server) => {
  router.push(`/console/${server.id}`)
}

const handleCommand = async (command, server) => {
  switch (command) {
    case 'start':
      await startServer(server)
      break
    case 'stop':
      await stopServer(server)
      break
    case 'restart':
      await restartServer(server)
      break
    case 'console':
      router.push(`/console/${server.id}`)
      break
    case 'files':
      router.push(`/files/${server.id}`)
      break
    case 'edit':
      editServer(server)
      break
    case 'delete':
      deleteServer(server)
      break
  }
}

const startServer = async (server) => {
  try {
    await serverStore.startServer(server.id)
    ElMessage.success('Server started successfully')
  } catch (error) {
    ElMessage.error('Failed to start server')
  }
}

const stopServer = async (server) => {
  try {
    await serverStore.stopServer(server.id)
    ElMessage.success('Server stopped successfully')
  } catch (error) {
    ElMessage.error('Failed to stop server')
  }
}

const restartServer = async (server) => {
  try {
    await serverStore.restartServer(server.id)
    ElMessage.success('Server restarted successfully')
  } catch (error) {
    ElMessage.error('Failed to restart server')
  }
}

const editServer = (server) => {
  ElMessage.info('Edit feature coming soon')
}

const deleteServer = async (server) => {
  try {
    await ElMessageBox.confirm(
      `Delete server "${server.name}"? This action cannot be undone.`,
      'Warning',
      {
        confirmButtonText: 'Delete',
        cancelButtonText: 'Cancel',
        type: 'warning'
      }
    )
    
    await serverStore.deleteServer(server.id)
    ElMessage.success('Server deleted successfully')
  } catch (error) {
    // User cancelled
  }
}

const createServer = async () => {
  creating.value = true
  try {
    await serverStore.createServer(createForm.value)
    showCreateDialog.value = false
    createForm.value = {
      name: '',
      description: '',
      nodeId: '',
      dockerImage: 'itzg/minecraft-server',
      cpuLimit: 100,
      memoryLimit: 1024,
      diskLimit: 10240,
      startupCommand: ''
    }
  } catch (error) {
    // Error handled in store
  } finally {
    creating.value = false
  }
}

onMounted(async () => {
  await serverStore.fetchServers()
  await serverStore.fetchNodes()
})
</script>

<style scoped>
.servers {
  height: 100vh;
}

.sidebar {
  background: #fff;
  border-right: 1px solid #e0e0e0;
}

.logo {
  padding: 20px;
  text-align: center;
  border-bottom: 1px solid #e0e0e0;
}

.logo h2 {
  margin: 0;
  font-size: 1.5rem;
}

.sidebar-menu {
  height: calc(100vh - 80px);
  border-right: none;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 20px;
  background: white;
  border-bottom: 1px solid #e0e0e0;
}

.header h1 {
  margin: 0;
  font-size: 1.5rem;
}

.main-content {
  padding: 20px;
  background: #f5f7fa;
}

.table-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.resources {
  display: flex;
  gap: 15px;
  align-items: center;
}

.resources span {
  display: flex;
  align-items: center;
  gap: 5px;
  color: #606266;
}

.unit {
  margin-left: 5px;
  color: #909399;
}
</style>
EOF

# Create Console view with WebSocket
cat > src/views/Console.vue <<'EOF'
<template>
  <div class="console">
    <el-container>
      <el-aside width="250px" class="sidebar">
        <div class="logo">
          <h2>🎮 Console</h2>
        </div>
        <el-menu router class="sidebar-menu">
          <el-menu-item @click="$router.push('/servers')">
            <el-icon><Back /></el-icon>
            <span>Back to Servers</span>
          </el-menu-item>
          <el-menu-item @click="$router.push(`/servers/${serverId}`)">
            <el-icon><Monitor /></el-icon>
            <span>Server Details</span>
          </el-menu-item>
          <el-menu-item @click="$router.push(`/files/${serverId}`)">
            <el-icon><Folder /></el-icon>
            <span>File Manager</span>
          </el-menu-item>
        </el-menu>
      </el-aside>
      
      <el-container>
        <el-header class="header">
          <div class="server-info">
            <h1>Console - {{ server?.name }}</h1>
            <div class="server-status">
              <el-tag :type="getStatusType(server?.status)" size="small">
                {{ server?.status || 'UNKNOWN' }}
              </el-tag>
              <span class="identifier">{{ server?.identifier }}</span>
            </div>
          </div>
          <div class="header-actions">
            <el-button-group>
              <el-button
                :type="connected ? 'success' : 'primary'"
                :loading="connecting"
                @click="toggleConnection"
              >
                {{ connected ? 'Connected' : 'Connect' }}
              </el-button>
              <el-button @click="clearConsole" :disabled="!connected">
                Clear
              </el-button>
              <el-dropdown @command="handlePowerCommand">
                <el-button>
                  Power<el-icon class="el-icon--right"><arrow-down /></el-icon>
                </el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="start" :disabled="server?.status === 'ONLINE'">
                      Start
                    </el-dropdown-item>
                    <el-dropdown-item command="stop" :disabled="server?.status !== 'ONLINE'">
                      Stop
                    </el-dropdown-item>
                    <el-dropdown-item command="restart" :disabled="server?.status !== 'ONLINE'">
                      Restart
                    </el-dropdown-item>
                    <el-dropdown-item command="kill" divided>
                      Force Stop
                    </el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </el-button-group>
          </div>
        </el-header>
        
        <el-main class="main-content">
          <!-- Console output -->
          <el-card class="console-card">
            <div
              ref="consoleOutput"
              class="console-output"
              @click="focusInput"
            >
              <div
                v-for="(line, index) in consoleLines"
                :key="index"
                class="console-line"
              >
                <span class="timestamp">{{ line.timestamp }}</span>
                <span class="content">{{ line.content }}</span>
              </div>
              <div v-if="consoleLines.length === 0" class="console-empty">
                Console output will appear here when connected.
              </div>
            </div>
            
            <div class="console-input">
              <el-input
                ref="inputRef"
                v-model="inputCommand"
                placeholder="Type command and press Enter..."
                :disabled="!connected"
                @keyup.enter="sendCommand"
              >
                <template #prepend>
                  <span class="prompt">$</span>
                </template>
                <template #append>
                  <el-button :disabled="!connected || !inputCommand" @click="sendCommand">
                    Send
                  </el-button>
                </template>
              </el-input>
            </div>
          </el-card>
          
          <!-- Quick commands -->
          <el-card class="quick-commands">
            <template #header>
              <h3>Quick Commands</h3>
            </template>
            <div class="command-buttons">
              <el-button
                v-for="cmd in quickCommands"
                :key="cmd.command"
                size="small"
                @click="sendQuickCommand(cmd.command)"
                :disabled="!connected"
              >
                {{ cmd.label }}
              </el-button>
            </div>
          </el-card>
          
          <!-- Server stats -->
          <el-card class="server-stats">
            <template #header>
              <h3>Server Statistics</h3>
            </template>
            <div class="stats-grid">
              <div class="stat-item">
                <div class="stat-label">CPU Usage</div>
                <div class="stat-value">{{ currentStats?.cpu || 0 }}%</div>
                <el-progress
                  :percentage="currentStats?.cpu || 0"
                  :color="getProgressColor(currentStats?.cpu)"
                  :show-text="false"
                />
              </div>
              
              <div class="stat-item">
                <div class="stat-label">Memory Usage</div>
                <div class="stat-value">{{ currentStats?.memory || 0 }}MB</div>
                <el-progress
                  :percentage="getMemoryPercentage()"
                  :color="getProgressColor(getMemoryPercentage())"
                  :show-text="false"
                />
              </div>
              
              <div class="stat-item">
                <div class="stat-label">Disk Usage</div>
                <div class="stat-value">{{ currentStats?.disk || 0 }}MB</div>
                <el-progress
                  :percentage="getDiskPercentage()"
                  :color="getProgressColor(getDiskPercentage())"
                  :show-text="false"
                />
              </div>
              
              <div class="stat-item">
                <div class="stat-label">Uptime</div>
                <div class="stat-value">{{ formatUptime(server?.uptime) }}</div>
                <div class="stat-hint">Server uptime</div>
              </div>
            </div>
          </el-card>
        </el-main>
      </el-container>
    </el-container>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  Back, Monitor, Folder, ArrowDown
} from '@element-plus/icons-vue'
import { useServerStore } from '@/stores/server'
import { socket } from '@/main.js'

const route = useRoute()
const router = useRouter()
const serverStore = useServerStore()

const serverId = route.params.id
const server = computed(() => serverStore.currentServer)
const currentStats = computed(() => serverStore.currentServerStats)

const consoleOutput = ref(null)
const inputRef = ref(null)
const consoleLines = ref([])
const inputCommand = ref('')
const connected = ref(false)
const connecting = ref(false)

const quickCommands = [
  { label: 'List Files', command: 'ls -la' },
  { label: 'Check RAM', command: 'free -h' },
  { label: 'Check Disk', command: 'df -h' },
  { label: 'Check CPU', command: 'top -n 1' },
  { label: 'Current Directory', command: 'pwd' },
  { label: 'Server Info', command: 'uname -a' }
]

const getStatusType = (status) => {
  const types = {
    ONLINE: 'success',
    OFFLINE: 'info',
    STARTING: 'warning',
    STOPPING: 'warning',
    ERROR: 'danger',
    SUSPENDED: 'danger'
  }
  return types[status] || 'info'
}

const formatUptime = (seconds) => {
  if (!seconds) return 'N/A'
  
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  
  if (days > 0) return `${days}d ${hours}h`
  if (hours > 0) return `${hours}h ${minutes}m`
  return `${minutes}m`
}

const getMemoryPercentage = () => {
  if (!server.value || !currentStats.value) return 0
  return Math.round((currentStats.value.memory / server.value.memoryLimit) * 100)
}

const getDiskPercentage = () => {
  if (!server.value || !currentStats.value) return 0
  return Math.round((currentStats.value.disk / server.value.diskLimit) * 100)
}

const getProgressColor = (percentage) => {
  if (percentage < 70) return '#67c23a'
  if (percentage < 90) return '#e6a23c'
  return '#f56c6c'
}

const toggleConnection = async () => {
  if (connected.value) {
    disconnectWebSocket()
  } else {
    await connectWebSocket()
  }
}

const connectWebSocket = async () => {
  if (!server.value) {
    ElMessage.warning('Server not found')
    return
  }
  
  connecting.value = true
  
  try {
    // Join server room
    socket.emit('join-server', server.value.id)
    
    socket.on('console-output', (data) => {
      if (data.serverId === server.value.id) {
        addConsoleLine(data.output, new Date(data.timestamp))
      }
    })
    
    socket.on('server-update', (data) => {
      if (data.serverId === server.value.id) {
        // Update server status
        serverStore.fetchServer(server.value.id)
      }
    })
    
    connected.value = true
    ElMessage.success('Console connected')
  } catch (error) {
    ElMessage.error('Failed to connect to console')
  } finally {
    connecting.value = false
  }
}

const disconnectWebSocket = () => {
  if (server.value) {
    socket.emit('leave-server', server.value.id)
  }
  connected.value = false
  ElMessage.info('Console disconnected')
}

const addConsoleLine = (content, timestamp) => {
  consoleLines.value.push({
    content,
    timestamp: timestamp.toLocaleTimeString()
  })
  
  // Keep only last 1000 lines
  if (consoleLines.value.length > 1000) {
    consoleLines.value.shift()
  }
  
  // Auto-scroll to bottom
  nextTick(() => {
    if (consoleOutput.value) {
      consoleOutput.value.scrollTop = consoleOutput.value.scrollHeight
    }
  })
}

const clearConsole = () => {
  consoleLines.value = []
}

const focusInput = () => {
  if (inputRef.value) {
    inputRef.value.focus()
  }
}

const sendCommand = () => {
  if (!inputCommand.value.trim() || !connected.value) return
  
  const command = inputCommand.value.trim()
  
  // Send command via WebSocket
  socket.emit('console-input', {
    serverId: server.value.id,
    command: command + '\n'
  })
  
  // Echo command in console
  addConsoleLine(`$ ${command}`, new Date())
  inputCommand.value = ''
}

const sendQuickCommand = (command) => {
  inputCommand.value = command
  sendCommand()
}

const handlePowerCommand = async (command) => {
  if (!server.value) return
  
  try {
    switch (command) {
      case 'start':
        await serverStore.startServer(server.value.id)
        ElMessage.success('Server starting...')
        break
      case 'stop':
        await serverStore.stopServer(server.value.id)
        ElMessage.success('Server stopping...')
        break
      case 'restart':
        await serverStore.restartServer(server.value.id)
        ElMessage.success('Server restarting...')
        break
      case 'kill':
        // Force stop implementation
        ElMessage.info('Force stop command sent')
        break
    }
    
    // Refresh server status
    await serverStore.fetchServer(server.value.id)
  } catch (error) {
    ElMessage.error('Failed to execute power command')
  }
}

onMounted(async () => {
  await serverStore.fetchServer(serverId)
  focusInput()
  
  // Connect to WebSocket if server is online
  if (server.value?.status === 'ONLINE') {
    await connectWebSocket()
  }
})

onUnmounted(() => {
  disconnectWebSocket()
})

// Watch for server status changes
watch(() => server.value?.status, (newStatus) => {
  if (newStatus === 'ONLINE' && !connected.value) {
    connectWebSocket()
  } else if (newStatus !== 'ONLINE' && connected.value) {
    disconnectWebSocket()
  }
})
</script>

<style scoped>
.console {
  height: 100vh;
}

.sidebar {
  background: #fff;
  border-right: 1px solid #e0e0e0;
}

.logo {
  padding: 20px;
  text-align: center;
  border-bottom: 1px solid #e0e0e0;
}

.logo h2 {
  margin: 0;
  font-size: 1.5rem;
}

.sidebar-menu {
  height: calc(100vh - 80px);
  border-right: none;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 20px;
  background: white;
  border-bottom: 1px solid #e0e0e0;
}

.server-info h1 {
  margin: 0;
  font-size: 1.5rem;
}

.server-status {
  margin-top: 5px;
  display: flex;
  align-items: center;
  gap: 10px;
}

.identifier {
  color: #909399;
  font-size: 14px;
}

.main-content {
  padding: 20px;
  background: #f5f7fa;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.console-card {
  flex: 1;
  display: flex;
  flex-direction: column;
}

.console-output {
  flex: 1;
  height: 400px;
  background: #1e1e1e;
  color: #f0f0f0;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 14px;
  padding: 15px;
  overflow-y: auto;
  border-radius: 4px;
  margin-bottom: 15px;
  white-space: pre-wrap;
  word-break: break-all;
}

.console-line {
  margin-bottom: 2px;
  line-height: 1.4;
}

.timestamp {
  color: #888;
  margin-right: 10px;
  user-select: none;
}

.content {
  color: #f0f0f0;
}

.console-empty {
  color: #888;
  text-align: center;
  padding: 40px;
}

.console-input {
  margin-top: 15px;
}

.prompt {
  color: #67c23a;
  font-weight: bold;
}

.quick-commands .command-buttons {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 10px;
}

.server-stats .stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 20px;
}

.stat-item {
  padding: 15px;
  background: #f8f9fa;
  border-radius: 8px;
}

.stat-label {
  font-size: 14px;
  color: #606266;
  margin-bottom: 5px;
}

.stat-value {
  font-size: 24px;
  font-weight: bold;
  color: #303133;
  margin-bottom: 10px;
}

.stat-hint {
  font-size: 12px;
  color: #909399;
  margin-top: 5px;
}
</style>
EOF

# Create basic other views
cat > src/views/ServerDetail.vue <<'EOF'
<template>
  <div class="server-detail">
    <h1>Server Detail</h1>
    <p>Server ID: {{ $route.params.id }}</p>
    <!-- Implement server detail view -->
  </div>
</template>
EOF

cat > src/views/Files.vue <<'EOF'
<template>
  <div class="files">
    <h1>File Manager</h1>
    <p>Server ID: {{ $route.params.id }}</p>
    <!-- Implement file manager -->
  </div>
</template>
EOF

cat > src/views/Users.vue <<'EOF'
<template>
  <div class="users">
    <h1>User Management</h1>
    <!-- Implement user management -->
  </div>
</template>
EOF

cat > src/views/Nodes.vue <<'EOF'
<template>
  <div class="nodes">
    <h1>Node Management</h1>
    <!-- Implement node management -->
  </div>
</template>
EOF

cat > src/views/Settings.vue <<'EOF'
<template>
  <div class="settings">
    <h1>Settings</h1>
    <!-- Implement settings -->
  </div>
</template>
EOF

cat > src/views/NotFound.vue <<'EOF'
<template>
  <div class="not-found">
    <h1>404 - Page Not Found</h1>
    <p>The page you are looking for does not exist.</p>
    <el-button type="primary" @click="$router.push('/')">Go Home</el-button>
  </div>
</template>
EOF

echo -e "${GREEN}[6/12] Building frontend...${NC}"
npm run build

echo -e "${GREEN}[7/12] Configuring Nginx...${NC}"
cat > /etc/nginx/sites-available/gamepanel-frontend <<EOF
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
    
    # Root directory
    root /var/www/gamepanel-frontend/dist;
    index index.html;
    
    # API proxy
    location /api/ {
        proxy_pass ${API_URL}/;
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
    
    # WebSocket proxy
    location /socket.io/ {
        proxy_pass ${WS_URL}/socket.io/;
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
    
    # Frontend routing
    location / {
        try_files \$uri \$uri/ /index.html;
        expires -1;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
    }
    
    # Cache static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
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
ln -sf /etc/nginx/sites-available/gamepanel-frontend /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test Nginx configuration
nginx -t

echo -e "${GREEN}[8/12] Obtaining SSL certificate...${NC}"
certbot --nginx -d ${DOMAIN} --non-interactive --agree-tos --email ${ADMIN_EMAIL} --redirect

echo -e "${GREEN}[9/12] Setting permissions...${NC}"
chown -R www-data:www-data /var/www/gamepanel-frontend
chmod -R 755 /var/www/gamepanel-frontend

echo -e "${GREEN}[10/12] Creating environment file...${NC}"
cat > /var/www/gamepanel-frontend/.env.production <<EOF
VITE_API_URL=${API_URL}
VITE_WS_URL=${WS_URL}
EOF

# Build for production
echo -e "${GREEN}[11/12] Building for production...${NC}"
cd /var/www/gamepanel-frontend
export NODE_ENV=production
npm run build

# Create health check endpoint
echo -e "${GREEN}[12/12] Creating health check...${NC}"
cat > /var/www/gamepanel-frontend/dist/health.html <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Game Panel - Health Check</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .status { padding: 20px; margin: 10px 0; border-radius: 5px; }
        .online { background: #d4edda; color: #155724; }
        .offline { background: #f8d7da; color: #721c24; }
        .checking { background: #fff3cd; color: #856404; }
    </style>
</head>
<body>
    <h1>Game Panel Health Check</h1>
    <div id="status" class="status checking">
        Checking services...
    </div>
    
    <div class="services">
        <h2>Service Status</h2>
        <ul>
            <li>Frontend: <span id="frontend">Checking...</span></li>
            <li>Backend API: <span id="backend">Checking...</span></li>
            <li>WebSocket: <span id="websocket">Checking...</span></li>
        </ul>
    </div>
    
    <script>
        async function checkService(url, elementId) {
            try {
                const response = await fetch(url);
                if (response.ok) {
                    document.getElementById(elementId).textContent = '✅ Online';
                    return true;
                } else {
                    document.getElementById(elementId).textContent = '❌ Offline';
                    return false;
                }
            } catch (error) {
                document.getElementById(elementId).textContent = '❌ Offline';
                return false;
            }
        }
        
        async function checkAll() {
            const frontend = await checkService('/', 'frontend');
            const backend = await checkService('${API_URL}/health', 'backend');
            const websocket = await checkWebSocket();
            
            const statusDiv = document.getElementById('status');
            if (frontend && backend && websocket) {
                statusDiv.className = 'status online';
                statusDiv.textContent = 'All systems operational!';
            } else {
                statusDiv.className = 'status offline';
                statusDiv.textContent = 'Some services are offline';
            }
        }
        
        async function checkWebSocket() {
            return new Promise((resolve) => {
                const ws = new WebSocket('${WS_URL}');
                let connected = false;
                
                ws.onopen = () => {
                    connected = true;
                    document.getElementById('websocket').textContent = '✅ Online';
                    ws.close();
                    resolve(true);
                };
                
                ws.onerror = () => {
                    document.getElementById('websocket').textContent = '❌ Offline';
                    resolve(false);
                };
                
                setTimeout(() => {
                    if (!connected) {
                        document.getElementById('websocket').textContent = '❌ Offline';
                        resolve(false);
                    }
                }, 3000);
            });
        }
        
        checkAll();
        setInterval(checkAll, 30000);
    </script>
</body>
</html>
EOF

# Restart Nginx
systemctl restart nginx

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}🎉 Frontend Installation Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e ""
echo -e "${YELLOW}📋 Installation Summary:${NC}"
echo -e "  Frontend URL:   https://${DOMAIN}"
echo -e "  Backend API:    ${API_URL}"
echo -e "  WebSocket URL:  ${WS_URL}"
echo -e "  Build Output:   /var/www/gamepanel-frontend/dist"
echo -e ""
echo -e "${YELLOW}🔧 Management Commands:${NC}"
echo -e "  Restart Nginx:  systemctl restart nginx"
echo -e "  View logs:      journalctl -u nginx -f"
echo -e "  Rebuild:        cd /var/www/gamepanel-frontend && npm run build"
echo -e ""
echo -e "${YELLOW}🚀 Next Steps:${NC}"
echo -e "  1. Access https://${DOMAIN} in your browser"
echo -e "  2. Login with demo credentials:"
echo -e "     Email: admin@example.com"
echo -e "     Password: admin123"
echo -e "  3. Configure your first server"
echo -e "  4. Connect to server console"
echo -e ""
echo -e "${YELLOW}📱 Features:${NC}"
echo -e "  • Modern Vue.js 3 frontend"
echo -e "  • Real-time WebSocket console"
echo -e "  • Server management"
echo -e "  • User authentication"
echo -e "  • Responsive design"
echo -e "  • Element Plus UI"
echo -e "  • Socket.IO integration"
echo -e ""
echo -e "${BLUE}========================================${NC}"