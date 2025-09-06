const { app, BrowserWindow, ipcMain, Menu, Tray, shell, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const { startBackend, stopBackend } = require('./backend-launcher');

let mainWindow;
let tray;
let isConnected = false;
let currentServer = null;
let backendReady = false;

// Enable live reload for Electron development
try {
  require('electron-reloader')(module);
} catch {}

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    icon: path.join(__dirname, 'assets/icons/icon.png'),
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    frame: process.platform !== 'darwin',
    backgroundColor: '#1e293b'
  });

  // Show loading screen while starting backend
  const loadingHTML = `
    <!DOCTYPE html>
    <html style="height: 100%; margin: 0;">
    <head>
      <style>
        body {
          height: 100%;
          margin: 0;
          display: flex;
          justify-content: center;
          align-items: center;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          color: white;
        }
        .loader { text-align: center; }
        .spinner {
          width: 50px;
          height: 50px;
          border: 4px solid rgba(255, 255, 255, 0.3);
          border-top-color: white;
          border-radius: 50%;
          animation: spin 1s linear infinite;
          margin: 0 auto 20px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        h1 { font-size: 24px; margin: 10px 0; }
        p { font-size: 14px; opacity: 0.8; }
      </style>
    </head>
    <body>
      <div class="loader">
        <div class="spinner"></div>
        <h1>KyberShield VPN</h1>
        <p>Starting secure backend services...</p>
      </div>
    </body>
    </html>
  `;
  
  mainWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(loadingHTML)}`);

  // Start backend if not already running
  if (!backendReady) {
    try {
      await startBackend();
      backendReady = true;
      console.log('Backend started successfully');
    } catch (error) {
      console.error('Failed to start backend:', error);
      dialog.showErrorBox('Backend Error', 
        'Failed to start VPN backend service.\n\n' +
        'Please ensure Python 3 is installed and try again.\n\n' +
        'Error: ' + error.message
      );
    }
  }

  // Wait a moment then load the actual app
  setTimeout(() => {
    // Try loading from backend first
    fetch('http://localhost:5000/api/health')
      .then(response => {
        if (response.ok) {
          console.log('Backend is running, loading from server');
          mainWindow.loadURL('http://localhost:5000');
        } else {
          throw new Error('Backend not responding');
        }
      })
      .catch(error => {
        console.log('Backend not available, loading static UI');
        // Load the embedded UI directly
        const uiPath = path.join(__dirname, '..', 'kyberlink_ultimate_design_FINAL', 'build', 'index.html');
        if (fs.existsSync(uiPath)) {
          mainWindow.loadFile(uiPath);
        } else {
          // Load embedded simple UI
          mainWindow.loadURL('http://localhost:5000');
        }
      });
  }, 2000);

  // Create application menu
  createMenu();

  // Handle window closed
  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Open external links in browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });
}

function createMenu() {
  const template = [
    {
      label: 'KyberShield',
      submenu: [
        {
          label: 'About KyberShield',
          click: () => {
            dialog.showMessageBox(mainWindow, {
              type: 'info',
              title: 'About KyberShield VPN',
              message: 'KyberShield VPN v1.0.0',
              detail: 'Quantum-resistant VPN with ML-KEM-768 (Kyber) encryption.\n\n© 2025 KyberShield Technologies',
              buttons: ['OK']
            });
          }
        },
        { type: 'separator' },
        {
          label: 'Preferences',
          accelerator: 'CmdOrCtrl+,',
          click: () => {
            mainWindow.webContents.send('open-settings');
          }
        },
        { type: 'separator' },
        {
          label: 'Quit',
          accelerator: process.platform === 'darwin' ? 'Cmd+Q' : 'Ctrl+Q',
          click: () => {
            app.quit();
          }
        }
      ]
    },
    {
      label: 'Connection',
      submenu: [
        {
          label: 'Quick Connect',
          accelerator: 'CmdOrCtrl+K',
          click: () => {
            mainWindow.webContents.send('quick-connect');
          }
        },
        {
          label: 'Disconnect',
          accelerator: 'CmdOrCtrl+D',
          enabled: false,
          id: 'disconnect-menu',
          click: () => {
            mainWindow.webContents.send('disconnect');
          }
        },
        { type: 'separator' },
        {
          label: 'Server List',
          click: () => {
            mainWindow.webContents.send('show-servers');
          }
        }
      ]
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'forceReload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' }
      ]
    },
    {
      label: 'Help',
      submenu: [
        {
          label: 'Documentation',
          click: () => {
            shell.openExternal('https://kybershield.com/docs');
          }
        },
        {
          label: 'Support',
          click: () => {
            shell.openExternal('https://kybershield.com/support');
          }
        },
        { type: 'separator' },
        {
          label: 'Check for Updates',
          click: () => {
            checkForUpdates();
          }
        }
      ]
    }
  ];

  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
}

function createTray() {
  const trayIcon = path.join(__dirname, 'assets/icons/tray.png');
  tray = new Tray(trayIcon);
  
  updateTrayMenu();
  
  tray.setToolTip('KyberShield VPN - Disconnected');
  
  tray.on('click', () => {
    if (mainWindow) {
      mainWindow.show();
    } else {
      createWindow();
    }
  });
}

function updateTrayMenu() {
  const contextMenu = Menu.buildFromTemplate([
    {
      label: isConnected ? `Connected to ${currentServer}` : 'Disconnected',
      enabled: false
    },
    { type: 'separator' },
    {
      label: isConnected ? 'Disconnect' : 'Quick Connect',
      click: () => {
        if (mainWindow) {
          mainWindow.webContents.send(isConnected ? 'disconnect' : 'quick-connect');
        }
      }
    },
    { type: 'separator' },
    {
      label: 'Show App',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
        } else {
          createWindow();
        }
      }
    },
    {
      label: 'Quit',
      click: () => {
        app.quit();
      }
    }
  ]);
  
  tray.setContextMenu(contextMenu);
}

function checkForUpdates() {
  dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: 'Check for Updates',
    message: 'KyberShield is up to date',
    detail: 'You have the latest version (1.0.0) installed.',
    buttons: ['OK']
  });
}

// IPC Handlers
ipcMain.handle('get-app-version', () => {
  return app.getVersion();
});

ipcMain.on('connection-status', (event, status) => {
  isConnected = status.connected;
  currentServer = status.server;
  
  // Update tray
  if (tray) {
    tray.setToolTip(`KyberShield VPN - ${isConnected ? `Connected to ${currentServer}` : 'Disconnected'}`);
    updateTrayMenu();
  }
  
  // Update menu
  const menu = Menu.getApplicationMenu();
  const disconnectItem = menu.getMenuItemById('disconnect-menu');
  if (disconnectItem) {
    disconnectItem.enabled = isConnected;
  }
});

ipcMain.on('minimize-to-tray', () => {
  mainWindow.hide();
});

// App event handlers
app.whenReady().then(async () => {
  await createWindow();
  createTray();
  
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  stopBackend();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  stopBackend();
});

// Prevent multiple instances
const gotTheLock = app.requestSingleInstanceLock();

if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });
}

// Handle certificate errors
app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  // In development, ignore certificate errors
  if (process.env.NODE_ENV === 'development') {
    event.preventDefault();
    callback(true);
  } else {
    callback(false);
  }
});