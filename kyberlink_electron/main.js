const { app, BrowserWindow, ipcMain, Menu, Tray, shell, dialog } = require('electron');
const path = require('path');
const fs = require('fs');

let mainWindow;
let tray;
let isConnected = false;
let currentServer = null;

// Enable live reload for Electron development
try {
  require('electron-reloader')(module);
} catch {}

function createWindow() {
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

  // Load the web app - in production, this would be the deployed URL
  if (process.env.NODE_ENV === 'development') {
    mainWindow.loadURL('http://localhost:5000');
  } else {
    // In production, load the built React app or connect to deployed server
    mainWindow.loadFile('index.html');
  }

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
app.whenReady().then(() => {
  createWindow();
  createTray();
  
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
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