const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // App info
  getVersion: () => ipcRenderer.invoke('get-app-version'),
  
  // Connection management
  sendConnectionStatus: (status) => ipcRenderer.send('connection-status', status),
  minimizeToTray: () => ipcRenderer.send('minimize-to-tray'),
  
  // Listen for main process events
  onQuickConnect: (callback) => ipcRenderer.on('quick-connect', callback),
  onDisconnect: (callback) => ipcRenderer.on('disconnect', callback),
  onShowServers: (callback) => ipcRenderer.on('show-servers', callback),
  onOpenSettings: (callback) => ipcRenderer.on('open-settings', callback),
  
  // Remove listeners
  removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel)
});