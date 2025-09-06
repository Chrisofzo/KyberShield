const { autoUpdater } = require('electron-updater');
const { dialog, app } = require('electron');

// Configure auto-updater
autoUpdater.autoDownload = false;
autoUpdater.autoInstallOnAppQuit = true;

// Set the feed URL for updates
const updateFeedUrl = 'https://kybershield.io/api/updates/';

function initAutoUpdater(mainWindow) {
    // Configure update server
    autoUpdater.setFeedURL({
        provider: 'generic',
        url: updateFeedUrl,
        channel: 'stable'
    });

    // Check for updates every 4 hours
    setInterval(() => {
        autoUpdater.checkForUpdates();
    }, 4 * 60 * 60 * 1000);

    // Check on startup
    setTimeout(() => {
        autoUpdater.checkForUpdates();
    }, 5000);

    // Auto-updater events
    autoUpdater.on('checking-for-update', () => {
        console.log('Checking for updates...');
    });

    autoUpdater.on('update-available', (info) => {
        dialog.showMessageBox(mainWindow, {
            type: 'info',
            title: 'Update Available',
            message: `A new version (${info.version}) of KyberShield VPN is available!`,
            detail: 'Would you like to download it now?',
            buttons: ['Download', 'Later'],
            defaultId: 0
        }).then((result) => {
            if (result.response === 0) {
                autoUpdater.downloadUpdate();
            }
        });
    });

    autoUpdater.on('update-not-available', () => {
        console.log('No updates available');
    });

    autoUpdater.on('error', (err) => {
        console.error('Update error:', err);
    });

    autoUpdater.on('download-progress', (progressObj) => {
        let logMessage = 'Download speed: ' + progressObj.bytesPerSecond;
        logMessage = logMessage + ' - Downloaded ' + progressObj.percent + '%';
        logMessage = logMessage + ' (' + progressObj.transferred + '/' + progressObj.total + ')';
        console.log(logMessage);
        
        // Send progress to renderer
        if (mainWindow) {
            mainWindow.webContents.send('download-progress', progressObj);
        }
    });

    autoUpdater.on('update-downloaded', (info) => {
        dialog.showMessageBox(mainWindow, {
            type: 'info',
            title: 'Update Ready',
            message: 'Update downloaded successfully!',
            detail: `Version ${info.version} has been downloaded and will be installed when you restart the app.`,
            buttons: ['Restart Now', 'Later'],
            defaultId: 0
        }).then((result) => {
            if (result.response === 0) {
                autoUpdater.quitAndInstall();
            }
        });
    });
}

function checkForUpdatesManually(mainWindow) {
    autoUpdater.checkForUpdates().then((updateCheckResult) => {
        if (!updateCheckResult || !updateCheckResult.updateInfo) {
            dialog.showMessageBox(mainWindow, {
                type: 'info',
                title: 'No Updates',
                message: 'You are running the latest version!',
                detail: `Version ${app.getVersion()} is up to date.`
            });
        }
    }).catch((err) => {
        dialog.showMessageBox(mainWindow, {
            type: 'error',
            title: 'Update Check Failed',
            message: 'Could not check for updates',
            detail: err.message
        });
    });
}

module.exports = {
    initAutoUpdater,
    checkForUpdatesManually
};