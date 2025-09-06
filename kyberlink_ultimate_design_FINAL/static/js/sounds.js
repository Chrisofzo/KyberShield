/* ===================================
   KyberShield VPN - Sound System (DISABLED)
   All audio functionality disabled for silent UI
   =================================== */

class KyberShieldAudio {
    constructor() {
        this.audioEnabled = false; // Permanently disabled
        this.volume = 0;
        this.audioContext = null;
        this.sounds = {};
    }
    
    // All methods return empty/silent
    async init() { }
    async initAudioContext() { }
    async createSounds() { }
    
    playSound(soundName) { }
    play(soundName) { }
    stop() { }
    pause() { }
    
    setVolume(volume) { }
    enable() { }
    disable() { }
    toggle() { }
    
    // Connection sounds (silent)
    playConnect() { }
    playDisconnect() { }
    playNotification() { }
    playClick() { }
    playSuccess() { }
    playError() { }
    playHover() { }
}

// Initialize silent audio system
window.kyberAudio = new KyberShieldAudio();

// Export for global use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = KyberShieldAudio;
}