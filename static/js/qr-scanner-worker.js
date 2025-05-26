// Import QR scanner library
importScripts('https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js');

self.onmessage = function(e) {
    const imageData = e.data;
    try {
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: "dontInvert",
        });
        
        if (code) {
            self.postMessage([code.data]);
        } else {
            self.postMessage([]);
        }
    } catch (error) {
        self.postMessage([]);
    }
};