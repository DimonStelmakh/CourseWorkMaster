class BiometricCollector {
    constructor() {
        this.keystrokeData = [];
        this.mouseData = [];
        this.touchData = [];
        this.sensorData = [];
        
        this.lastKeyDown = {};
        this.lastKeyUp = null;
        this.lastInputTime = null; // For mobile virtual keyboard
        this.lastMousePos = null;
        this.lastMouseTime = null;
        
        this.isCollecting = false;
        this.collectionInterval = null;
        this.sendInterval = 5000; // Send data every 5 seconds
        
        this.onDataReady = null;
        
        // Session counters
        this.sessionKeystrokeCount = 0;
        this.sessionMouseMoveCount = 0;
        this.onCountUpdate = null;  // Callback for UI update
        
        // Device detection
        this.deviceCategory = this.detectDeviceCategory();
        console.log('Device category detected:', this.deviceCategory);
    }
    
    /**
     * Detect if device is mobile or desktop.
     * Uses multiple heuristics for reliable detection.
     */
    detectDeviceCategory() {
        // Check for touch capability
        const hasTouch = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
        
        // Check user agent for mobile keywords
        const mobileUA = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
        
        // Check screen size (mobile typically < 768px width)
        const smallScreen = window.innerWidth < 768;
        
        // Check for mouse/pointer capabilities
        const hasFinePointer = window.matchMedia('(pointer: fine)').matches;
        const hasCoarsePointer = window.matchMedia('(pointer: coarse)').matches;
        
        // Decision logic:
        // - If has coarse pointer (finger) and mobile UA -> mobile
        // - If has fine pointer (mouse) and no mobile UA -> desktop
        // - Fallback to screen size
        if (hasCoarsePointer && mobileUA) {
            return 'mobile';
        }
        if (hasFinePointer && !mobileUA) {
            return 'desktop';
        }
        
        // Fallback
        return smallScreen ? 'mobile' : 'desktop';
    }
    
    start() {
        if (this.isCollecting) return;
        
        this.isCollecting = true;
        this.sessionKeystrokeCount = 0;
        this.sessionMouseMoveCount = 0;
        this.bindEvents();
        this.startSensorCollection();
        
        // Periodic data sending
        this.collectionInterval = setInterval(() => {
            this.sendCollectedData();
        }, this.sendInterval);
        
        console.log('Biometric collection started');
    }
    
    stop() {
        this.isCollecting = false;
        this.unbindEvents();
        this.stopSensorCollection();
        
        if (this.collectionInterval) {
            clearInterval(this.collectionInterval);
            this.collectionInterval = null;
        }
        
        console.log('Biometric collection stopped');
    }
    
    bindEvents() {
        // Keystroke events (for desktop physical keyboards)
        document.addEventListener('keydown', this.handleKeyDown.bind(this));
        document.addEventListener('keyup', this.handleKeyUp.bind(this));
        
        // Input events (for mobile virtual keyboards - iOS Safari fix)
        if (this.deviceCategory === 'mobile') {
            document.addEventListener('input', this.handleInput.bind(this), true);
        }
        
        // Mouse events
        document.addEventListener('mousemove', this.handleMouseMove.bind(this));
        document.addEventListener('click', this.handleMouseClick.bind(this));
        document.addEventListener('wheel', this.handleMouseScroll.bind(this));
        
        // Touch events
        document.addEventListener('touchstart', this.handleTouchStart.bind(this));
        document.addEventListener('touchmove', this.handleTouchMove.bind(this));
        document.addEventListener('touchend', this.handleTouchEnd.bind(this));
    }
    
    unbindEvents() {
        document.removeEventListener('keydown', this.handleKeyDown);
        document.removeEventListener('keyup', this.handleKeyUp);
        document.removeEventListener('input', this.handleInput, true);
        document.removeEventListener('mousemove', this.handleMouseMove);
        document.removeEventListener('click', this.handleMouseClick);
        document.removeEventListener('wheel', this.handleMouseScroll);
        document.removeEventListener('touchstart', this.handleTouchStart);
        document.removeEventListener('touchmove', this.handleTouchMove);
        document.removeEventListener('touchend', this.handleTouchEnd);
    }
    
    // Keystroke handlers
    handleKeyDown(e) {
        if (!this.isCollecting) return;
        
        const now = performance.now();
        const key = e.key;
        
        // Store key down time
        if (!this.lastKeyDown[key]) {
            this.lastKeyDown[key] = now;
        }
    }
    
    handleKeyUp(e) {
        if (!this.isCollecting) return;
        
        const now = performance.now();
        const key = e.key;
        
        if (this.lastKeyDown[key]) {
            const holdTime = now - this.lastKeyDown[key];
            const flightTime = this.lastKeyUp ? now - this.lastKeyUp : null;
            
            this.keystrokeData.push({
                key: key.length === 1 ? 'char' : key, // Anonymize single chars
                key_down_time: this.lastKeyDown[key],
                key_up_time: now,
                hold_time: holdTime,
                flight_time: flightTime
            });
            
            delete this.lastKeyDown[key];
            this.lastKeyUp = now;
            
            // Update counter
            this.sessionKeystrokeCount++;
            if (this.onCountUpdate) {
                this.onCountUpdate({
                    keystroke: this.sessionKeystrokeCount,
                    mouse: this.sessionMouseMoveCount
                });
            }
        }
    }
    
    /**
     * Handle input events for mobile virtual keyboards.
     * iOS Safari doesn't fire keydown/keyup for virtual keyboard,
     * so we use input events to simulate keystroke timing.
     */
    handleInput(e) {
        if (!this.isCollecting) return;
        if (this.deviceCategory !== 'mobile') return; // Only for mobile
        
        const now = performance.now();
        
        // Calculate timing based on input events
        // For mobile, we estimate hold_time based on typical tap duration (~100ms)
        const estimatedHoldTime = 80 + Math.random() * 40; // 80-120ms realistic range
        const flightTime = this.lastInputTime ? now - this.lastInputTime : null;
        
        // Only record if this is actual text input (not programmatic)
        if (e.inputType === 'insertText' || e.inputType === 'deleteContentBackward') {
            this.keystrokeData.push({
                key: 'char', // Anonymized
                key_down_time: now - estimatedHoldTime,
                key_up_time: now,
                hold_time: estimatedHoldTime,
                flight_time: flightTime
            });
            
            this.lastInputTime = now;
            
            // Update counter
            this.sessionKeystrokeCount++;
            if (this.onCountUpdate) {
                this.onCountUpdate({
                    keystroke: this.sessionKeystrokeCount,
                    mouse: this.sessionMouseMoveCount
                });
            }
        }
    }
    
    // Mouse handlers
    handleMouseMove(e) {
        if (!this.isCollecting) return;
        
        const now = performance.now();
        const x = e.clientX;
        const y = e.clientY;
        
        let velocity = null;
        let acceleration = null;
        
        if (this.lastMousePos && this.lastMouseTime) {
            const dx = x - this.lastMousePos.x;
            const dy = y - this.lastMousePos.y;
            const dt = now - this.lastMouseTime;
            
            if (dt > 0) {
                const distance = Math.sqrt(dx * dx + dy * dy);
                velocity = distance / dt;
                
                if (this.lastVelocity !== undefined) {
                    acceleration = (velocity - this.lastVelocity) / dt;
                }
                this.lastVelocity = velocity;
            }
        }
        
        // Sample every 50ms to reduce data volume
        if (!this.lastMouseTime || now - this.lastMouseTime > 50) {
            this.mouseData.push({
                x, y,
                timestamp: now,
                event_type: 'move',
                velocity,
                acceleration
            });
            
            this.lastMousePos = { x, y };
            this.lastMouseTime = now;
        }
    }
    
    handleMouseClick(e) {
        if (!this.isCollecting) return;
        
        this.mouseData.push({
            x: e.clientX,
            y: e.clientY,
            timestamp: performance.now(),
            event_type: 'click',
            button: e.button === 0 ? 'left' : e.button === 2 ? 'right' : 'middle'
        });
    }
    
    handleMouseScroll(e) {
        if (!this.isCollecting) return;
        
        this.mouseData.push({
            x: e.clientX,
            y: e.clientY,
            timestamp: performance.now(),
            event_type: 'scroll',
            deltaY: e.deltaY
        });
    }
    
    // Touch handlers
    handleTouchStart(e) {
        if (!this.isCollecting) return;
        
        for (const touch of e.touches) {
            this.touchData.push({
                x: touch.clientX,
                y: touch.clientY,
                timestamp: performance.now(),
                event_type: 'start',
                pressure: touch.force || null,
                touch_area: touch.radiusX && touch.radiusY ? 
                    Math.PI * touch.radiusX * touch.radiusY : null
            });
        }
    }
    
    handleTouchMove(e) {
        if (!this.isCollecting) return;
        
        for (const touch of e.touches) {
            this.touchData.push({
                x: touch.clientX,
                y: touch.clientY,
                timestamp: performance.now(),
                event_type: 'move',
                pressure: touch.force || null,
                touch_area: touch.radiusX && touch.radiusY ? 
                    Math.PI * touch.radiusX * touch.radiusY : null
            });
        }
    }
    
    handleTouchEnd(e) {
        if (!this.isCollecting) return;
        
        for (const touch of e.changedTouches) {
            this.touchData.push({
                x: touch.clientX,
                y: touch.clientY,
                timestamp: performance.now(),
                event_type: 'end'
            });
        }
    }
    
    // Sensor collection (accelerometer, gyroscope)
    startSensorCollection() {
        if ('DeviceMotionEvent' in window) {
            // Request permission on iOS 13+
            if (typeof DeviceMotionEvent.requestPermission === 'function') {
                DeviceMotionEvent.requestPermission()
                    .then(response => {
                        if (response === 'granted') {
                            window.addEventListener('devicemotion', this.handleDeviceMotion.bind(this));
                        }
                    })
                    .catch(console.error);
            } else {
                window.addEventListener('devicemotion', this.handleDeviceMotion.bind(this));
            }
        }
        
        if ('DeviceOrientationEvent' in window) {
            if (typeof DeviceOrientationEvent.requestPermission === 'function') {
                DeviceOrientationEvent.requestPermission()
                    .then(response => {
                        if (response === 'granted') {
                            window.addEventListener('deviceorientation', this.handleDeviceOrientation.bind(this));
                        }
                    })
                    .catch(console.error);
            } else {
                window.addEventListener('deviceorientation', this.handleDeviceOrientation.bind(this));
            }
        }
    }
    
    stopSensorCollection() {
        window.removeEventListener('devicemotion', this.handleDeviceMotion);
        window.removeEventListener('deviceorientation', this.handleDeviceOrientation);
    }
    
    handleDeviceMotion(e) {
        if (!this.isCollecting) return;
        
        const accel = e.accelerationIncludingGravity;
        const gyro = e.rotationRate;
        
        // Only collect if we have actual values (not null)
        const hasValidAccel = accel && (accel.x !== null || accel.y !== null || accel.z !== null);
        const hasValidGyro = gyro && (gyro.alpha !== null || gyro.beta !== null || gyro.gamma !== null);
        
        if (hasValidAccel || hasValidGyro) {
            this.sensorData.push({
                accelerometer: hasValidAccel ? { x: accel.x, y: accel.y, z: accel.z } : null,
                gyroscope: hasValidGyro ? { x: gyro.alpha, y: gyro.beta, z: gyro.gamma } : null,
                timestamp: performance.now()
            });
        }
    }
    
    handleDeviceOrientation(e) {
        // Can be used for additional sensor fusion
    }
    
    // Get collected data
    getKeystrokeData() {
        const data = [...this.keystrokeData];
        this.keystrokeData = [];
        return data;
    }
    
    getMouseData() {
        const data = [...this.mouseData];
        this.mouseData = [];
        return data;
    }
    
    getTouchData() {
        const data = [...this.touchData];
        this.touchData = [];
        return data;
    }
    
    getSensorData() {
        const data = [...this.sensorData];
        this.sensorData = [];
        return data;
    }
    
    // Get login keystroke data (for password field)
    getLoginKeystrokeData() {
        return this.getKeystrokeData();
    }
    
    // Send collected data to server
    async sendCollectedData() {
        if (!this.onDataReady) return;
        
        const batches = [];
        const device = this.deviceCategory;
        
        const keystroke = this.getKeystrokeData();
        if (keystroke.length > 0) {
            batches.push({ data_type: 'KEYSTROKE', data: keystroke, device_category: device });
        }
        
        const mouse = this.getMouseData();
        if (mouse.length > 0) {
            batches.push({ data_type: 'MOUSE', data: mouse, device_category: device });
        }
        
        const touch = this.getTouchData();
        if (touch.length > 0) {
            batches.push({ data_type: 'TOUCH', data: touch, device_category: device });
        }
        
        const sensor = this.getSensorData();
        if (sensor.length > 0) {
            batches.push({ data_type: 'SENSOR_FUSION', data: sensor, device_category: device });
        }
        
        for (const batch of batches) {
            try {
                await this.onDataReady(batch);
            } catch (error) {
                console.error('Failed to send biometric data:', error);
            }
        }
    }
    
    /**
     * Get device category for login biometric data
     */
    getDeviceCategory() {
        return this.deviceCategory;
    }
}

// Global instance
window.biometricCollector = new BiometricCollector();
