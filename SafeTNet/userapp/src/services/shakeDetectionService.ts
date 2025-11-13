import {AppState, AppStateStatus, Platform, DevSettings, Alert, InteractionManager, NativeModules} from 'react-native';
import {DevMenuModule} from '../modules/DevMenuModule';

// Safely import react-native-push-notification
let PushNotification: any = null;
try {
  const pushNotifModule = require('react-native-push-notification');
  PushNotification = pushNotifModule.default || pushNotifModule;
  // Check if it's actually available
  if (PushNotification && typeof PushNotification.configure === 'function') {
    // Module is available
  } else {
    PushNotification = null;
  }
} catch (error) {
  console.warn('react-native-push-notification not available:', error);
  PushNotification = null;
}

// Safely import react-native-sensors
let accelerometer: any = null;
let setUpdateIntervalForType: any = null;
let SensorTypes: any = null;

// Track initialization attempts to avoid infinite retries
let initializationAttempts = 0;
const MAX_INIT_ATTEMPTS = 5;

// Function to check and initialize accelerometer
function initializeAccelerometer(): any {
  // If already successfully initialized, return it
  if (accelerometer && accelerometer !== false && typeof accelerometer.subscribe === 'function') {
    return accelerometer;
  }

  // If we've already determined it's not available after multiple attempts, don't retry
  if (accelerometer === false && initializationAttempts >= MAX_INIT_ATTEMPTS) {
    return false;
  }

  // Reset attempts if we're retrying after some time
  if (accelerometer === false && initializationAttempts < MAX_INIT_ATTEMPTS) {
    initializationAttempts++;
  }

  try {
    // Try to require the module
    const sensors = require('react-native-sensors');
    
    // Check if module loaded successfully
    if (!sensors) {
      console.warn('react-native-sensors module is null');
      if (initializationAttempts >= MAX_INIT_ATTEMPTS) {
        accelerometer = false;
      }
      return false;
    }

    // Check for accelerometer export
    if (sensors.accelerometer) {
      const accel = sensors.accelerometer;
      
      // Verify it has the subscribe method
      if (typeof accel.subscribe === 'function') {
        accelerometer = accel;
        setUpdateIntervalForType = sensors.setUpdateIntervalForType;
        SensorTypes = sensors.SensorTypes;
        initializationAttempts = 0; // Reset on success

        // Configure sensor update interval safely
        if (setUpdateIntervalForType && SensorTypes && SensorTypes.accelerometer) {
          try {
            setUpdateIntervalForType(SensorTypes.accelerometer, 100); // 100ms = 10Hz
          } catch (e) {
            console.warn('Could not set accelerometer update interval:', e);
          }
        }
        
        console.log('Accelerometer initialized successfully');
        return accelerometer;
      } else {
        console.warn('Accelerometer does not have subscribe method');
        if (initializationAttempts >= MAX_INIT_ATTEMPTS) {
          accelerometer = false;
        }
        return false;
      }
    } else {
      console.warn('Accelerometer not found in sensors module');
      if (sensors && typeof sensors === 'object') {
        console.warn('Available exports:', Object.keys(sensors));
      }
      if (initializationAttempts >= MAX_INIT_ATTEMPTS) {
        accelerometer = false;
      }
      return false;
    }
  } catch (error: any) {
    // Check if it's the specific "native modules not available" error
    const errorMessage = error?.message || String(error);
    if (errorMessage.includes('Native modules for sensors not available')) {
      console.warn('react-native-sensors native module not linked. Please rebuild the app.');
      if (initializationAttempts >= MAX_INIT_ATTEMPTS) {
        accelerometer = false;
      }
      return false;
    }
    
    console.warn('Error initializing accelerometer:', errorMessage);
    // Don't mark as false immediately on other errors, might be temporary
    if (initializationAttempts >= MAX_INIT_ATTEMPTS) {
      accelerometer = false;
    }
    return null;
  }
}

// Don't initialize immediately - let it be lazy loaded when needed

interface ShakeDetectionConfig {
  threshold: number; // Acceleration threshold for shake detection
  shakeCount: number; // Number of shakes required
  timeWindow: number; // Time window in ms to detect shakes
}

const defaultConfig: ShakeDetectionConfig = {
  threshold: 25.0, // Extremely high threshold to require very strong shakes (25.0 m/s² ≈ 2.5g)
  shakeCount: 3,
  timeWindow: 2000, // 2 seconds - time window for detecting 3 shakes
};

class ShakeDetectionService {
  private subscription: any = null;
  private shakeTimestamps: number[] = [];
  private isActive: boolean = false;
  private config: ShakeDetectionConfig = defaultConfig;
  private onShakeDetected: (() => void) | null = null;
  private lastAcceleration: {x: number; y: number; z: number} | null = null;
  private appStateListener: any = null;
  private pendingConfirmation: boolean = false; // Track if confirmation is pending
  private lastShakeTime: number = 0; // Track last shake time to prevent rapid triggers
  private minShakeInterval: number = 600; // Minimum 600ms between shake detections (very strict)

  private isConfigured: boolean = false;

  constructor() {
    // Configure push notifications lazily
    this.configureNotifications();
  }

  private configureNotifications() {
    if (this.isConfigured) {
      return;
    }

    if (!PushNotification) {
      console.warn('PushNotification is not available - notifications will be disabled');
      this.isConfigured = true; // Mark as configured to avoid repeated checks
      return;
    }

    try {
      // Configure push notifications only if available
      if (PushNotification && typeof PushNotification.configure === 'function') {
        const shouldRequestPermissions = Platform.OS === 'ios';

        const config: any = {
          onRegister: function (token: any) {
            console.log('Push notification token:', token);
          },
          onNotification: function (notification: any) {
            console.log('Notification received:', notification);
          },
          permissions: {
            alert: true,
            badge: true,
            sound: true,
          },
          popInitialNotification: false, // Changed to false to avoid getInitialNotification error
          requestPermissions: shouldRequestPermissions, // Only request permissions automatically where supported
        };

        if (!shouldRequestPermissions) {
          console.log('Skipping automatic push notification permission request (unsupported on this platform or Firebase not configured).');
        }

        // Only add getInitialNotification if it exists
        if (PushNotification.getInitialNotification) {
          try {
            const initialNotification = PushNotification.getInitialNotification();
            if (initialNotification) {
              console.log('Initial notification:', initialNotification);
            }
          } catch (e) {
            console.warn('Could not get initial notification:', e);
          }
        }

        PushNotification.configure(config);
      }

          // Create notification channel for Android
          if (Platform.OS === 'android' && PushNotification && typeof PushNotification.createChannel === 'function') {
            try {
              PushNotification.createChannel(
                {
                  channelId: 'sos-channel',
                  channelName: 'SOS Notifications',
                  channelDescription: 'Notifications for SOS alerts',
                  playSound: true,
                  soundName: 'default',
                  importance: 4, // High importance (IMPORTANCE_HIGH)
                  vibrate: true,
                },
                (created: boolean) => {
                  console.log('SOS notification channel created:', created);
                  if (!created) {
                    console.warn('SOS notification channel may already exist');
                  }
                },
              );
            } catch (e) {
              console.error('Could not create notification channel:', e);
            }
          }

      this.isConfigured = true;
    } catch (error) {
      console.error('Error configuring push notifications:', error);
      this.isConfigured = true; // Mark as configured to avoid repeated failures
    }
  }

  start(onShakeDetected: () => void) {
    if (this.isActive) {
      return;
    }

    this.onShakeDetected = onShakeDetected;
    this.isActive = true;
    this.shakeTimestamps = [];

    try {
      // Disable React Native dev menu shake gesture to prevent conflicts
      // Method 1: Try using DevSettings (if available)
      if (__DEV__ && DevSettings && typeof DevSettings.setIsShakeToShowDevMenuEnabled === 'function') {
        try {
          DevSettings.setIsShakeToShowDevMenuEnabled(false);
          console.log('Dev menu shake gesture disabled via DevSettings');
        } catch (e) {
          console.warn('Could not disable dev menu shake gesture via DevSettings:', e);
        }
      }

      // Method 2: Use native module to prevent dev menu from opening
      if (Platform.OS === 'android') {
        try {
          DevMenuModule.setShakeDetectionActive(true);
          console.log('Dev menu shake gesture disabled via native module');
        } catch (e) {
          console.warn('Could not disable dev menu shake gesture via native module:', e);
        }
      }

      // Start native foreground service for background detection (Android only)
      if (Platform.OS === 'android') {
        try {
          if (NativeModules && typeof NativeModules === 'object') {
            const {ShakeDetectionServiceModule} = NativeModules;
            if (ShakeDetectionServiceModule && typeof ShakeDetectionServiceModule.startService === 'function') {
              // Save setting to native SharedPreferences so service can check it when app is closed
              if (typeof ShakeDetectionServiceModule.setShakeEnabled === 'function') {
                ShakeDetectionServiceModule.setShakeEnabled(true);
              }
              ShakeDetectionServiceModule.startService();
              this.nativeServiceActive = true;
              console.log('Native shake detection service started');
            }
          }
        } catch (e) {
          console.warn('Could not start native shake detection service:', e);
        }
      }

      // Also start JavaScript-based detection for when app is in foreground
      // Re-check and initialize accelerometer
      const accel = initializeAccelerometer();
      if (accel && accel !== false) {
        // Subscribe to accelerometer
        this.subscription = accel.subscribe(
          ({x, y, z}: {x: number; y: number; z: number}) => {
            if (x !== undefined && y !== undefined && z !== undefined) {
              this.handleAccelerometerData(x, y, z);
            }
          },
          (error: any) => {
            console.error('Accelerometer subscription error:', error);
            // Don't set isActive to false - native service might still be running
          },
        );
        
        console.log('Accelerometer subscription started successfully');
      } else {
        console.warn('JavaScript accelerometer not available, relying on native service');
      }

      // Monitor app state to keep detection active in background
      this.appStateListener = AppState.addEventListener('change', this.handleAppStateChange);
    } catch (error) {
      console.error('Error starting shake detection:', error);
      // Don't set isActive to false if native service is running
      if (!this.nativeServiceActive) {
        this.isActive = false;
      }
    }
  }

  stop() {
    if (this.subscription) {
      this.subscription.unsubscribe();
      this.subscription = null;
    }
    
    // Stop native service
    if (Platform.OS === 'android') {
      try {
        if (NativeModules && typeof NativeModules === 'object') {
          const {ShakeDetectionServiceModule} = NativeModules;
          if (ShakeDetectionServiceModule) {
            // Save setting to native SharedPreferences
            if (typeof ShakeDetectionServiceModule.setShakeEnabled === 'function') {
              ShakeDetectionServiceModule.setShakeEnabled(false);
            }
            if (typeof ShakeDetectionServiceModule.stopService === 'function') {
              ShakeDetectionServiceModule.stopService();
            }
            this.nativeServiceActive = false;
            console.log('Native shake detection service stopped');
          }
        }
      } catch (e) {
        console.warn('Could not stop native shake detection service:', e);
      }
    }
    
    // Remove event listener
    if (this.eventEmitter) {
      this.eventEmitter.removeAllListeners('ShakeDetected');
      this.eventEmitter = null;
    }
    
    this.isActive = false;
    this.shakeTimestamps = [];
    this.lastAcceleration = null;
    if (this.appStateListener) {
      this.appStateListener.remove();
      this.appStateListener = null;
    }

    // Re-enable React Native dev menu shake gesture when stopping
    // Method 1: Try using DevSettings (if available)
    if (__DEV__ && DevSettings && typeof DevSettings.setIsShakeToShowDevMenuEnabled === 'function') {
      try {
        DevSettings.setIsShakeToShowDevMenuEnabled(true);
        console.log('Dev menu shake gesture re-enabled via DevSettings');
      } catch (e) {
        console.warn('Could not re-enable dev menu shake gesture via DevSettings:', e);
      }
    }

    // Method 2: Re-enable via native module
    if (Platform.OS === 'android') {
      try {
        DevMenuModule.setShakeDetectionActive(false);
        console.log('Dev menu shake gesture re-enabled via native module');
      } catch (e) {
        console.warn('Could not re-enable dev menu shake gesture via native module:', e);
      }
    }
  }

  isAccelerometerAvailable(): boolean {
    // Re-check availability in case module loaded later
    const result = initializeAccelerometer();
    if (result && result !== false && typeof result.subscribe === 'function') {
      return true;
    }
    return false;
  }

  private handleAppStateChange = (nextAppState: AppStateStatus) => {
    // Keep shake detection active even when app is in background
    // The accelerometer subscription continues to work in background
    console.log('App state changed to:', nextAppState);
  };

  private handleAccelerometerData(x: number, y: number, z: number) {
    // Validate input
    if (typeof x !== 'number' || typeof y !== 'number' || typeof z !== 'number') {
      return;
    }

    if (isNaN(x) || isNaN(y) || isNaN(z)) {
      return;
    }

    // Accelerometer data is typically in m/s², but we need to account for gravity (9.8 m/s²)
    // When device is at rest, one axis should read ~9.8, others ~0
    // We need to subtract gravity to get actual acceleration
    
    if (!this.lastAcceleration) {
      this.lastAcceleration = {x, y, z};
      return;
    }

    const now = Date.now();
    
    // Prevent rapid shake detections - enforce minimum interval
    if (now - this.lastShakeTime < this.minShakeInterval) {
      this.lastAcceleration = {x, y, z};
      return;
    }

    // Calculate the magnitude of acceleration (including gravity)
    const currentMagnitude = Math.sqrt(x * x + y * y + z * z);
    const lastMagnitude = Math.sqrt(
      this.lastAcceleration.x * this.lastAcceleration.x +
      this.lastAcceleration.y * this.lastAcceleration.y +
      this.lastAcceleration.z * this.lastAcceleration.z
    );

    // Calculate change in acceleration magnitude
    // This is more reliable than deltaX/deltaY/deltaZ for detecting shakes
    const magnitudeChange = Math.abs(currentMagnitude - lastMagnitude);
    
    // Also calculate the rate of change (jerk) - how quickly acceleration is changing
    const deltaX = Math.abs(x - this.lastAcceleration.x);
    const deltaY = Math.abs(y - this.lastAcceleration.y);
    const deltaZ = Math.abs(z - this.lastAcceleration.z);
    const totalDelta = Math.sqrt(deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ);

    // Log shake detection for debugging (only when significant movement detected)
    if (magnitudeChange > 5.0 || totalDelta > 5.0) {
      const deviationFromGravity = Math.abs(currentMagnitude - 9.8);
      console.log(`[SHAKE] magnitudeChange=${magnitudeChange.toFixed(2)}, totalDelta=${totalDelta.toFixed(2)}, threshold=${this.config.threshold}, currentMag=${currentMagnitude.toFixed(2)}, lastMag=${lastMagnitude.toFixed(2)}, deviationFromGravity=${deviationFromGravity.toFixed(2)}`);
    }

    // For shake detection, we need EXTREMELY STRICT conditions to prevent false positives
    // react-native-sensors provides data in m/s²
    // Normal gravity is ~9.8 m/s², so we need significantly higher values for actual shakes
    // Note: If accelerometer provides data in g-force (where 1g = 9.8 m/s²), thresholds need adjustment
    const magnitudeThreshold = this.config.threshold * 0.9; // 90% of threshold for magnitude (22.5 m/s²)
    const deltaThreshold = this.config.threshold * 1.1; // 110% of threshold for rate of change (27.5 m/s²) - even stricter
    
    // Additional check: current magnitude should be significantly different from gravity (9.8 m/s²)
    // This helps filter out normal device orientation changes
    const gravityMagnitude = 9.8; // Standard gravity
    const deviationFromGravity = Math.abs(currentMagnitude - gravityMagnitude);
    const minDeviationFromGravity = 15.0; // Require at least 15 m/s² deviation from gravity (very strict)
    
    // Additional check: require that at least one axis has significant change
    // This ensures it's not just noise in one direction
    const maxAxisDelta = Math.max(deltaX, deltaY, deltaZ);
    const minAxisDelta = 12.0; // Require at least 12 m/s² change in at least one axis (increased)
    
    // Additional check: require that the current magnitude itself is high (not just change)
    // This ensures the device is actually being shaken, not just moved slowly
    const minCurrentMagnitude = 15.0; // Require current magnitude to be at least 15 m/s²
    
    // Only consider significant shakes - require ALL conditions:
    // 1. Magnitude change exceeds threshold (22.5 m/s²)
    // 2. Rate of change exceeds threshold (27.5 m/s²) - even stricter
    // 3. Current acceleration deviates significantly from gravity (15+ m/s²)
    // 4. At least one axis has significant change (12+ m/s²)
    // 5. Current magnitude is high enough (15+ m/s²)
    if (magnitudeChange > magnitudeThreshold && 
        totalDelta > deltaThreshold && 
        deviationFromGravity > minDeviationFromGravity &&
        maxAxisDelta > minAxisDelta &&
        currentMagnitude > minCurrentMagnitude) {
      // Update last shake time to prevent rapid triggers
      this.lastShakeTime = now;
      
      const deviationFromGravity = Math.abs(currentMagnitude - 9.8);
      const maxAxisDelta = Math.max(
        Math.abs(x - this.lastAcceleration.x),
        Math.abs(y - this.lastAcceleration.y),
        Math.abs(z - this.lastAcceleration.z)
      );
      console.log(`[SHAKE DETECTED] magnitudeChange=${magnitudeChange.toFixed(2)}, totalDelta=${totalDelta.toFixed(2)}, threshold=${this.config.threshold}, magThreshold=${magnitudeThreshold.toFixed(2)}, deltaThreshold=${deltaThreshold.toFixed(2)}, deviationFromGravity=${deviationFromGravity.toFixed(2)}, maxAxisDelta=${maxAxisDelta.toFixed(2)}, currentMagnitude=${currentMagnitude.toFixed(2)}`);
      
      // Remove old timestamps outside time window first
      this.shakeTimestamps = this.shakeTimestamps.filter(
        (timestamp) => now - timestamp <= this.config.timeWindow,
      );

      // Only add new shake if there are existing shakes within the time window
      // OR if this is the first shake (empty array)
      // This ensures shakes are consecutive
      if (this.shakeTimestamps.length === 0 || 
          (this.shakeTimestamps.length > 0 && 
           now - this.shakeTimestamps[this.shakeTimestamps.length - 1] <= this.config.timeWindow / 2)) {
        this.shakeTimestamps.push(now);
        console.log(`Shake ${this.shakeTimestamps.length} registered at ${new Date(now).toISOString()}`);
      } else {
        // If too much time passed, reset and start fresh
        console.log('Shake sequence reset - too much time between shakes');
        this.shakeTimestamps = [now];
      }

            // Check if required number of consecutive shakes detected
            if (this.shakeTimestamps.length >= this.config.shakeCount) {
              // Verify all shakes are within the time window (consecutive)
              const firstShake = this.shakeTimestamps[0];
              const lastShake = this.shakeTimestamps[this.shakeTimestamps.length - 1];
              const timeSpan = lastShake - firstShake;
              
              if (timeSpan <= this.config.timeWindow) {
                // Reset shake timestamps to prevent re-triggering
                this.shakeTimestamps = [];
                
                // Check if app is in foreground - if not, send SOS directly without confirmation
                // When app is closed/background, we can't show dialogs, so send directly
                const isAppInForeground = AppState.currentState === 'active';
                
                if (!isAppInForeground) {
                  // App is in background - send SOS directly without confirmation
                  console.log('[SOS DETECTED] App in background, sending SOS directly');
                  this.sendSOS();
                  return;
                }
                
                // App is in foreground - show confirmation dialog
                if (!this.pendingConfirmation) {
                  this.pendingConfirmation = true;
                  console.log('[SOS DETECTED] 3 consecutive shakes detected, showing confirmation dialog');
                  
                  // Vibrate to indicate shake detection
                  try {
                    const {CustomVibration} = require('../modules/VibrationModule');
                    CustomVibration.vibrate(200); // Short vibration to indicate detection
                    console.log('[SOS DETECTED] Vibration triggered for shake detection');
                  } catch (e) {
                    console.warn('[SOS DETECTED] Could not vibrate:', e);
                    // Fallback to React Native Vibration
                    try {
                      const {Vibration} = require('react-native');
                      Vibration.vibrate(200);
                    } catch (e2) {
                      console.error('[SOS DETECTED] Fallback vibration also failed:', e2);
                    }
                  }
                  
                  // Use setTimeout with a small delay to ensure we're on the main thread
                  setTimeout(() => {
                    try {
                      console.log('[SOS DETECTED] About to show confirmation dialog');
                      this.showConfirmationDialog(() => {
                        // User confirmed - send SOS
                        console.log('[SOS DETECTED] User confirmed - sending SOS');
                        this.pendingConfirmation = false;
                        this.sendSOS();
                      }, () => {
                        // User cancelled
                        this.pendingConfirmation = false;
                        console.log('[SOS DETECTED] User cancelled SOS');
                      });
                    } catch (error) {
                      console.error('[SOS DETECTED] Error in showConfirmationDialog setTimeout:', error);
                      this.pendingConfirmation = false;
                    }
                  }, 100);
                } else {
                  console.log('[SOS DETECTED] Confirmation dialog already pending, ignoring shake');
                }
              }
            }
    }

    this.lastAcceleration = {x, y, z};
  }

  private sendSOS() {
    console.log('3 consecutive shakes detected - sending SOS');
    
    // Vibrate on 3rd shake (before sending notification)
    try {
      // Use CustomVibration for better reliability
      const {CustomVibration} = require('../modules/VibrationModule');
      // Vibrate once for 1000ms when 3 shakes detected (longer for better feel)
      console.log('Attempting to vibrate using CustomVibration...');
      CustomVibration.vibrate(1000);
      console.log('Vibration triggered on 3rd shake via CustomVibration');
    } catch (e) {
      console.warn('Could not vibrate using CustomVibration:', e);
      // Fallback to React Native Vibration
      try {
        const {Vibration} = require('react-native');
        console.log('Attempting fallback vibration using React Native Vibration...');
        Vibration.vibrate(1000);
        console.log('Vibration triggered on 3rd shake via React Native Vibration');
      } catch (e2) {
        console.error('Fallback vibration also failed:', e2);
      }
    }
    
    // Trigger SOS (this will send alert and show push notification)
    this.triggerShakeDetected();
  }

  private showConfirmationDialog(onConfirm: () => void, onCancel: () => void) {
    try {
      console.log('[CONFIRMATION DIALOG] Showing dialog for SOS confirmation');
      console.log('[CONFIRMATION DIALOG] Alert imported:', typeof Alert, Alert !== undefined && Alert !== null);
      
      if (!Alert || typeof Alert.alert !== 'function') {
        console.error('[CONFIRMATION DIALOG] Alert.alert is not available!');
        // Fallback: just send the SOS
        onConfirm();
        return;
      }
      
      // Use Alert directly from React Native (imported at top)
      console.log('[CONFIRMATION DIALOG] Calling Alert.alert now...');
      Alert.alert(
        'Send SOS Alert?',
        'Do you want to send an emergency SOS alert?',
        [
          {
            text: 'Cancel',
            style: 'cancel',
            onPress: () => {
              console.log('[CONFIRMATION DIALOG] User pressed Cancel');
              onCancel();
            },
          },
          {
            text: 'Send SOS',
            style: 'destructive',
            onPress: () => {
              console.log('[CONFIRMATION DIALOG] User pressed Send SOS');
              onConfirm();
            },
          },
        ],
        {
          cancelable: true,
          onDismiss: () => {
            console.log('[CONFIRMATION DIALOG] User dismissed dialog');
            onCancel();
          },
        }
      );
      console.log('[CONFIRMATION DIALOG] Alert.alert called successfully');
    } catch (e) {
      console.error('[CONFIRMATION DIALOG] Error showing confirmation dialog:', e);
      // If dialog fails, just send the SOS
      onConfirm();
    }
  }

  private triggerShakeDetected() {
    console.log('Triggering shake detected - sending SOS');
    if (this.onShakeDetected) {
      // Call the callback to send SOS
      this.onShakeDetected();
    }
    // Show notification
    this.showSOSNotification();
  }


  showSOSNotification() {
    console.log('Showing SOS push notification');
    try {
      if (!PushNotification) {
        console.warn('PushNotification is not available - using Alert as fallback');
        // Fallback to Alert if notifications not available
        const {Alert} = require('react-native');
        Alert.alert('SOS Sent Successfully', 'Your emergency alert has been sent. Our officials will be there shortly.');
        return;
      }

      // Ensure notifications are configured
      this.configureNotifications();

      if (PushNotification && typeof PushNotification.localNotification === 'function') {
        const notificationConfig: any = {
          id: 'sos-' + Date.now(), // Unique ID for notification
          title: 'SOS Sent Successfully',
          message: 'Your emergency alert has been sent. Our officials will be there shortly.',
          playSound: true,
          soundName: 'default',
          vibrate: false, // Don't vibrate in notification since we already vibrated on 3rd shake
          vibration: 0,
          tag: 'sos-alert',
          userInfo: {
            type: 'sos',
            timestamp: Date.now(),
          },
        };

        // Add Android-specific properties
        if (Platform.OS === 'android') {
          notificationConfig.channelId = 'sos-channel';
          notificationConfig.importance = 'high';
          notificationConfig.priority = 'high';
          notificationConfig.autoCancel = false; // Don't auto-cancel important SOS notification
          notificationConfig.ongoing = false;
          // Remove icon configs that might cause issues
          // notificationConfig.largeIcon = '';
          // notificationConfig.smallIcon = 'ic_notification';
        }

        console.log('Sending notification with config:', JSON.stringify(notificationConfig, null, 2));
        
        PushNotification.localNotification(notificationConfig);
        console.log('SOS push notification sent successfully with ID:', notificationConfig.id);
      } else {
        // Fallback to Alert
        const {Alert} = require('react-native');
        Alert.alert('SOS Sent Successfully', 'Your emergency alert has been sent. Our officials will be there shortly.');
      }
    } catch (error) {
      console.error('Error showing SOS push notification:', error);
      // Fallback to Alert on error
      try {
        const {Alert} = require('react-native');
        Alert.alert('SOS Sent Successfully', 'Your emergency alert has been sent. Our officials will be there shortly.');
      } catch (e) {
        console.error('Could not show alert:', e);
      }
    }
  }
}

// Singleton instance
export const shakeDetectionService = new ShakeDetectionService();

