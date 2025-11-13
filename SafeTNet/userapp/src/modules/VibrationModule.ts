import { NativeModules, Platform } from 'react-native';

const { VibrationModule } = NativeModules;

export const CustomVibration = {
  vibrate: (duration: number = 1000) => {
    if (Platform.OS === 'android' && VibrationModule) {
      VibrationModule.vibrate(duration);
    } else {
      // Fallback to React Native's Vibration API for iOS
      const { Vibration } = require('react-native');
      Vibration.vibrate(duration);
    }
  },
  
  vibratePattern: (pattern: number[], repeat: number = -1) => {
    if (Platform.OS === 'android' && VibrationModule) {
      // Convert number array to array that can be passed to native module
      VibrationModule.vibratePattern(pattern, repeat);
    } else {
      // Fallback to React Native's Vibration API for iOS
      const { Vibration } = require('react-native');
      Vibration.vibrate(pattern, repeat !== -1);
    }
  },
};

