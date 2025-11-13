import {Platform} from 'react-native';
import VolumeController from 'react-native-volume-controller';
import {emitSosTrigger} from './sosEventBus';

const REQUIRED_PRESSES = 4;
const WINDOW_MS = 1500;

let isMonitoring = false;
let volumeListener: any = null;
let pressTimestamps: number[] = [];

export const startVolumeQuickLaunch = () => {
  if (Platform.OS !== 'android') {
    return;
  }
  if (isMonitoring) {
    return;
  }
  try {
    pressTimestamps = [];
    volumeListener = VolumeController.addListener(() => {
      const now = Date.now();
      pressTimestamps = pressTimestamps.filter((timestamp) => now - timestamp <= WINDOW_MS);
      pressTimestamps.push(now);
      if (pressTimestamps.length >= REQUIRED_PRESSES) {
        pressTimestamps = [];
        emitSosTrigger();
      }
    });
    isMonitoring = true;
  } catch (error) {
    console.warn('Unable to start volume shortcut listener', error);
  }
};

export const stopVolumeQuickLaunch = () => {
  if (!isMonitoring) {
    return;
  }
  try {
    if (volumeListener?.remove) {
      volumeListener.remove();
    }
  } catch (error) {
    console.warn('Unable to stop volume shortcut listener', error);
  }
  volumeListener = null;
  pressTimestamps = [];
  isMonitoring = false;
};
