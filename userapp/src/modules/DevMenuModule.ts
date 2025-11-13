import {NativeModules, Platform} from 'react-native';

// Safely get DevMenuModule from NativeModules
let NativeDevMenuModule: any = null;
try {
  if (NativeModules && typeof NativeModules === 'object') {
    NativeDevMenuModule = NativeModules.DevMenuModule;
  }
} catch (e) {
  console.warn('Could not access NativeModules:', e);
}

interface DevMenuModuleInterface {
  setShakeDetectionActive: (active: boolean) => void;
  isShakeDetectionActive: () => Promise<boolean>;
}

export const DevMenuModule: DevMenuModuleInterface = {
  setShakeDetectionActive: (active: boolean) => {
    if (Platform.OS === 'android' && NativeDevMenuModule) {
      try {
        NativeDevMenuModule.setShakeDetectionActive(active);
      } catch (e) {
        console.warn('Could not set shake detection active state:', e);
      }
    }
  },
  isShakeDetectionActive: (): Promise<boolean> => {
    if (Platform.OS === 'android' && NativeDevMenuModule) {
      try {
        return NativeDevMenuModule.isShakeDetectionActive();
      } catch (e) {
        console.warn('Could not check shake detection active state:', e);
        return Promise.resolve(false);
      }
    }
    return Promise.resolve(false);
  },
};
