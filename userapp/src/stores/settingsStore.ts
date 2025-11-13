import {create} from 'zustand';
import AsyncStorage from '@react-native-async-storage/async-storage';

export type ThemeMode = 'light' | 'dark' | 'system';

interface SettingsState {
  shakeToSendSOS: boolean;
  themeMode: ThemeMode;
  setShakeToSendSOS: (enabled: boolean) => Promise<void>;
  setThemeMode: (mode: ThemeMode) => Promise<void>;
  loadSettings: () => Promise<void>;
}

const STORAGE_KEY = 'appSettings';
const LEGACY_SHAKE_KEY = 'shakeToSendSOS';

const getDefaultSettings = () => ({
  shakeToSendSOS: false,
  themeMode: 'system' as ThemeMode,
});

const persistSettings = async (settings: {shakeToSendSOS: boolean; themeMode: ThemeMode}) => {
  try {
    await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
  } catch (error) {
    console.error('Error saving settings:', error);
  }
};

export const useSettingsStore = create<SettingsState>((set, get) => ({
  ...getDefaultSettings(),
  setShakeToSendSOS: async (enabled: boolean) => {
    set({shakeToSendSOS: enabled});
    const {themeMode} = get();
    await persistSettings({shakeToSendSOS: enabled, themeMode});
  },
  setThemeMode: async (mode: ThemeMode) => {
    set({themeMode: mode});
    const {shakeToSendSOS} = get();
    await persistSettings({shakeToSendSOS, themeMode: mode});
  },
  loadSettings: async () => {
    try {
      const value = await AsyncStorage.getItem(STORAGE_KEY);
      if (value) {
        const parsed = JSON.parse(value);
        set({
          shakeToSendSOS: typeof parsed.shakeToSendSOS === 'boolean' ? parsed.shakeToSendSOS : false,
          themeMode: parsed.themeMode === 'light' || parsed.themeMode === 'dark' || parsed.themeMode === 'system' ? parsed.themeMode : 'system',
        });
        return;
      }

      // Legacy support for older shake-only storage
      const legacyShakeValue = await AsyncStorage.getItem(LEGACY_SHAKE_KEY);
      if (legacyShakeValue !== null) {
        const shakeEnabled = JSON.parse(legacyShakeValue);
        set({shakeToSendSOS: !!shakeEnabled});
        await persistSettings({shakeToSendSOS: !!shakeEnabled, themeMode: get().themeMode});
      }
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  },
}));

