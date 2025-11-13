import {create} from 'zustand';
import AsyncStorage from '@react-native-async-storage/async-storage';

type LockType = 'numeric' | 'alphanumeric';

type AppLockModal =
  | {type: null}
  | {type: 'setup'}
  | {type: 'unlock'}
  | {type: 'verifyDisable'}
  | {type: 'change'};

interface AppLockState {
  isEnabled: boolean;
  lockType: LockType;
  passcode: string | null;
  isUnlocked: boolean;
  modal: AppLockModal;
  load: () => Promise<void>;
  requireSetup: () => void;
  completeSetup: (passcode: string, type: LockType) => Promise<void>;
  enableLock: () => Promise<void>;
  requestDisable: () => void;
  disableLock: () => Promise<void>;
  requestChange: () => void;
  unlock: (passcode: string) => boolean;
  verifyForDisable: (passcode: string) => Promise<boolean>;
  changePasscode: (currentPasscode: string, newPasscode: string, type: LockType) => Promise<boolean>;
  dismissModal: () => void;
  lockIfNeeded: () => void;
}

interface PersistedAppLock {
  isEnabled: boolean;
  lockType: LockType;
  passcode: string | null;
}

const STORAGE_KEY = 'appLockSettings';

const defaultState: PersistedAppLock = {
  isEnabled: false,
  lockType: 'numeric',
  passcode: null,
};

const persistAppLock = async (state: PersistedAppLock) => {
  try {
    await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch (error) {
    console.warn('Unable to persist app lock settings', error);
  }
};

const validatePasscode = (passcode: string, type: LockType) => {
  if (type === 'numeric') {
    return /^\d{4}$/.test(passcode);
  }
  return /^[A-Za-z0-9]{4,}$/.test(passcode);
};

export const useAppLockStore = create<AppLockState>((set, get) => ({
  ...defaultState,
  isUnlocked: false,
  modal: {type: null},
  load: async () => {
    try {
      const raw = await AsyncStorage.getItem(STORAGE_KEY);
      if (!raw) {
        return;
      }
      const parsed = JSON.parse(raw) as PersistedAppLock;
      set({
        isEnabled: parsed.isEnabled,
        lockType: parsed.lockType,
        passcode: parsed.passcode,
        isUnlocked: !parsed.isEnabled,
        modal: parsed.isEnabled ? {type: 'unlock'} : {type: null},
      });
    } catch (error) {
      console.warn('Unable to load app lock settings', error);
    }
  },
  requireSetup: () => {
    set({modal: {type: 'setup'}, isUnlocked: false});
  },
  completeSetup: async (passcode, type) => {
    if (!validatePasscode(passcode, type)) {
      throw new Error(
        type === 'numeric'
          ? 'Numeric passcode must be exactly 4 digits.'
          : 'Alphanumeric passcode must be at least 4 characters (letters and numbers).',
      );
    }
    const newState: PersistedAppLock = {
      isEnabled: true,
      lockType: type,
      passcode,
    };
    await persistAppLock(newState);
    set({
      ...newState,
      isUnlocked: true,
      modal: {type: null},
    });
  },
  enableLock: async () => {
    const {passcode, lockType} = get();
    if (!passcode) {
      set({modal: {type: 'setup'}});
      return;
    }
    const newState: PersistedAppLock = {
      isEnabled: true,
      lockType,
      passcode,
    };
    await persistAppLock(newState);
    set({
      ...newState,
      isUnlocked: false,
      modal: {type: 'unlock'},
    });
  },
  requestDisable: () => {
    const {isEnabled} = get();
    if (!isEnabled) {
      return;
    }
    set({modal: {type: 'verifyDisable'}});
  },
  disableLock: async () => {
    const {lockType, passcode} = get();
    const newState: PersistedAppLock = {
      isEnabled: false,
      lockType,
      passcode,
    };
    await persistAppLock(newState);
    set({
      ...newState,
      isUnlocked: true,
      modal: {type: null},
    });
  },
  requestChange: () => {
    set({modal: {type: 'change'}});
  },
  unlock: (passcodeAttempt: string) => {
    const {passcode} = get();
    if (!passcode) {
      return true;
    }
    const success = passcodeAttempt === passcode;
    if (success) {
      set({isUnlocked: true, modal: {type: null}});
    }
    return success;
  },
  verifyForDisable: async (passcodeAttempt: string) => {
    const success = passcodeAttempt === get().passcode;
    if (success) {
      await get().disableLock();
    }
    return success;
  },
  changePasscode: async (currentPasscode: string, newPasscode: string, type: LockType) => {
    const {passcode} = get();
    if (passcode !== currentPasscode) {
      return false;
    }
    if (!validatePasscode(newPasscode, type)) {
      throw new Error(
        type === 'numeric'
          ? 'Numeric passcode must be exactly 4 digits.'
          : 'Alphanumeric passcode must be at least 4 characters (letters and numbers).',
      );
    }
    const newState: PersistedAppLock = {
      isEnabled: true,
      lockType: type,
      passcode: newPasscode,
    };
    await persistAppLock(newState);
    set({
      ...newState,
      isUnlocked: true,
      modal: {type: null},
    });
    return true;
  },
  dismissModal: () => {
    set({modal: {type: null}});
  },
  lockIfNeeded: () => {
    const {isEnabled} = get();
    if (isEnabled) {
      set({isUnlocked: false, modal: {type: 'unlock'}});
    }
  },
}));
