import {DeviceEventEmitter, EmitterSubscription} from 'react-native';

export const SOS_TRIGGER_EVENT = 'sos_trigger_volume';

export const emitSosTrigger = () => {
  DeviceEventEmitter.emit(SOS_TRIGGER_EVENT);
};

export const addSosTriggerListener = (handler: () => void): EmitterSubscription => {
  return DeviceEventEmitter.addListener(SOS_TRIGGER_EVENT, handler);
};
