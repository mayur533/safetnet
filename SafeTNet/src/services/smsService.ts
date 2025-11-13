import {Platform, Alert} from 'react-native';

let SmsAndroid: any = null;
if (Platform.OS === 'android') {
  try {
    SmsAndroid = require('react-native-sms-android');
  } catch (error) {
    console.warn('react-native-sms-android not installed');
  }
}

export const sendSmsDirect = async (phoneNumbers: string[], message: string) => {
  if (Platform.OS !== 'android') {
    return false;
  }

  if (!SmsAndroid) {
    Alert.alert(
      'SMS module unavailable',
      'Install react-native-sms-android to enable offline SMS fallback.',
    );
    return false;
  }

  if (phoneNumbers.length === 0) {
    return false;
  }

  return new Promise<boolean>((resolve) => {
    SmsAndroid.autoSend(
      phoneNumbers.join(','),
      message,
      (fail: unknown) => {
        console.warn('Failed to send SMS via direct send', fail);
        resolve(false);
      },
      () => {
        resolve(true);
      },
    );
  });
};
