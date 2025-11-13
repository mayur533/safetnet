import {PermissionsAndroid, Platform, Linking, Alert} from 'react-native';

export const requestDirectCall = async (phone?: string) => {
  if (!phone) {
    Alert.alert('Call Failed', 'No phone number available for this contact.');
    return false;
  }

  if (Platform.OS !== 'android') {
    try {
      await Linking.openURL(`tel:${phone}`);
      return true;
    } catch (error) {
      console.warn('Failed to initiate call:', error);
      Alert.alert('Call Failed', 'Unable to place the call. Please try again from your dialer.');
      return false;
    }
  }

  try {
    const permission = PermissionsAndroid.PERMISSIONS.CALL_PHONE;
    const hasPermission = await PermissionsAndroid.check(permission);
    let granted = hasPermission;

    if (!hasPermission) {
      const status = await PermissionsAndroid.request(permission, {
        title: 'Allow Phone Calls',
        message: 'Grant phone call access to contact emergency services directly.',
        buttonPositive: 'Allow',
        buttonNegative: 'Deny',
      });
      granted = status === PermissionsAndroid.RESULTS.GRANTED;
    }

    if (!granted) {
      Alert.alert(
        'Permission Required',
        'Please allow phone call access in settings to place emergency calls automatically.',
      );
      return false;
    }

    await Linking.openURL(`tel:${phone}`);
    return true;
  } catch (error) {
    console.warn('Call permission request failed:', error);
    Alert.alert('Call Failed', 'Unable to place the call. Please try again from your dialer.');
    return false;
  }
};
