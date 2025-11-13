declare module 'react-native-sms-android' {
  const SmsAndroid: {
    autoSend: (
      phoneNumber: string,
      message: string,
      failureCallback: (error: unknown) => void,
      successCallback: () => void,
    ) => void;
  };

  export default SmsAndroid;
}
