import NetInfo from '@react-native-community/netinfo';

export const checkNetworkStatus = async () => {
  try {
    const state = await NetInfo.fetch();
    return {
      isConnected: Boolean(state.isConnected),
      isInternetReachable: Boolean(state.isInternetReachable ?? state.isConnected),
    };
  } catch (error) {
    console.warn('Network check failed', error);
    return {isConnected: false, isInternetReachable: false};
  }
};
