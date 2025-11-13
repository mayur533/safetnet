import React, {useEffect, useMemo} from 'react';
import {NavigationContainer} from '@react-navigation/native';
import {SafeAreaProvider} from 'react-native-safe-area-context';
import {GestureHandlerRootView} from 'react-native-gesture-handler';
import {StatusBar, StyleSheet, useColorScheme} from 'react-native';
import {useAuthStore} from './src/stores/authStore';
import {useSettingsStore} from './src/stores/settingsStore';
import {useAppLockStore} from './src/stores/appLockStore';
import {startVolumeQuickLaunch, stopVolumeQuickLaunch} from './src/services/volumeQuickLaunchService';
import AuthNavigator from './src/navigation/AuthNavigator';
import AppNavigator from './src/navigation/AppNavigator';
import {LightAppTheme, DarkAppTheme} from './src/theme/navigationThemes';
import AppLockModal from './src/components/security/AppLockModal';

const App = () => {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const themeMode = useSettingsStore((state) => state.themeMode);
  const loadSettings = useSettingsStore((state) => state.loadSettings);
  const quickLaunchVolume = useSettingsStore((state) => state.quickLaunchVolume);
  const loadAppLock = useAppLockStore((state) => state.load);
  const systemScheme = useColorScheme();

  useEffect(() => {
    loadSettings();
    loadAppLock();
  }, [loadSettings, loadAppLock]);

  useEffect(() => {
    if (quickLaunchVolume && isAuthenticated) {
      startVolumeQuickLaunch();
    } else {
      stopVolumeQuickLaunch();
    }
    return () => {
      stopVolumeQuickLaunch();
    };
  }, [quickLaunchVolume, isAuthenticated]);

  const navigationTheme = useMemo(() => {
    if (systemScheme === 'dark') {
      return DarkAppTheme;
    }
    return LightAppTheme;
  }, [systemScheme]);

  const statusBarStyle = useMemo(() => {
    if (navigationTheme.dark) {
      return 'light-content';
    }
    return 'dark-content';
  }, [navigationTheme]);

  return (
    <GestureHandlerRootView style={styles.container}>
      <SafeAreaProvider>
        <NavigationContainer theme={navigationTheme}>
          <StatusBar barStyle={statusBarStyle} backgroundColor={navigationTheme.colors.background} />
          {isAuthenticated ? <AppNavigator /> : <AuthNavigator />}
          <AppLockModal />
        </NavigationContainer>
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
});

export default App;
