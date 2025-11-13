/**
 * Sample React Native App
 * https://github.com/facebook/react-native
 *
 * @format
 */

import React, {useEffect, useMemo} from 'react';
import {NavigationContainer} from '@react-navigation/native';
import {SafeAreaProvider} from 'react-native-safe-area-context';
import {GestureHandlerRootView} from 'react-native-gesture-handler';
import {StatusBar, StyleSheet, useColorScheme} from 'react-native';
import {useAuthStore} from './src/stores/authStore';
import {useSettingsStore} from './src/stores/settingsStore';
import AuthNavigator from './src/navigation/AuthNavigator';
import AppNavigator from './src/navigation/AppNavigator';
import {LightAppTheme, DarkAppTheme} from './src/theme/navigationThemes';

function App(): React.JSX.Element {
  // Always call hooks in the same order (before any conditional logic)
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const themeMode = useSettingsStore((state) => state.themeMode);
  const loadSettings = useSettingsStore((state) => state.loadSettings);
  const systemScheme = useColorScheme();

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  const resolvedScheme = themeMode === 'system' ? systemScheme ?? 'light' : themeMode;

  const navigationTheme = useMemo(
    () => (resolvedScheme === 'dark' ? DarkAppTheme : LightAppTheme),
    [resolvedScheme],
  );

  const statusBarStyle = resolvedScheme === 'dark' ? 'light-content' : 'dark-content';

  return (
    <GestureHandlerRootView style={styles.container}>
      <SafeAreaProvider>
        <NavigationContainer theme={navigationTheme}>
          <StatusBar barStyle={statusBarStyle} backgroundColor={navigationTheme.colors.background} />
          {isAuthenticated ? <AppNavigator /> : <AuthNavigator />}
        </NavigationContainer>
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
});

export default App;
