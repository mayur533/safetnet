import React, {useState, useEffect} from 'react';
import {View, Text, ScrollView, StyleSheet, Switch, TouchableOpacity} from 'react-native';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useTheme} from '@react-navigation/native';
import {useSettingsStore} from '../../stores/settingsStore';
import type {ThemeMode} from '../../stores/settingsStore';
import {shakeDetectionService} from '../../services/shakeDetectionService';

const SettingsScreen = () => {
  const shakeToSendSOS = useSettingsStore((state) => state.shakeToSendSOS);
  const setShakeToSendSOS = useSettingsStore((state) => state.setShakeToSendSOS);
  const themeMode = useSettingsStore((state) => state.themeMode);
  const setThemeMode = useSettingsStore((state) => state.setThemeMode);
  const [isAccelerometerAvailable, setIsAccelerometerAvailable] = useState(false);
  const theme = useTheme();

  useEffect(() => {
    // Check if accelerometer is available immediately
    const checkAvailability = () => {
      const available = shakeDetectionService.isAccelerometerAvailable();
      setIsAccelerometerAvailable(available);
      return available;
    };

    // Initial check
    checkAvailability();

    // Retry checking after a delay in case module loads later
    const retryInterval = setInterval(() => {
      if (checkAvailability()) {
        clearInterval(retryInterval); // Stop retrying once available
      }
    }, 2000); // Check every 2 seconds

    // Stop retrying after 10 seconds
    const timeout = setTimeout(() => {
      clearInterval(retryInterval);
    }, 10000);

    return () => {
      clearInterval(retryInterval);
      clearTimeout(timeout);
    };
  }, []);

  const themeOptions: {mode: ThemeMode; label: string; icon: string}[] = [
    {mode: 'light', label: 'Light', icon: 'light-mode'},
    {mode: 'dark', label: 'Dark', icon: 'dark-mode'},
    {mode: 'system', label: 'System', icon: 'settings'},
  ];

  return (
    <ScrollView
      style={[styles.container, {backgroundColor: theme.colors.background}]}
      contentContainerStyle={styles.content}>
      <View style={styles.section}>
        <Text style={[styles.sectionTitle, {color: theme.colors.text}]}>Safety</Text>
        <View
          style={[
            styles.settingItem,
            {backgroundColor: theme.colors.card, borderColor: theme.colors.border},
          ]}>
          <View style={styles.settingInfo}>
            <MaterialIcons name="vibration" size={24} color="#2563EB" />
            <View style={styles.settingTextContainer}>
              <Text style={[styles.settingTitle, {color: theme.colors.text}]}>Send SOS by shaking phone 3 times</Text>
              <Text style={[styles.settingDescription, {color: theme.colors.notification}]}>Enable shake gesture to quickly send SOS alerts</Text>
              {!isAccelerometerAvailable && (
                <Text style={styles.warningText}>
                  Accelerometer not available. Please rebuild the app.
                </Text>
              )}
            </View>
          </View>
          <Switch
            value={shakeToSendSOS && isAccelerometerAvailable}
            onValueChange={async (value) => {
              if (isAccelerometerAvailable) {
                await setShakeToSendSOS(value);
                // Start/stop service based on setting
                if (value) {
                  shakeDetectionService.start(() => {
                    // This will be handled by HomeScreen
                  });
                } else {
                  shakeDetectionService.stop();
                }
              }
            }}
            disabled={!isAccelerometerAvailable}
            trackColor={{false: '#D1D5DB', true: '#93C5FD'}}
            thumbColor={shakeToSendSOS && isAccelerometerAvailable ? '#2563EB' : '#F3F4F6'}
            ios_backgroundColor="#D1D5DB"
          />
        </View>
      </View>

      <View style={styles.section}>
        <Text style={[styles.sectionTitle, {color: theme.colors.text}]}>Appearance</Text>
        <View style={styles.themeOptionsContainer}>
          {themeOptions.map((option) => {
            const isActive = option.mode === themeMode;
            return (
              <TouchableOpacity
                key={option.mode}
                onPress={() => setThemeMode(option.mode)}
                activeOpacity={0.85}
                style={[
                  styles.themeOption,
                  {
                    backgroundColor: isActive ? '#2563EB' : theme.colors.card,
                    borderColor: isActive ? '#2563EB' : theme.colors.border,
                  },
                ]}>
                <MaterialIcons
                  name={option.icon}
                  size={22}
                  color={isActive ? '#FFFFFF' : theme.colors.text}
                />
                <Text
                  style={[
                    styles.themeOptionLabel,
                    {color: isActive ? '#FFFFFF' : theme.colors.text},
                  ]}>
                  {option.label}
                </Text>
              </TouchableOpacity>
            );
          })}
        </View>
        <Text style={[styles.themeHint, {color: theme.colors.notification}]}>System matches your device theme automatically.</Text>
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  content: {
    padding: 20,
  },
  section: {
    marginTop: 24,
    gap: 12,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: '700',
  },
  settingItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingVertical: 16,
    paddingHorizontal: 16,
    borderRadius: 12,
    borderWidth: 1,
  },
  settingInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
    marginRight: 16,
    gap: 12,
  },
  settingTextContainer: {
    flex: 1,
  },
  settingTitle: {
    fontSize: 16,
    fontWeight: '600',
    marginBottom: 4,
  },
  settingDescription: {
    fontSize: 14,
    lineHeight: 20,
  },
  warningText: {
    fontSize: 12,
    color: '#EF4444',
    marginTop: 4,
    fontStyle: 'italic',
  },
  themeOptionsContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: 12,
  },
  themeOption: {
    flex: 1,
    borderRadius: 12,
    borderWidth: 1,
    paddingVertical: 14,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 6,
  },
  themeOptionLabel: {
    fontSize: 14,
    fontWeight: '600',
  },
  themeHint: {
    fontSize: 12,
    marginTop: 4,
  },
});

export default SettingsScreen;

