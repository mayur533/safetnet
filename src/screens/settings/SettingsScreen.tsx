import React, {useState, useEffect} from 'react';
import {View, Text, ScrollView, StyleSheet, Switch, TouchableOpacity} from 'react-native';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useTheme} from '@react-navigation/native';
import {useSettingsStore} from '../../stores/settingsStore';
import type {ThemeMode} from '../../stores/settingsStore';
import {shakeDetectionService} from '../../services/shakeDetectionService';
import {useAppLockStore} from '../../stores/appLockStore';

const SettingsScreen = () => {
  const themeMode = useSettingsStore((state) => state.themeMode);
  const setThemeMode = useSettingsStore((state) => state.setThemeMode);
  const [isAccelerometerAvailable, setIsAccelerometerAvailable] = useState(false);
  const theme = useTheme();
  const isAppLockEnabled = useAppLockStore((state) => state.isEnabled);
  const passcode = useAppLockStore((state) => state.passcode);
  const enableAppLock = useAppLockStore((state) => state.enableLock);
  const requestDisable = useAppLockStore((state) => state.requestDisable);
  const requestChange = useAppLockStore((state) => state.requestChange);
  const requireSetup = useAppLockStore((state) => state.requireSetup);
  const quickLaunchVolume = useSettingsStore((state) => state.quickLaunchVolume);
  const setQuickLaunchVolume = useSettingsStore((state) => state.setQuickLaunchVolume);

  useEffect(() => {
    const checkAccelerometer = async () => {
      const available = await shakeDetectionService.isAccelerometerAvailable();
      setIsAccelerometerAvailable(available);
    };
    checkAccelerometer();
  }, []);

  const themeOptions: {mode: ThemeMode; label: string; icon: string}[] = [
    {mode: 'light', label: 'Light', icon: 'light-mode'},
    {mode: 'dark', label: 'Dark', icon: 'dark-mode'},
    {mode: 'system', label: 'System', icon: 'settings'},
  ];

  const handleAppLockToggle = async (value: boolean) => {
    if (value) {
      if (!passcode) {
        requireSetup();
      } else {
        await enableAppLock();
      }
    } else {
      requestDisable();
    }
  };

  const handleQuickLaunchToggle = async (value: boolean) => {
    await setQuickLaunchVolume(value);
  };

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <View style={styles.section}>
        <Text style={[styles.sectionTitle, {color: theme.colors.text}]}>Safety</Text>
        <View
          style={[styles.settingItem, {backgroundColor: theme.colors.card, borderColor: theme.colors.border}]}>
          <View style={styles.settingInfo}>
            <MaterialIcons name="lock" size={24} color="#2563EB" />
            <View style={styles.settingTextContainer}>
              <Text style={[styles.settingTitle, {color: theme.colors.text}]}>App lock</Text>
              <Text style={[styles.settingDescription, {color: theme.colors.notification}]}>Protect the app with a passcode. Numeric PIN (4 digits) or alphanumeric passwords are supported.</Text>
            </View>
          </View>
          <Switch
            value={isAppLockEnabled}
            onValueChange={handleAppLockToggle}
            trackColor={{false: '#D1D5DB', true: '#93C5FD'}}
            thumbColor={isAppLockEnabled ? '#2563EB' : '#F3F4F6'}
            ios_backgroundColor="#D1D5DB"
          />
        </View>

        <TouchableOpacity
          style={[styles.secondarySettingButton, {borderColor: theme.colors.border, backgroundColor: theme.colors.card}]}
          onPress={requestChange}
          disabled={!passcode}
          activeOpacity={0.85}>
          <View style={styles.secondarySettingInfo}>
            <MaterialIcons name="edit" size={20} color={passcode ? '#2563EB' : '#9CA3AF'} />
            <Text style={[styles.secondarySettingText, {color: passcode ? theme.colors.text : '#9CA3AF'}]}>Change passcode</Text>
          </View>
          <MaterialIcons name="chevron-right" size={20} color={theme.colors.notification} />
        </TouchableOpacity>

        <View
          style={[styles.settingItem, {backgroundColor: theme.colors.card, borderColor: theme.colors.border}]}>
          <View style={styles.settingInfo}>
            <MaterialIcons name="vibration" size={24} color="#2563EB" />
            <View style={styles.settingTextContainer}>
              <Text style={[styles.settingTitle, {color: theme.colors.text}]}>Send SOS by shaking phone 3 times</Text>
              <Text style={[styles.settingDescription, {color: theme.colors.notification}]}>Enable shake gesture to quickly send SOS alerts</Text>
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

        <View
          style={[styles.settingItem, {backgroundColor: theme.colors.card, borderColor: theme.colors.border}]}>
          <View style={styles.settingInfo}>
            <MaterialIcons name="volume-up" size={24} color="#2563EB" />
            <View style={styles.settingTextContainer}>
              <Text style={[styles.settingTitle, {color: theme.colors.text}]}>SOS via volume buttons</Text>
              <Text style={[styles.settingDescription, {color: theme.colors.notification}]}>Press either volume button quickly four times to trigger the SOS countdown.</Text>
            </View>
          </View>
          <Switch
            value={quickLaunchVolume}
            onValueChange={handleQuickLaunchToggle}
            trackColor={{false: '#D1D5DB', true: '#93C5FD'}}
            thumbColor={quickLaunchVolume ? '#2563EB' : '#F3F4F6'}
            ios_backgroundColor="#D1D5DB"
          />
        </View>
      </View>

      <View style={styles.section}>
        <Text style={[styles.sectionTitle, {color: theme.colors.text}]}>Appearance</Text>
        <View style={styles.themeOptionsContainer}>
          {themeOptions.map((option) => (
            <TouchableOpacity
              key={option.mode}
              style={[
                styles.themeOption,
                themeMode === option.mode && styles.themeOptionActive,
              ]}
              onPress={() => setThemeMode(option.mode)}>
              <MaterialIcons name={option.icon} size={24} color={theme.colors.text} />
              <Text style={styles.themeOptionLabel}>{option.label}</Text>
              {themeMode === option.mode && (
                <MaterialIcons name="check" size={20} color="#2563EB" />
              )}
            </TouchableOpacity>
          ))}
        </View>
        <Text style={[styles.themeHint, {color: theme.colors.notification}]}>
          {themeMode === 'system'
            ? 'System theme will adapt to your device settings'
            : themeMode === 'light'
            ? 'Light theme for a brighter display'
            : 'Dark theme for a darker display'}
        </Text>
      </View>

      <View style={styles.section}>
        <Text style={[styles.sectionTitle, {color: theme.colors.text}]}>Shake Detection</Text>
        <View
          style={[styles.settingItem, {backgroundColor: theme.colors.card, borderColor: theme.colors.border}]}>
          <View style={styles.settingInfo}>
            <MaterialIcons name="shake" size={24} color="#2563EB" />
            <View style={styles.settingTextContainer}>
              <Text style={[styles.settingTitle, {color: theme.colors.text}]}>Shake to Undo</Text>
              <Text style={[styles.settingDescription, {color: theme.colors.notification}]}>
                Shake your device to undo the last action.
              </Text>
            </View>
          </View>
          <Switch
            value={isAccelerometerAvailable}
            onValueChange={() => {}}
            trackColor={{false: '#D1D5DB', true: '#93C5FD'}}
            thumbColor={isAccelerometerAvailable ? '#2563EB' : '#F3F4F6'}
            ios_backgroundColor="#D1D5DB"
            disabled
          />
        </View>
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    padding: 20,
    backgroundColor: '#F9FAFB',
  },
  section: {
    marginBottom: 20,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 10,
  },
  settingItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 14,
    paddingHorizontal: 16,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: '#E5E7EB',
    backgroundColor: '#F9FAFB',
  },
  settingInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
  },
  settingTextContainer: {
    marginLeft: 10,
  },
  settingTitle: {
    fontSize: 16,
    fontWeight: '600',
  },
  settingDescription: {
    fontSize: 13,
    marginTop: 4,
  },
  themeOptionsContainer: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-around',
    marginTop: 10,
  },
  themeOption: {
    width: '30%',
    alignItems: 'center',
    marginVertical: 5,
  },
  themeOptionActive: {
    borderColor: '#2563EB',
    borderWidth: 2,
  },
  themeOptionLabel: {
    fontSize: 14,
    fontWeight: '600',
  },
  themeHint: {
    fontSize: 12,
    marginTop: 4,
  },
  secondarySettingButton: {
    marginTop: 12,
    borderWidth: 1,
    borderRadius: 12,
    paddingVertical: 14,
    paddingHorizontal: 16,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  secondarySettingInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  secondarySettingText: {
    fontSize: 15,
    fontWeight: '600',
  },
});

export default SettingsScreen;
