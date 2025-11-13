import React, {useEffect, useMemo, useRef, useState} from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  PermissionsAndroid,
  Platform,
  Alert,
} from 'react-native';
import {useSafeAreaInsets} from 'react-native-safe-area-context';
import {useTheme} from '@react-navigation/native';
import type {Theme} from '@react-navigation/native';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import Geolocation, {
  GeolocationResponse,
  GeolocationError,
} from '@react-native-community/geolocation';

const withAlpha = (hex: string, alpha: number) => {
  const sanitized = hex.replace('#', '');
  const expanded =
    sanitized.length === 3
      ? sanitized
          .split('')
          .map((char) => char + char)
          .join('')
      : sanitized;
  const bigint = parseInt(expanded, 16);
  const r = (bigint >> 16) & 255;
  const g = (bigint >> 8) & 255;
  const b = bigint & 255;

  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
};

type ShareDurationOption = 15 | 30;

type LiveLocationThemeTokens = {
  cardShadowColor: string;
  mutedTextColor: string;
  secondaryTextColor: string;
  softSurfaceColor: string;
  borderColor: string;
  successColor: string;
  warningColor: string;
};

interface LocationSnapshot {
  timestamp: number;
  coords: {
    latitude: number;
    longitude: number;
    accuracy?: number;
    speed?: number | null;
    heading?: number | null;
  };
}

const LiveLocationScreen = () => {
  const insets = useSafeAreaInsets();
  const theme = useTheme();
  const {colors} = theme;
  const isDarkMode = theme.dark;

  const themeTokens = useMemo<LiveLocationThemeTokens>(
    () => ({
      cardShadowColor: isDarkMode ? 'rgba(15, 23, 42, 0.4)' : '#000000',
      mutedTextColor: isDarkMode ? 'rgba(226, 232, 240, 0.75)' : '#6B7280',
      secondaryTextColor: isDarkMode ? 'rgba(148, 163, 184, 0.85)' : '#9CA3AF',
      softSurfaceColor: isDarkMode ? withAlpha(colors.primary, 0.18) : '#F3F4F6',
      borderColor: withAlpha(colors.border, isDarkMode ? 0.7 : 1),
      successColor: '#10B981',
      warningColor: '#F59E0B',
    }),
    [colors, isDarkMode],
  );

  const styles = useMemo(
    () => createStyles(colors, themeTokens, isDarkMode),
    [colors, themeTokens, isDarkMode],
  );

  const [selectedDuration, setSelectedDuration] = useState<ShareDurationOption>(15);
  const [remainingSeconds, setRemainingSeconds] = useState<number | null>(null);
  const [isSharing, setIsSharing] = useState(false);
  const [lastLocation, setLastLocation] = useState<LocationSnapshot | null>(null);
  const [locationHistory, setLocationHistory] = useState<LocationSnapshot[]>([]);
  const watchIdRef = useRef<number | null>(null);
  const countdownIntervalRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    return () => {
      stopSharing();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!isSharing || remainingSeconds === null) {
      return;
    }

    if (remainingSeconds <= 0) {
      stopSharing();
      Alert.alert('Live Share Ended', 'Your live location session has timed out.');
      return;
    }

    countdownIntervalRef.current = setTimeout(() => {
      setRemainingSeconds((prev) => (prev === null ? prev : prev - 1));
    }, 1000);

    return () => {
      if (countdownIntervalRef.current) {
        clearTimeout(countdownIntervalRef.current);
      }
    };
  }, [isSharing, remainingSeconds]);

  const requestLocationPermissions = async () => {
    if (Platform.OS !== 'android') {
      return true;
    }

    try {
      const permissions = [
        PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
        PermissionsAndroid.PERMISSIONS.ACCESS_COARSE_LOCATION,
      ];

      const results = await PermissionsAndroid.requestMultiple(permissions);
      const denied = Object.entries(results).some(
        ([, value]) => value !== PermissionsAndroid.RESULTS.GRANTED,
      );

      if (denied) {
        Alert.alert(
          'Permission Needed',
          'Location permissions are required for live sharing.',
        );
        return false;
      }

      return true;
    } catch (error) {
      console.warn('Location permission request failed', error);
      return false;
    }
  };

  const startSharing = async () => {
    if (isSharing) {
      return;
    }

    const granted = await requestLocationPermissions();
    if (!granted) {
      return;
    }

    try {
      if (Platform.OS === 'ios') {
        Geolocation.requestAuthorization('whenInUse');
      }

      const durationSeconds = selectedDuration * 60;
      const watchId = Geolocation.watchPosition(
        handleLocationSuccess,
        handleLocationError,
        {
          enableHighAccuracy: true,
          distanceFilter: 10,
          interval: 10000,
          fastestInterval: 5000,
        },
      );

      watchIdRef.current = watchId;
      setIsSharing(true);
      setRemainingSeconds(durationSeconds);
      setLocationHistory([]);
    } catch (error) {
      console.warn('Failed to start location watch', error);
      Alert.alert('Live Share Failed', 'Unable to start location tracking.');
    }
  };

  const stopSharing = () => {
    if (watchIdRef.current !== null) {
      Geolocation.clearWatch(watchIdRef.current);
      watchIdRef.current = null;
    }

    if (countdownIntervalRef.current) {
      clearTimeout(countdownIntervalRef.current);
      countdownIntervalRef.current = null;
    }

    setIsSharing(false);
    setRemainingSeconds(null);
  };

  const handleLocationSuccess = (position: GeolocationResponse) => {
    const snapshot: LocationSnapshot = {
      timestamp: Date.now(),
      coords: {
        latitude: position.coords.latitude,
        longitude: position.coords.longitude,
        accuracy: position.coords.accuracy,
        speed: position.coords.speed,
        heading: position.coords.heading,
      },
    };

    setLastLocation(snapshot);
    setLocationHistory((prev) => [snapshot, ...prev].slice(0, 5));
  };

  const handleLocationError = (error: GeolocationError) => {
    console.warn('Live location error', error);
    Alert.alert('Location Error', error.message);
    stopSharing();
  };

  const formatDuration = (totalSeconds: number | null) => {
    if (totalSeconds === null) {
      return '--:--';
    }
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    return `${minutes.toString().padStart(2, '0')}:${seconds
      .toString()
      .padStart(2, '0')}`;
  };

  const formatCoordinate = (value?: number) => {
    if (typeof value !== 'number') {
      return '--';
    }
    return value.toFixed(6);
  };

  const formatTime = (timestamp: number) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString();
  };

  return (
    <View style={[styles.container, {paddingTop: insets.top, paddingBottom: insets.bottom}]}>\n      <Text style={styles.heading}>Live Location Sharing</Text>

      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Select share duration</Text>
        <View style={styles.durationRow}>
          {[15, 30].map((option) => {
            const typedOption = option as ShareDurationOption;
            const isActive = selectedDuration === typedOption;
            return (
              <TouchableOpacity
                key={option}
                style={[styles.durationChip, isActive && styles.durationChipActive]}
                onPress={() => setSelectedDuration(typedOption)}
                disabled={isSharing}
                activeOpacity={0.7}>
                <Text
                  style={[
                    styles.durationChipText,
                    isActive && styles.durationChipTextActive,
                  ]}>{`${option} minutes`}</Text>
              </TouchableOpacity>
            );
          })}
        </View>

        <View style={styles.statusRow}>
          <MaterialIcons
            name={isSharing ? 'location-on' : 'location-disabled'}
            size={24}
            color={isSharing ? themeTokens.successColor : themeTokens.secondaryTextColor}
          />
          <Text
            style={[styles.statusText, {color: isSharing ? themeTokens.successColor : themeTokens.secondaryTextColor}]}>
            {isSharing ? 'Sharing in progress' : 'Sharing paused'}
          </Text>
        </View>

        <View style={styles.timerRow}>
          <Text style={styles.timerLabel}>Time remaining</Text>
          <Text style={styles.timerValue}>{formatDuration(remainingSeconds)}</Text>
        </View>

        <View style={styles.buttonRow}>
          <TouchableOpacity
            style={[styles.actionButton, isSharing && styles.actionButtonDisabled]}
            onPress={startSharing}
            disabled={isSharing}
            activeOpacity={0.8}>
            <MaterialIcons name="play-arrow" size={22} color="#FFFFFF" />
            <Text style={styles.actionButtonText}>Start Sharing</Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[styles.actionButtonOutline, !isSharing && styles.actionButtonOutlineDisabled]}
            onPress={stopSharing}
            disabled={!isSharing}
            activeOpacity={0.8}>
            <MaterialIcons name="stop" size={20} color={isSharing ? colors.primary : themeTokens.secondaryTextColor} />
            <Text
              style={[
                styles.actionButtonOutlineText,
                {color: isSharing ? colors.primary : themeTokens.secondaryTextColor},
              ]}>Stop</Text>
          </TouchableOpacity>
        </View>
      </View>

      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Current location</Text>
        {lastLocation ? (
          <View style={styles.locationGrid}>
            <View style={styles.locationRow}>
              <Text style={styles.locationLabel}>Latitude</Text>
              <Text style={styles.locationValue}>
                {formatCoordinate(lastLocation.coords.latitude)}
              </Text>
            </View>
            <View style={styles.locationRow}>
              <Text style={styles.locationLabel}>Longitude</Text>
              <Text style={styles.locationValue}>
                {formatCoordinate(lastLocation.coords.longitude)}
              </Text>
            </View>
            <View style={styles.locationRow}>
              <Text style={styles.locationLabel}>Accuracy</Text>
              <Text style={styles.locationValue}>
                {lastLocation.coords.accuracy ? `${lastLocation.coords.accuracy.toFixed(1)} m` : '--'}
              </Text>
            </View>
            <View style={styles.locationRow}>
              <Text style={styles.locationLabel}>Last update</Text>
              <Text style={styles.locationValue}>{formatTime(lastLocation.timestamp)}</Text>
            </View>
          </View>
        ) : (
          <Text style={[styles.emptyHint, {color: themeTokens.mutedTextColor}]}>No location captured yet.</Text>
        )}
      </View>

      <View style={styles.card}>
        <Text style={styles.sectionTitle}>Recent updates</Text>
        {locationHistory.length === 0 ? (
          <Text style={[styles.emptyHint, {color: themeTokens.mutedTextColor}]}>Start sharing to see the update trail.</Text>
        ) : (
          locationHistory.map((item) => (
            <View key={item.timestamp} style={styles.historyRow}>
              <View style={styles.historyIconContainer}>
                <MaterialIcons name="my-location" size={18} color={colors.primary} />
              </View>
              <View style={styles.historyContent}>
                <Text style={styles.historyTitle} numberOfLines={1}>
                  {`${formatCoordinate(item.coords.latitude)}, ${formatCoordinate(item.coords.longitude)}`}
                </Text>
                <Text style={[styles.historySubtitle, {color: themeTokens.secondaryTextColor}]}>Updated at {formatTime(item.timestamp)}</Text>
              </View>
            </View>
          ))
        )}
      </View>
    </View>
  );
};

const createStyles = (colors: Theme['colors'], tokens: LiveLocationThemeTokens, isDarkMode: boolean) =>
  StyleSheet.create({
    container: {
      flex: 1,
      backgroundColor: colors.background,
      paddingHorizontal: 20,
    },
    heading: {
      fontSize: 20,
      fontWeight: '700',
      color: colors.text,
      marginBottom: 16,
    },
    card: {
      backgroundColor: colors.card,
      borderRadius: 16,
      padding: 16,
      marginBottom: 16,
      borderWidth: 1,
      borderColor: tokens.borderColor,
      shadowColor: tokens.cardShadowColor,
      shadowOffset: {width: 0, height: 2},
      shadowOpacity: isDarkMode ? 0.25 : 0.08,
      shadowRadius: isDarkMode ? 6 : 4,
      elevation: isDarkMode ? 4 : 2,
    },
    sectionTitle: {
      fontSize: 16,
      fontWeight: '600',
      color: colors.text,
      marginBottom: 12,
    },
    durationRow: {
      flexDirection: 'row',
      gap: 12,
      marginBottom: 12,
    },
    durationChip: {
      flex: 1,
      borderRadius: 12,
      paddingVertical: 12,
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: tokens.softSurfaceColor,
      borderWidth: 1,
      borderColor: tokens.borderColor,
    },
    durationChipActive: {
      borderColor: colors.primary,
      backgroundColor: withAlpha(colors.primary, isDarkMode ? 0.25 : 0.15),
    },
    durationChipText: {
      fontSize: 14,
      fontWeight: '500',
      color: tokens.mutedTextColor,
    },
    durationChipTextActive: {
      color: colors.primary,
      fontWeight: '600',
    },
    statusRow: {
      flexDirection: 'row',
      alignItems: 'center',
      gap: 8,
      marginBottom: 12,
    },
    statusText: {
      fontSize: 14,
      fontWeight: '600',
    },
    timerRow: {
      flexDirection: 'row',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: 16,
    },
    timerLabel: {
      fontSize: 14,
      color: tokens.mutedTextColor,
    },
    timerValue: {
      fontSize: 20,
      fontWeight: '700',
      color: colors.text,
    },
    buttonRow: {
      flexDirection: 'row',
      gap: 12,
    },
    actionButton: {
      flex: 1,
      flexDirection: 'row',
      alignItems: 'center',
      justifyContent: 'center',
      gap: 6,
      backgroundColor: colors.primary,
      paddingVertical: 14,
      borderRadius: 12,
      elevation: isDarkMode ? 4 : 2,
      shadowColor: colors.primary,
      shadowOffset: {width: 0, height: 2},
      shadowOpacity: isDarkMode ? 0.3 : 0.18,
      shadowRadius: isDarkMode ? 6 : 4,
    },
    actionButtonDisabled: {
      opacity: 0.5,
    },
    actionButtonText: {
      color: '#FFFFFF',
      fontSize: 15,
      fontWeight: '600',
    },
    actionButtonOutline: {
      flex: 1,
      flexDirection: 'row',
      alignItems: 'center',
      justifyContent: 'center',
      gap: 6,
      backgroundColor: 'transparent',
      paddingVertical: 14,
      borderRadius: 12,
      borderWidth: 1,
      borderColor: colors.primary,
    },
    actionButtonOutlineDisabled: {
      borderColor: tokens.secondaryTextColor,
    },
    actionButtonOutlineText: {
      fontSize: 15,
      fontWeight: '600',
    },
    locationGrid: {
      gap: 12,
    },
    locationRow: {
      flexDirection: 'row',
      justifyContent: 'space-between',
      alignItems: 'center',
    },
    locationLabel: {
      fontSize: 14,
      color: tokens.mutedTextColor,
    },
    locationValue: {
      fontSize: 15,
      fontWeight: '600',
      color: colors.text,
    },
    emptyHint: {
      fontSize: 14,
      fontStyle: 'italic',
    },
    historyRow: {
      flexDirection: 'row',
      alignItems: 'center',
      marginBottom: 12,
    },
    historyIconContainer: {
      width: 36,
      height: 36,
      borderRadius: 18,
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: withAlpha(colors.primary, isDarkMode ? 0.3 : 0.15),
      marginRight: 12,
    },
    historyContent: {
      flex: 1,
    },
    historyTitle: {
      fontSize: 14,
      fontWeight: '600',
      color: colors.text,
    },
    historySubtitle: {
      fontSize: 12,
    },
  });

export default LiveLocationScreen;
