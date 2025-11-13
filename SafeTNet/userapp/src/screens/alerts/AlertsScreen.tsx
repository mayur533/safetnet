import React, {useMemo, useState} from 'react';
import {
  View,
  Text,
  ScrollView,
  RefreshControl,
  StyleSheet,
  StatusBar,
} from 'react-native';
import {useSafeAreaInsets} from 'react-native-safe-area-context';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useTheme} from '@react-navigation/native';
import type {Theme} from '@react-navigation/native';
import {mockAlerts} from '../../services/mockData';
import {format} from 'date-fns';

interface Alert {
  id: string;
  type: string;
  title: string;
  message: string;
  timestamp: Date;
  read: boolean;
  location?: {lat: number; lng: number};
}

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

type AlertThemeTokens = {
  borderColor: string;
  cardShadowColor: string;
  mutedTextColor: string;
  secondaryTextColor: string;
  iconMutedColor: string;
  emptyIconColor: string;
};

const AlertsScreen = () => {
  const insets = useSafeAreaInsets();
  const theme = useTheme();
  const {colors} = theme;
  const isDarkMode = theme.dark;

  const themeTokens = useMemo<AlertThemeTokens>(() => ({
    borderColor: withAlpha(colors.border, isDarkMode ? 0.7 : 1),
    cardShadowColor: isDarkMode ? 'rgba(15, 23, 42, 0.45)' : '#000000',
    mutedTextColor: isDarkMode ? 'rgba(226, 232, 240, 0.75)' : '#6B7280',
    secondaryTextColor: isDarkMode ? 'rgba(148, 163, 184, 0.85)' : '#9CA3AF',
    iconMutedColor: isDarkMode ? 'rgba(203, 213, 225, 0.85)' : '#6B7280',
    emptyIconColor: isDarkMode ? withAlpha(colors.notification, 0.7) : '#9CA3AF',
  }), [colors, isDarkMode]);

  const styles = useMemo(() => createStyles(colors, themeTokens, isDarkMode), [colors, themeTokens, isDarkMode]);
  const {mutedTextColor, secondaryTextColor, iconMutedColor, emptyIconColor} = themeTokens;

  const [refreshing, setRefreshing] = useState(false);

  const onRefresh = async () => {
    setRefreshing(true);
    await new Promise<void>((resolve) => setTimeout(() => resolve(), 1000));
    setRefreshing(false);
  };

  const getAlertPalette = (type: string) => {
    const baseAccent = (() => {
      switch (type) {
        case 'emergency':
          return '#EF4444';
        case 'geofence':
          return '#2563EB';
        case 'report':
          return '#EAB308';
        default:
          return colors.primary;
      }
    })();

    return {
      background: withAlpha(baseAccent, isDarkMode ? 0.24 : 0.12),
      border: withAlpha(baseAccent, isDarkMode ? 0.45 : 0.2),
      iconBackground: isDarkMode ? withAlpha(baseAccent, 0.65) : baseAccent,
      iconColor: '#FFFFFF',
      textColor: colors.text,
      dotColor: baseAccent,
    };
  };

  const getAlertIcon = (type: string) => {
    switch (type) {
      case 'emergency':
        return 'warning';
      case 'geofence':
        return 'location-on';
      case 'report':
        return 'description';
      default:
        return 'notifications';
    }
  };

  const formatTimeAgo = (date: Date) => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    if (days < 7) return `${days}d ago`;
    return format(date, 'MMM d, yyyy');
  };

  const renderAlert = (alert: Alert) => {
    const palette = getAlertPalette(alert.type);

    return (
      <View
        key={alert.id}
        style={[
          styles.alertCard,
          {
            backgroundColor: palette.background,
            borderColor: palette.border,
            borderLeftWidth: !alert.read ? 4 : 1,
          },
        ]}>
        <View style={styles.alertHeader}>
          <View style={[styles.iconContainer, {backgroundColor: palette.iconBackground}]}>
            <MaterialIcons name={getAlertIcon(alert.type)} size={20} color={palette.iconColor} />
          </View>
          <View style={styles.alertContent}>
            <View style={styles.alertTitleRow}>
              <Text style={[styles.alertTitle, {color: palette.textColor}]} numberOfLines={1}>
                {alert.title}
              </Text>
              {!alert.read && <View style={[styles.unreadDot, {backgroundColor: palette.dotColor}]} />}
            </View>
            <Text style={[styles.alertMessage, {color: palette.textColor}]} numberOfLines={2}>
              {alert.message}
            </Text>
            <Text style={styles.alertTime}>{formatTimeAgo(alert.timestamp)}</Text>
          </View>
        </View>
      </View>
    );
  };

  return (
    <View style={[styles.container, {backgroundColor: colors.background, paddingTop: insets.top}]}>
      <StatusBar barStyle={isDarkMode ? 'light-content' : 'dark-content'} backgroundColor={colors.background} />

      {mockAlerts.length === 0 ? (
        <View style={styles.emptyState}>
          <MaterialIcons name="notifications-none" size={64} color={emptyIconColor} />
          <Text style={styles.emptyStateText}>No alerts yet</Text>
          <Text style={styles.emptyStateSubtext}>You'll see alerts here when they're sent</Text>
        </View>
      ) : (
        <ScrollView
          style={styles.scrollView}
          contentContainerStyle={[styles.scrollContent, {paddingBottom: 24 + insets.bottom}]}
          refreshControl={
            <RefreshControl
              refreshing={refreshing}
              onRefresh={onRefresh}
              tintColor={colors.primary}
              progressBackgroundColor={colors.card}
            />
          }
          showsVerticalScrollIndicator={true}>
          {mockAlerts.map((alert) => renderAlert(alert))}
        </ScrollView>
      )}
    </View>
  );
};

const createStyles = (colors: Theme['colors'], tokens: AlertThemeTokens, isDarkMode: boolean) =>
  StyleSheet.create({
    container: {
      flex: 1,
    },
    scrollView: {
      flex: 1,
    },
    scrollContent: {
      paddingHorizontal: 16,
      paddingTop: 16,
      paddingBottom: 24,
    },
    alertCard: {
      borderRadius: 12,
      padding: 12,
      marginBottom: 10,
      borderWidth: 1,
      shadowColor: tokens.cardShadowColor,
      shadowOffset: {width: 0, height: 1},
      shadowOpacity: isDarkMode ? 0.22 : 0.08,
      shadowRadius: isDarkMode ? 4 : 2,
      elevation: isDarkMode ? 4 : 2,
    },
    alertHeader: {
      flexDirection: 'row',
      alignItems: 'flex-start',
    },
    iconContainer: {
      width: 40,
      height: 40,
      borderRadius: 20,
      alignItems: 'center',
      justifyContent: 'center',
      marginRight: 12,
      backgroundColor: tokens.iconMutedColor,
    },
    alertContent: {
      flex: 1,
    },
    alertTitleRow: {
      flexDirection: 'row',
      alignItems: 'center',
      marginBottom: 4,
    },
    alertTitle: {
      fontSize: 15,
      fontWeight: '600',
      flex: 1,
      marginRight: 8,
      color: colors.text,
    },
    unreadDot: {
      width: 8,
      height: 8,
      borderRadius: 4,
      backgroundColor: colors.primary,
    },
    alertMessage: {
      fontSize: 13,
      lineHeight: 18,
      marginBottom: 6,
      color: colors.text,
    },
    alertTime: {
      fontSize: 11,
      color: tokens.secondaryTextColor,
    },
    emptyState: {
      flex: 1,
      alignItems: 'center',
      justifyContent: 'center',
      paddingHorizontal: 32,
    },
    emptyStateText: {
      fontSize: 18,
      fontWeight: '600',
      color: colors.text,
      marginTop: 16,
    },
    emptyStateSubtext: {
      fontSize: 14,
      color: tokens.mutedTextColor,
      marginTop: 8,
      textAlign: 'center',
    },
  });

export default AlertsScreen;

export default AlertsScreen;
