import React, {useMemo} from 'react';
import {View, Text, StyleSheet, FlatList, TouchableOpacity} from 'react-native';
import {useTheme} from '@react-navigation/native';
import type {Theme} from '@react-navigation/native';
import {useSafeAreaInsets} from 'react-native-safe-area-context';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useIncidentStore} from '../../stores/incidentStore';
import {useSubscription, FREE_CONTACT_LIMIT} from '../../lib/hooks/useSubscription';

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

const FREE_HISTORY_LIMIT = 5;

const IncidentHistoryScreen = () => {
  const theme = useTheme();
  const {colors} = theme;
  const isDarkMode = theme.dark;
  const insets = useSafeAreaInsets();
  const {incidents} = useIncidentStore();
  const {isPremium, requirePremium} = useSubscription();

  const themeTokens = useMemo(
    () => ({
      cardShadowColor: isDarkMode ? 'rgba(15, 23, 42, 0.35)' : '#000000',
      mutedTextColor: isDarkMode ? 'rgba(226, 232, 240, 0.75)' : '#6B7280',
      secondaryTextColor: isDarkMode ? 'rgba(148, 163, 184, 0.85)' : '#9CA3AF',
      borderColor: withAlpha(colors.border, isDarkMode ? 0.7 : 1),
      softSurfaceColor: isDarkMode ? withAlpha(colors.primary, 0.18) : '#F3F4F6',
    }),
    [colors, isDarkMode],
  );

  const styles = useMemo(
    () => createStyles(colors, themeTokens, isDarkMode),
    [colors, themeTokens, isDarkMode],
  );

  const visibleIncidents = useMemo(() => {
    if (isPremium) {
      return incidents;
    }
    return incidents.slice(0, FREE_HISTORY_LIMIT);
  }, [incidents, isPremium]);

  const shouldShowUpgrade = !isPremium && incidents.length > FREE_HISTORY_LIMIT;

  const renderIncident = ({item}: any) => {
    const time = new Date(item.timestamp).toLocaleTimeString();
    const date = new Date(item.timestamp).toLocaleDateString();
    return (
      <View style={styles.incidentCard}>
        <View style={styles.incidentHeader}>
          <View style={[styles.incidentIcon, {backgroundColor: withAlpha(colors.primary, isDarkMode ? 0.25 : 0.15)}]}>
            <MaterialIcons name="sos" size={18} color={colors.primary} />
          </View>
          <View style={styles.incidentHeaderText}>
            <Text style={styles.incidentTitle}>{item.message}</Text>
            <Text style={[styles.incidentTimestamp, {color: themeTokens.secondaryTextColor}]}>
              {date} · {time}
            </Text>
          </View>
        </View>
        <View style={styles.incidentRow}>
          <MaterialIcons name="sms" size={16} color={item.smsSent ? '#10B981' : themeTokens.secondaryTextColor} />
          <Text style={[styles.incidentDetail, {color: item.smsSent ? '#10B981' : themeTokens.secondaryTextColor}]}>SMS {item.smsSent ? 'sent' : 'not sent'}</Text>
        </View>
        <View style={styles.incidentRow}>
          <MaterialIcons name="call" size={16} color={item.callPlaced ? '#10B981' : themeTokens.secondaryTextColor} />
          <Text style={[styles.incidentDetail, {color: item.callPlaced ? '#10B981' : themeTokens.secondaryTextColor}]}>Call {item.callPlaced ? `placed (${item.callNumber ?? 'unknown'})` : 'not placed'}</Text>
        </View>
        <View style={styles.recipientsBox}>
          <Text style={[styles.recipientsLabel, {color: themeTokens.secondaryTextColor}]}>Recipients:</Text>
          <Text style={styles.recipientsValue} numberOfLines={2}>
            {item.recipients.join(', ')}
          </Text>
        </View>
      </View>
    );
  };

  return (
    <View style={[styles.container, {paddingTop: insets.top, paddingBottom: insets.bottom + 16}]}>\n      <View style={styles.header}>
        <Text style={styles.title}>Incident History</Text>
        <Text style={[styles.subtitle, {color: themeTokens.secondaryTextColor}]}>Review your recent SOS alerts and the contacts notified.</Text>
      </View>

      {shouldShowUpgrade && (
        <View style={styles.noticeCard}>
          <MaterialIcons name="workspace-premium" size={20} color={colors.primary} />
          <View style={styles.noticeContent}>
            <Text style={styles.noticeTitle}>Unlock unlimited history</Text>
            <Text style={[styles.noticeDescription, {color: themeTokens.secondaryTextColor}]}>Free users can see the last {FREE_HISTORY_LIMIT} incidents. Upgrade to view your complete alert trail and enable secure cloud backup.</Text>
          </View>
          <TouchableOpacity
            style={styles.noticeButton}
            onPress={() => requirePremium('Unlock unlimited incident history and premium backups.')}
            activeOpacity={0.8}>
            <Text style={styles.noticeButtonText}>Upgrade</Text>
          </TouchableOpacity>
        </View>
      )}

      <FlatList
        data={visibleIncidents}
        keyExtractor={(item) => item.id}
        renderItem={renderIncident}
        contentContainerStyle={styles.listContent}
        ListEmptyComponent={() => (
          <View style={styles.emptyState}>
            <MaterialIcons name="event-note" size={48} color={themeTokens.secondaryTextColor} />
            <Text style={styles.emptyTitle}>No incidents logged yet</Text>
            <Text style={[styles.emptySubtitle, {color: themeTokens.mutedTextColor}]}>Trigger SOS from the home screen to see a record of alerts and notifications here.</Text>
          </View>
        )}
      />
    </View>
  );
};

const createStyles = (colors: Theme['colors'], tokens: any, isDarkMode: boolean) =>
  StyleSheet.create({
    container: {
      flex: 1,
      backgroundColor: colors.background,
    },
    header: {
      paddingHorizontal: 20,
      paddingTop: 12,
      paddingBottom: 16,
    },
    title: {
      fontSize: 22,
      fontWeight: '700',
      color: colors.text,
      marginBottom: 6,
    },
    subtitle: {
      fontSize: 14,
      lineHeight: 20,
    },
    noticeCard: {
      marginHorizontal: 20,
      marginBottom: 16,
      borderRadius: 16,
      padding: 16,
      backgroundColor: tokens.softSurfaceColor,
      borderWidth: 1,
      borderColor: tokens.borderColor,
      flexDirection: 'row',
      alignItems: 'center',
      gap: 12,
    },
    noticeContent: {
      flex: 1,
      gap: 4,
    },
    noticeTitle: {
      fontSize: 15,
      fontWeight: '700',
      color: colors.text,
    },
    noticeDescription: {
      fontSize: 13,
      lineHeight: 18,
    },
    noticeButton: {
      paddingHorizontal: 16,
      paddingVertical: 10,
      borderRadius: 12,
      backgroundColor: colors.primary,
    },
    noticeButtonText: {
      color: '#FFFFFF',
      fontWeight: '600',
      fontSize: 13,
    },
    listContent: {
      paddingHorizontal: 20,
      paddingBottom: 24,
      gap: 16,
    },
    incidentCard: {
      backgroundColor: colors.card,
      borderRadius: 16,
      borderWidth: 1,
      borderColor: tokens.borderColor,
      padding: 16,
      shadowColor: tokens.cardShadowColor,
      shadowOffset: {width: 0, height: 2},
      shadowOpacity: isDarkMode ? 0.24 : 0.1,
      shadowRadius: isDarkMode ? 6 : 4,
      elevation: isDarkMode ? 4 : 2,
      gap: 10,
    },
    incidentHeader: {
      flexDirection: 'row',
      gap: 12,
    },
    incidentIcon: {
      width: 36,
      height: 36,
      borderRadius: 18,
      alignItems: 'center',
      justifyContent: 'center',
    },
    incidentHeaderText: {
      flex: 1,
      gap: 4,
    },
    incidentTitle: {
      fontSize: 15,
      fontWeight: '600',
      color: colors.text,
    },
    incidentTimestamp: {
      fontSize: 12,
    },
    incidentRow: {
      flexDirection: 'row',
      alignItems: 'center',
      gap: 8,
    },
    incidentDetail: {
      fontSize: 13,
    },
    recipientsBox: {
      marginTop: 6,
      padding: 12,
      borderRadius: 12,
      backgroundColor: withAlpha(colors.primary, isDarkMode ? 0.15 : 0.08),
      borderWidth: 1,
      borderColor: withAlpha(colors.primary, isDarkMode ? 0.3 : 0.15),
    },
    recipientsLabel: {
      fontSize: 12,
      fontWeight: '600',
      marginBottom: 4,
    },
    recipientsValue: {
      fontSize: 13,
      color: colors.text,
    },
    emptyState: {
      alignItems: 'center',
      gap: 12,
      paddingVertical: 48,
    },
    emptyTitle: {
      fontSize: 16,
      fontWeight: '600',
      color: colors.text,
    },
    emptySubtitle: {
      fontSize: 13,
      textAlign: 'center',
    },
  });

export default IncidentHistoryScreen;
