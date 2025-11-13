import React, {useMemo, useState} from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  TouchableOpacity,
  Linking,
  Alert,
} from 'react-native';
import {useSafeAreaInsets} from 'react-native-safe-area-context';
import {useTheme} from '@react-navigation/native';
import type {Theme} from '@react-navigation/native';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';

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

type TipCategory = 'personal' | 'travel' | 'home' | 'emergency';

interface SafetyTip {
  id: string;
  title: string;
  category: TipCategory;
  summary: string;
  points: string[];
  source?: {label: string; url: string};
  icon: string;
}

const SAFETY_TIPS: SafetyTip[] = [
  {
    id: 'personal_awareness',
    category: 'personal',
    title: 'Stay Aware When Moving Around',
    summary: 'Small habits help you avoid risky situations while you commute or travel alone.',
    points: [
      'Share your live location with a trusted contact when travelling late night.',
      'Keep earbuds volume low so you can still hear your surroundings.',
      'Preload your emergency contacts in the app before you step out.',
    ],
    source: {
      label: 'UN Women – Safety Tips',
      url: 'https://www.unwomen.org/en/news-stories/feature-story/2017/11/ten-tips-for-women-to-stay-safe',
    },
    icon: 'person-pin-circle',
  },
  {
    id: 'travel_planning',
    category: 'travel',
    title: 'Plan Safer Commutes',
    summary: 'Know your route in advance and let someone close track your journey.',
    points: [
      'Check the route preview inside your maps app before booking a cab.',
      'Send the cab details to a family member or a friend.',
      'Use the SOS volume shortcut or shake-to-alert when you feel unsafe.',
    ],
    source: {
      label: 'SafeTNet Travel Advisory',
      url: 'https://example.com/safetynet/secure-travel-guide',
    },
    icon: 'directions-car',
  },
  {
    id: 'home_security',
    category: 'home',
    title: 'Upgrade Your Home Security',
    summary: 'Layered protections make your home difficult to target.',
    points: [
      'Install motion-activated lights around entry points.',
      'Use smart locks and regularly change access codes.',
      'Share geofence alerts with your trusted circle for instant updates.',
    ],
    source: {
      label: 'National Crime Prevention Council',
      url: 'https://www.ncpc.org/resources/home-neighborhood-safety',
    },
    icon: 'home-security',
  },
  {
    id: 'sos_preparedness',
    category: 'emergency',
    title: 'Be Ready for Emergencies',
    summary: 'A simple checklist shortens the time it takes to respond.',
    points: [
      'Keep a printed list of emergency contacts in your wallet.',
      'Prepare a small go-bag with medication, power bank, and IDs.',
      'Practice using the SOS button so you know exactly what happens.',
    ],
    source: {
      label: 'Ready.gov Checklist',
      url: 'https://www.ready.gov/kit',
    },
    icon: 'warning-amber',
  },
];

const FILTERS: {label: string; value: TipCategory | 'all'; icon: string}[] = [
  {label: 'All', value: 'all', icon: 'list'},
  {label: 'Personal', value: 'personal', icon: 'person'},
  {label: 'Travel', value: 'travel', icon: 'flight'},
  {label: 'Home', value: 'home', icon: 'home'},
  {label: 'Emergency', value: 'emergency', icon: 'warning'},
];

const SafetyTipsScreen = () => {
  const insets = useSafeAreaInsets();
  const theme = useTheme();
  const {colors} = theme;
  const isDarkMode = theme.dark;

  const themeTokens = useMemo(
    () => ({
      cardShadowColor: isDarkMode ? 'rgba(15, 23, 42, 0.35)' : '#000000',
      mutedTextColor: isDarkMode ? 'rgba(226, 232, 240, 0.75)' : '#6B7280',
      secondaryTextColor: isDarkMode ? 'rgba(148, 163, 184, 0.85)' : '#9CA3AF',
      softSurfaceColor: isDarkMode ? withAlpha(colors.primary, 0.18) : '#F3F4F6',
      borderColor: withAlpha(colors.border, isDarkMode ? 0.7 : 1),
    }),
    [colors, isDarkMode],
  );

  const styles = useMemo(
    () => createStyles(colors, themeTokens, isDarkMode),
    [colors, themeTokens, isDarkMode],
  );

  const [filter, setFilter] = useState<TipCategory | 'all'>('all');

  const filteredTips = useMemo(() => {
    if (filter === 'all') {
      return SAFETY_TIPS;
    }
    return SAFETY_TIPS.filter((tip) => tip.category === filter);
  }, [filter]);

  const handleOpenSource = (url?: string) => {
    if (!url) {
      return;
    }
    Linking.openURL(url).catch(() => {
      Alert.alert('Unable to open link', 'Please try again later.');
    });
  };

  return (
    <View style={[styles.container, {paddingTop: insets.top}]}>\n      <View style={styles.header}>
        <Text style={styles.title}>Safety Tips</Text>
        <Text style={[styles.subtitle, {color: themeTokens.secondaryTextColor}]}>Browse curated advice for staying safe in different situations.</Text>
      </View>

      <ScrollView
        horizontal
        showsHorizontalScrollIndicator={false}
        contentContainerStyle={styles.filterRow}
        style={styles.filterContainer}>
        {FILTERS.map((item) => {
          const isActive = filter === item.value;
          return (
            <TouchableOpacity
              key={item.value}
              style={[styles.filterChip, isActive && styles.filterChipActive]}
              onPress={() => setFilter(item.value)}
              activeOpacity={0.8}>
              <MaterialIcons
                name={item.icon}
                size={16}
                color={isActive ? colors.primary : themeTokens.secondaryTextColor}
              />
              <Text
                style={[styles.filterChipText, isActive && styles.filterChipTextActive]}>
                {item.label}
              </Text>
            </TouchableOpacity>
          );
        })}
      </ScrollView>

      <ScrollView
        contentContainerStyle={[styles.content, {paddingBottom: insets.bottom + 24}]}
        showsVerticalScrollIndicator={false}>
        {filteredTips.map((tip) => (
          <View key={tip.id} style={styles.card}>
            <View style={styles.cardHeader}>
              <View style={[styles.cardIcon, {backgroundColor: withAlpha(colors.primary, isDarkMode ? 0.3 : 0.15)}]}>
                <MaterialIcons name={tip.icon as any} size={20} color={colors.primary} />
              </View>
              <View style={styles.cardHeaderText}>
                <Text style={styles.cardTitle}>{tip.title}</Text>
                <Text style={[styles.cardSummary, {color: themeTokens.mutedTextColor}]}>{tip.summary}</Text>
              </View>
            </View>

            {tip.points.map((point, index) => (
              <View key={`${tip.id}_point_${index}`} style={styles.pointRow}>
                <MaterialIcons name="check-circle" size={16} color={colors.primary} style={styles.pointIcon} />
                <Text style={styles.pointText}>{point}</Text>
              </View>
            ))}

            {tip.source && (
              <TouchableOpacity
                style={styles.sourceButton}
                onPress={() => handleOpenSource(tip.source?.url)}
                activeOpacity={0.8}>
                <MaterialIcons name="open-in-new" size={16} color={colors.primary} />
                <Text style={[styles.sourceButtonText, {color: colors.primary}]}>Read more · {tip.source.label}</Text>
              </TouchableOpacity>
            )}
          </View>
        ))}

        {filteredTips.length === 0 && (
          <View style={styles.emptyState}>
            <MaterialIcons name="emoji-people" size={48} color={themeTokens.secondaryTextColor} />
            <Text style={styles.emptyStateText}>We are curating more guidance for this category.</Text>
            <Text style={[styles.emptyStateSubtitle, {color: themeTokens.mutedTextColor}]}>Switch to another filter or check back soon for new tips.</Text>
          </View>
        )}
      </ScrollView>
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
      fontSize: 24,
      fontWeight: '700',
      color: colors.text,
      marginBottom: 6,
    },
    subtitle: {
      fontSize: 14,
      lineHeight: 20,
    },
    filterContainer: {
      maxHeight: 54,
    },
    filterRow: {
      paddingHorizontal: 16,
      paddingBottom: 12,
      gap: 12,
      alignItems: 'center',
    },
    filterChip: {
      flexDirection: 'row',
      alignItems: 'center',
      gap: 6,
      paddingHorizontal: 14,
      paddingVertical: 8,
      borderRadius: 999,
      backgroundColor: tokens.softSurfaceColor,
      borderWidth: 1,
      borderColor: tokens.borderColor,
    },
    filterChipActive: {
      backgroundColor: withAlpha(colors.primary, isDarkMode ? 0.25 : 0.15),
      borderColor: colors.primary,
    },
    filterChipText: {
      fontSize: 13,
      fontWeight: '500',
      color: tokens.secondaryTextColor,
    },
    filterChipTextActive: {
      color: colors.primary,
      fontWeight: '600',
    },
    content: {
      paddingHorizontal: 20,
      paddingTop: 8,
      gap: 16,
    },
    card: {
      backgroundColor: colors.card,
      borderRadius: 16,
      padding: 18,
      borderWidth: 1,
      borderColor: tokens.borderColor,
      shadowColor: tokens.cardShadowColor,
      shadowOffset: {width: 0, height: 2},
      shadowOpacity: isDarkMode ? 0.24 : 0.1,
      shadowRadius: isDarkMode ? 6 : 4,
      elevation: isDarkMode ? 4 : 2,
    },
    cardHeader: {
      flexDirection: 'row',
      gap: 12,
      marginBottom: 12,
    },
    cardIcon: {
      width: 40,
      height: 40,
      borderRadius: 20,
      alignItems: 'center',
      justifyContent: 'center',
    },
    cardHeaderText: {
      flex: 1,
    },
    cardTitle: {
      fontSize: 16,
      fontWeight: '700',
      color: colors.text,
      marginBottom: 4,
    },
    cardSummary: {
      fontSize: 13,
      lineHeight: 18,
    },
    pointRow: {
      flexDirection: 'row',
      alignItems: 'flex-start',
      gap: 10,
      marginBottom: 8,
    },
    pointIcon: {
      marginTop: 2,
    },
    pointText: {
      flex: 1,
      fontSize: 13,
      color: colors.text,
      lineHeight: 19,
    },
    sourceButton: {
      flexDirection: 'row',
      alignItems: 'center',
      gap: 6,
      marginTop: 12,
      alignSelf: 'flex-start',
    },
    sourceButtonText: {
      fontSize: 13,
      fontWeight: '600',
    },
    emptyState: {
      alignItems: 'center',
      justifyContent: 'center',
      paddingVertical: 48,
      gap: 12,
    },
    emptyStateText: {
      fontSize: 16,
      fontWeight: '600',
      color: colors.text,
    },
    emptyStateSubtitle: {
      fontSize: 13,
      textAlign: 'center',
    },
  });

export default SafetyTipsScreen;
