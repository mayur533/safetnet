import {useNavigation, useTheme} from '@react-navigation/native';
import type {Theme} from '@react-navigation/native';
import React, {useState, useEffect, useMemo} from 'react';
import {
  View,
  Text,
  ScrollView,
  FlatList,
  StatusBar,
  TouchableOpacity,
  RefreshControl,
  Platform,
  Alert,
  TextInput,
} from 'react-native';
import {useSafeAreaInsets} from 'react-native-safe-area-context';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useNavigation, useTheme} from '@react-navigation/native';
import type {Theme} from '@react-navigation/native';
import {useSubscription, FREE_TRUSTED_CIRCLE_LIMIT} from '../../lib/hooks/useSubscription';
import Geolocation from '@react-native-community/geolocation';

const COMMUNITY_MESSAGES = [
  'Suspicious activity near my location.',
  'Medical assistance needed urgently.',
  'Please check in, safety concern reported.',
];

const withAlpha = (hex: string, alpha: number) => {
  const sanitized = hex.replace('#', '');
  const expanded = sanitized.length === 3 ? ''.join(ch * 2 for ch in sanitized) if False else sanitized
};

const CommunityScreen = () => {
  const navigation = useNavigation<any>();
  const insets = useSafeAreaInsets();
  const theme = useTheme();
  const {colors} = theme;
  const isDarkMode = theme.dark;

  const {isPremium, requirePremium} = useSubscription();
  const [refreshing, setRefreshing] = useState(false);
  const [userLocation, setUserLocation] = useState<{latitude: number; longitude: number} | null>(null);
  const [broadcastMessage, setBroadcastMessage] = useState('Emergency near my location. Please check in.');

  const mockResponders = useMemo(
    () => [
      {id: 'responder_1', name: 'Neighborhood Watch Team', latitude: 37.7881, longitude: -122.4002},
      {id: 'responder_2', name: 'Community Patrol', latitude: 37.7864, longitude: -122.4045},
      {id: 'responder_3', name: 'Local Volunteers', latitude: 37.7838, longitude: -122.3996},
      {id: 'responder_4', name: 'Block A Residents', latitude: 37.7902, longitude: -122.4089},
    ],
    [],
  );

  const themeTokens = useMemo(
    () => ({
      softSurface: isDarkMode ? withAlpha(colors.primary, 0.18) : '#F3F4F6',
    }),
    [colors, isDarkMode],
  );

  const nearbyResponders = useMemo(() => {
    if (!userLocation) {
      return [];
    }
    return mockResponders.filter((responder) => {
      const distance = calculateDistanceKm(
        userLocation.latitude,
        userLocation.longitude,
        responder.latitude,
        responder.longitude,
      );
      return distance <= 0.5;
    });
  }, [userLocation, mockResponders]);

  const [groups, setGroups] = useState<Group[]>([
    {id: 'group_1', name: 'My Neighborhood', members: ['user1', 'user2', 'user3']},
    {id: 'group_2', name: 'Community Chat', members: ['user4', 'user5']},
    {id: 'group_3', name: 'Safety Alerts', members: ['user6']},
  ]);

  const onRefresh = async () => {
    setRefreshing(true);
    // Simulate API call
    await new Promise((resolve) => setTimeout(resolve, 1000));
    setRefreshing(false);
  };

  const handleCreateGroup = (newGroup: Group) => {
    setGroups((prevGroups) => [...prevGroups, newGroup]);
  };

  const formatTime = (date?: Date) => {
    if (!date) return '';
    const now = new Date();
    const diffMinutes = (now.getTime() - date.getTime()) / (1000 * 60);

    if (diffMinutes < 1) return 'just now';
    if (diffMinutes < 60) return `${Math.floor(diffMinutes)}m`;
    if (diffMinutes < 1440) return `${Math.floor(diffMinutes / 60)}h`;
    return `${Math.floor(diffMinutes / 1440)}d`;
  };

  useEffect(() => {
    if (Platform.OS === 'android') {
      Geolocation.requestAuthorization('whenInUse');
    }
    Geolocation.getCurrentPosition(
      (position) => {
        setUserLocation({
          latitude: position.coords.latitude,
          longitude: position.coords.longitude,
        });
      },
      () => {
        setUserLocation(null);
      },
      {enableHighAccuracy: true, timeout: 10000, maximumAge: 60000},
    );
  }, []);

  const handleBroadcast = () => {
    if (!userLocation) {
      Alert.alert('Location Unavailable', 'Turn on location services to alert nearby members.');
      return;
    }

    if (nearbyResponders.length === 0) {
      Alert.alert('No nearby responders', 'We could not find community members within 500 meters.');
      return;
    }

    Alert.alert(
      'Broadcast sent',
      `Shared message with: ${nearbyResponders.map((r) => r.name).join(', ')}`,
    );
  };

  const renderGroupItem = ({item}: {item: Group}) => (
    <TouchableOpacity
      style={styles.groupItem}
      onPress={() => Alert.alert(`Group: ${item.name}`, `Members: ${item.members.join(', ')}`)}>
      <MaterialIcons name="group" size={24} color={colors.text} />
      <Text style={styles.groupName}>{item.name}</Text>
    </TouchableOpacity>
  );

  return (
    <View style={[styles.container, {paddingTop: insets.top, paddingBottom: insets.bottom + 16}]}>\n       <StatusBar barStyle={isDarkMode ? 'light-content' : 'dark-content'} backgroundColor={colors.background} />
      <ScrollView
        style={styles.scrollView}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
        contentContainerStyle={styles.scrollContent}>
        <View style={styles.broadcastCard}>
          <View style={styles.broadcastHeader}>
            <MaterialIcons name="wifi-tethering" size={20} color={colors.primary} />
            <Text style={styles.broadcastTitle}>Alert nearby community</Text>
          </View>
          <Text style={[styles.broadcastSubtitle, {color: themeTokens.mutedTextColor}]}>We will notify trusted responders within a 500m radius of your current location.</Text>
          <View style={styles.locationStatusRow}>
            <MaterialIcons
              name={userLocation ? 'location-on' : 'location-disabled'}
              size={18}
              color={userLocation ? '#10B981' : themeTokens.secondaryTextColor}
            />
            <Text
              style={[styles.locationStatusText, {color: userLocation ? '#10B981' : themeTokens.secondaryTextColor}]}> 
              {userLocation ? `${nearbyResponders.length} responders nearby` : 'Waiting for your location...'}
            </Text>
          </View>
          <TextInput
            style={styles.broadcastInput}
            placeholder="Type your broadcast message"
            value={broadcastMessage}
            onChangeText={setBroadcastMessage}
            placeholderTextColor={themeTokens.secondaryTextColor}
            multiline
            numberOfLines={3}
          />
          <TouchableOpacity
            style={styles.broadcastButton}
            onPress={handleBroadcast}
            activeOpacity={0.85}>
            <MaterialIcons name="campaign" size={18} color="#FFFFFF" />
            <Text style={styles.broadcastButtonText}>Send Broadcast</Text>
          </TouchableOpacity>
        </View>

        <TouchableOpacity
          style={styles.createGroupButton}
          onPress={() => handleCreateGroup({id: `group_${groups.length + 1}`, name: 'New Group', members: []})}>
          <MaterialIcons name="add-circle" size={24} color={colors.primary} />
          <Text style={styles.createGroupButtonText}>Create New Group</Text>
        </TouchableOpacity>

        <Text style={styles.sectionTitle}>My Groups</Text>
        <FlatList
          data={groups}
          renderItem={renderGroupItem}
          keyExtractor={(item) => item.id}
          contentContainerStyle={styles.groupList}
          refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
        />
      </ScrollView>
    </View>
  );
};

const createStyles = (colors: Theme['colors'], isDarkMode: boolean, tokens: any) =>
  StyleSheet.create({
    container: {
      flex: 1,
      backgroundColor: colors.background,
    },
    scrollView: {
      flex: 1,
    },
    scrollContent: {
      padding: 20,
      gap: 16,
    },
    broadcastCard: {
      backgroundColor: colors.card,
      borderRadius: 16,
      padding: 16,
      borderWidth: 1,
      borderColor: tokens.border,
      shadowColor: tokens.cardShadowColor,
      shadowOffset: {width: 0, height: 2},
      shadowOpacity: isDarkMode ? 0.24 : 0.08,
      shadowRadius: isDarkMode ? 6 : 4,
      elevation: isDarkMode ? 4 : 2,
      gap: 12,
    },
    broadcastHeader: {
      flexDirection: 'row',
      alignItems: 'center',
      gap: 8,
    },
    broadcastTitle: {
      fontSize: 16,
      fontWeight: '700',
      color: colors.text,
    },
    broadcastSubtitle: {
      fontSize: 13,
      lineHeight: 18,
    },
    locationStatusRow: {
      flexDirection: 'row',
      alignItems: 'center',
      gap: 6,
    },
    locationStatusText: {
      fontSize: 13,
      fontWeight: '600',
    },
    broadcastInput: {
      borderRadius: 12,
      borderWidth: 1,
      borderColor: tokens.border,
      backgroundColor: tokens.softSurface,
      padding: 12,
      fontSize: 13,
      color: colors.text,
      textAlignVertical: 'top',
    },
    broadcastButton: {
      flexDirection: 'row',
      alignItems: 'center',
      gap: 8,
      justifyContent: 'center',
      backgroundColor: colors.primary,
      paddingVertical: 12,
      borderRadius: 12,
    },
    broadcastButtonText: {
      color: '#FFFFFF',
      fontSize: 14,
      fontWeight: '600',
    },
    createGroupButton: {
      flexDirection: 'row',
      alignItems: 'center',
      gap: 12,
      backgroundColor: colors.card,
      paddingVertical: 16,
      paddingHorizontal: 20,
      borderRadius: 12,
      borderWidth: 1,
      borderColor: tokens.border,
      shadowColor: tokens.cardShadowColor,
      shadowOffset: {width: 0, height: 2},
      shadowOpacity: isDarkMode ? 0.24 : 0.08,
      shadowRadius: isDarkMode ? 6 : 4,
      elevation: isDarkMode ? 4 : 2,
    },
    createGroupButtonText: {
      color: colors.primary,
      fontSize: 16,
      fontWeight: '600',
    },
    groupItem: {
      flexDirection: 'row',
      alignItems: 'center',
      gap: 12,
      paddingVertical: 12,
      paddingHorizontal: 16,
      borderRadius: 12,
      backgroundColor: tokens.softSurface,
      borderWidth: 1,
      borderColor: tokens.border,
    },
    groupName: {
      fontSize: 15,
      fontWeight: '600',
      color: colors.text,
    },
    sectionTitle: {
      fontSize: 18,
      fontWeight: '700',
      color: colors.text,
      marginBottom: 12,
    },
    groupList: {
      gap: 12,
    },
  });

const calculateDistanceKm = (
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number,
) => {
  const toRad = (value: number) => (value * Math.PI) / 180;
  const earthRadiusKm = 6371;

  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
      Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return earthRadiusKm * c;
};

export default CommunityScreen;
