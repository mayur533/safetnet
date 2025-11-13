import React, {useMemo, useState} from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Linking,
  FlatList,
  Platform,
  Alert,
} from 'react-native';
import MapView, {Marker, PROVIDER_GOOGLE, Region} from 'react-native-maps';
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

type SafePlaceCategory = 'hospital' | 'police' | 'shelter';

interface SafePlace {
  id: string;
  name: string;
  category: SafePlaceCategory;
  phone?: string;
  address: string;
  coordinate: {latitude: number; longitude: number};
}

type MapThemeTokens = {
  cardShadowColor: string;
  mutedTextColor: string;
  secondaryTextColor: string;
  softSurfaceColor: string;
  borderColor: string;
};

const SAFE_PLACES: SafePlace[] = [
  {
    id: 'hospital_1',
    name: 'City Care Hospital',
    category: 'hospital',
    phone: '+1-800-555-1010',
    address: '123 Wellness Ave, Downtown',
    coordinate: {latitude: 37.78755, longitude: -122.40352},
  },
  {
    id: 'police_1',
    name: 'Downtown Police Station',
    category: 'police',
    phone: '+1-800-555-1100',
    address: '45 Justice St, Downtown',
    coordinate: {latitude: 37.79031, longitude: -122.40111},
  },
  {
    id: 'hospital_2',
    name: 'SafeHands Clinic',
    category: 'hospital',
    phone: '+1-800-555-1020',
    address: '678 Serenity Rd, Uptown',
    coordinate: {latitude: 37.78208, longitude: -122.41058},
  },
  {
    id: 'shelter_1',
    name: 'Community Safe Shelter',
    category: 'shelter',
    phone: '+1-800-555-1200',
    address: '89 Hope Blvd, Eastside',
    coordinate: {latitude: 37.78455, longitude: -122.39866},
  },
  {
    id: 'police_2',
    name: 'Harborside Police Outpost',
    category: 'police',
    phone: '+1-800-555-1133',
    address: '210 Harbor Rd, Waterfront',
    coordinate: {latitude: 37.79341, longitude: -122.3958},
  },
];

const INITIAL_REGION: Region = {
  latitude: 37.78755,
  longitude: -122.40352,
  latitudeDelta: 0.03,
  longitudeDelta: 0.03,
};

const NearbyHelpMapScreen = () => {
  const insets = useSafeAreaInsets();
  const theme = useTheme();
  const {colors} = theme;
  const isDarkMode = theme.dark;

  const themeTokens = useMemo<MapThemeTokens>(
    () => ({
      cardShadowColor: isDarkMode ? 'rgba(15, 23, 42, 0.4)' : '#000000',
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

  const [selectedPlace, setSelectedPlace] = useState<SafePlace | null>(SAFE_PLACES[0]);

  const handleCall = (phone?: string) => {
    if (!phone) {
      Alert.alert('No phone available', 'This location does not have a contact number listed.');
      return;
    }
    Linking.openURL(`tel:${phone}`).catch(() => {
      Alert.alert('Unable to dial', 'Please try calling from your dialer.');
    });
  };

  const handleDirections = (place: SafePlace) => {
    const url = Platform.select({
      ios: `http://maps.apple.com/?daddr=${place.coordinate.latitude},${place.coordinate.longitude}`,
      android: `geo:0,0?q=${place.coordinate.latitude},${place.coordinate.longitude}(${encodeURIComponent(place.name)})`,
    });

    if (!url) {
      Alert.alert('Maps unavailable', 'Cannot open maps on this device.');
      return;
    }

    Linking.openURL(url).catch(() => {
      Alert.alert('Unable to open maps', 'Please open your maps app manually.');
    });
  };

  const renderListItem = ({item}: {item: SafePlace}) => {
    const isActive = selectedPlace?.id === item.id;
    return (
      <TouchableOpacity
        style={[styles.listItem, isActive && styles.listItemActive]}
        onPress={() => setSelectedPlace(item)}
        activeOpacity={0.8}>
        <View style={[styles.listIcon, {backgroundColor: getCategoryColor(item.category, colors)}]}>
          <MaterialIcons name={getCategoryIcon(item.category)} size={20} color="#FFFFFF" />
        </View>
        <View style={styles.listContent}>
          <Text style={styles.listTitle} numberOfLines={1}>
            {item.name}
          </Text>
          <Text style={[styles.listSubtitle, {color: themeTokens.mutedTextColor}]} numberOfLines={1}>
            {item.address}
          </Text>
        </View>
        <MaterialIcons name="chevron-right" size={20} color={themeTokens.secondaryTextColor} />
      </TouchableOpacity>
    );
  };

  return (
    <View style={[styles.container, {paddingTop: insets.top, paddingBottom: insets.bottom}]}>\n      <View style={styles.mapContainer}>
        <MapView
          provider={PROVIDER_GOOGLE}
          style={styles.map}
          initialRegion={INITIAL_REGION}
          customMapStyle={isDarkMode ? darkMapStyle : undefined}
          showsUserLocation
          showsMyLocationButton
          pitchEnabled
          showsCompass>
          {SAFE_PLACES.map((place) => (
            <Marker
              key={place.id}
              coordinate={place.coordinate}
              identifier={place.id}
              onPress={() => setSelectedPlace(place)}>
              <View
                style={[
                  styles.marker,
                  {
                    backgroundColor: getCategoryColor(place.category, colors),
                    borderColor:
                      selectedPlace?.id === place.id
                        ? colors.background
                        : withAlpha('#FFFFFF', 0.8),
                  },
                ]}>
                <MaterialIcons name={getCategoryIcon(place.category)} size={18} color="#FFFFFF" />
              </View>
            </Marker>
          ))}
        </MapView>

        {selectedPlace && (
          <View style={styles.selectedCard}>
            <Text style={styles.selectedTitle}>{selectedPlace.name}</Text>
            <Text style={[styles.selectedSubtitle, {color: themeTokens.mutedTextColor}]}> {selectedPlace.address}</Text>
            <View style={styles.selectedActions}>
              <TouchableOpacity
                style={styles.selectedActionButton}
                onPress={() => handleCall(selectedPlace.phone)}
                activeOpacity={0.8}>
                <MaterialIcons name="call" size={18} color={colors.primary} />
                <Text style={[styles.selectedActionText, {color: colors.primary}]}>Call</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.selectedActionButton}
                onPress={() => handleDirections(selectedPlace)}
                activeOpacity={0.8}>
                <MaterialIcons name="navigation" size={18} color={colors.primary} />
                <Text style={[styles.selectedActionText, {color: colors.primary}]}>Directions</Text>
              </TouchableOpacity>
            </View>
          </View>
        )}
      </View>

      <View style={styles.listHeader}>
        <Text style={styles.listHeaderTitle}>Nearby help centers</Text>
        <Text style={[styles.listHeaderSubtitle, {color: themeTokens.secondaryTextColor}]}>Tap a location to focus on the map.</Text>
      </View>

      <FlatList
        data={SAFE_PLACES}
        renderItem={renderListItem}
        keyExtractor={(item) => item.id}
        contentContainerStyle={styles.listContentContainer}
        showsVerticalScrollIndicator={false}
      />
    </View>
  );
};

const getCategoryColor = (category: SafePlaceCategory, colors: Theme['colors']) => {
  switch (category) {
    case 'hospital':
      return '#10B981';
    case 'police':
      return colors.primary;
    case 'shelter':
      return '#F97316';
    default:
      return colors.primary;
  }
};

const getCategoryIcon = (category: SafePlaceCategory) => {
  switch (category) {
    case 'hospital':
      return 'local-hospital';
    case 'police':
      return 'local-police';
    case 'shelter':
      return 'home';
    default:
      return 'location-on';
  }
};

const createStyles = (colors: Theme['colors'], tokens: MapThemeTokens, isDarkMode: boolean) =>
  StyleSheet.create({
    container: {
      flex: 1,
      backgroundColor: colors.background,
    },
    mapContainer: {
      height: '45%',
      position: 'relative',
    },
    map: {
      ...StyleSheet.absoluteFillObject,
    },
    marker: {
      width: 36,
      height: 36,
      borderRadius: 18,
      alignItems: 'center',
      justifyContent: 'center',
      borderWidth: 2,
    },
    selectedCard: {
      position: 'absolute',
      left: 20,
      right: 20,
      bottom: 20,
      backgroundColor: colors.card,
      borderRadius: 16,
      padding: 16,
      borderWidth: 1,
      borderColor: tokens.borderColor,
      shadowColor: tokens.cardShadowColor,
      shadowOffset: {width: 0, height: 4},
      shadowOpacity: isDarkMode ? 0.3 : 0.12,
      shadowRadius: isDarkMode ? 8 : 6,
      elevation: isDarkMode ? 6 : 3,
    },
    selectedTitle: {
      fontSize: 16,
      fontWeight: '700',
      color: colors.text,
      marginBottom: 4,
    },
    selectedSubtitle: {
      fontSize: 13,
      marginBottom: 12,
    },
    selectedActions: {
      flexDirection: 'row',
      gap: 12,
    },
    selectedActionButton: {
      flexDirection: 'row',
      alignItems: 'center',
      gap: 6,
      paddingVertical: 8,
      paddingHorizontal: 14,
      borderRadius: 12,
      backgroundColor: tokens.softSurfaceColor,
      borderWidth: 1,
      borderColor: tokens.borderColor,
    },
    selectedActionText: {
      fontSize: 14,
      fontWeight: '600',
    },
    listHeader: {
      paddingHorizontal: 20,
      paddingVertical: 16,
    },
    listHeaderTitle: {
      fontSize: 18,
      fontWeight: '700',
      color: colors.text,
    },
    listHeaderSubtitle: {
      fontSize: 13,
    },
    listContentContainer: {
      paddingHorizontal: 20,
      paddingBottom: 24,
    },
    listItem: {
      flexDirection: 'row',
      alignItems: 'center',
      paddingVertical: 14,
      paddingHorizontal: 16,
      marginBottom: 12,
      borderRadius: 14,
      backgroundColor: colors.card,
      borderWidth: 1,
      borderColor: tokens.borderColor,
      shadowColor: tokens.cardShadowColor,
      shadowOffset: {width: 0, height: 2},
      shadowOpacity: isDarkMode ? 0.22 : 0.08,
      shadowRadius: isDarkMode ? 6 : 4,
      elevation: isDarkMode ? 4 : 2,
    },
    listItemActive: {
      borderColor: colors.primary,
      backgroundColor: withAlpha(colors.primary, isDarkMode ? 0.2 : 0.1),
    },
    listIcon: {
      width: 40,
      height: 40,
      borderRadius: 20,
      alignItems: 'center',
      justifyContent: 'center',
      marginRight: 14,
    },
    listContent: {
      flex: 1,
    },
    listTitle: {
      fontSize: 15,
      fontWeight: '600',
      color: colors.text,
    },
    listSubtitle: {
      fontSize: 13,
    },
  });

const darkMapStyle = [
  {elementType: 'geometry', stylers: [{color: '#1F2937'}]},
  {elementType: 'labels.text.fill', stylers: [{color: '#E5E7EB'}]},
  {elementType: 'labels.text.stroke', stylers: [{color: '#1F2937'}]},
  {
    featureType: 'poi',
    elementType: 'labels.text.fill',
    stylers: [{color: '#9CA3AF'}],
  },
  {
    featureType: 'road',
    elementType: 'geometry',
    stylers: [{color: '#111827'}],
  },
  {
    featureType: 'road.local',
    elementType: 'labels.text.fill',
    stylers: [{color: '#9CA3AF'}],
  },
  {
    featureType: 'road.highway',
    elementType: 'geometry',
    stylers: [{color: '#374151'}],
  },
  {
    featureType: 'water',
    elementType: 'geometry',
    stylers: [{color: '#1D4ED8'}],
  },
  {
    featureType: 'poi.park',
    elementType: 'geometry',
    stylers: [{color: '#064E3B'}],
  },
];

export default NearbyHelpMapScreen;
