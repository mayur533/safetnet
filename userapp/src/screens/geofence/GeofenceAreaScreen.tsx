import React, {useMemo, useState} from 'react';
import {View, Text, ScrollView, TouchableOpacity, RefreshControl, Switch, StyleSheet} from 'react-native';
import {mockGeofences} from '../../services/mockData';
import {useSubscription} from '../../lib/hooks/useSubscription';

const GeofenceAreaScreen = () => {
  const {isPremium, requirePremium} = useSubscription();
  const [refreshing, setRefreshing] = useState(false);
  const [geofences, setGeofences] = useState(mockGeofences);

  const onRefresh = async () => {
    setRefreshing(true);
    await new Promise<void>((resolve) => setTimeout(() => resolve(), 1000));
    setRefreshing(false);
  };

  const premiumDisabled = useMemo(() => !isPremium, [isPremium]);

  const toggleGeofence = (id: string) => {
    if (premiumDisabled) {
      requirePremium('Geo-fencing alerts are part of the Premium plan. Upgrade to manage safe zones.');
      return;
    }
    setGeofences(
      geofences.map((geo) => (geo.id === id ? {...geo, isActive: !geo.isActive} : geo))
    );
  };

  return (
    <View style={styles.wrapper}>
      <ScrollView
        style={styles.scroll}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}>
        <View style={styles.inner}>
          <View style={styles.headerRow}>
            <Text style={styles.title}>Geofence Areas</Text>
            <TouchableOpacity
              style={[styles.addButton, premiumDisabled && styles.addButtonDisabled]}
              onPress={() => {
                if (premiumDisabled) {
                  requirePremium('Geo-fencing alerts are part of the Premium plan. Upgrade to manage safe zones.');
                  return;
                }
              }}
              activeOpacity={0.8}
              disabled={premiumDisabled}>
              <Text style={styles.addButtonText}>+ Add</Text>
            </TouchableOpacity>
          </View>

          {geofences.map((geofence) => (
            <View key={geofence.id} style={styles.card}>
              <View style={styles.cardHeader}>
                <View style={styles.cardInfo}>
                  <Text style={styles.cardTitle}>{geofence.name}</Text>
                  <Text style={styles.cardSubtitle}>Radius: {geofence.radius}m</Text>
                  <Text style={styles.cardCoordinates}>
                    📍 {geofence.center.lat.toFixed(4)}, {geofence.center.lng.toFixed(4)}
                  </Text>
                </View>
                <Switch
                  value={geofence.isActive && !premiumDisabled}
                  onValueChange={() => toggleGeofence(geofence.id)}
                  trackColor={{false: '#D1D5DB', true: '#10B981'}}
                  thumbColor={geofence.isActive ? '#FFFFFF' : '#9CA3AF'}
                  disabled={premiumDisabled}
                />
              </View>
              <View style={styles.cardActions}>
                <TouchableOpacity
                  style={[styles.actionButton, styles.actionPrimary, premiumDisabled && styles.actionDisabled]}
                  onPress={() => {
                    if (premiumDisabled) {
                      requirePremium('Upgrade to edit geo-fence zones.');
                    }
                  }}
                  activeOpacity={0.7}
                  disabled={premiumDisabled}>
                  <Text style={[styles.actionText, styles.actionPrimaryText]}>Edit</Text>
                </TouchableOpacity>
                <TouchableOpacity
                  style={[styles.actionButton, styles.actionDanger, premiumDisabled && styles.actionDisabled]}
                  onPress={() => {
                    if (premiumDisabled) {
                      requirePremium('Upgrade to manage geo-fence zones.');
                      return;
                    }
                  }}
                  activeOpacity={0.7}
                  disabled={premiumDisabled}>
                  <Text style={[styles.actionText, styles.actionDangerText]}>Delete</Text>
                </TouchableOpacity>
              </View>
            </View>
          ))}
        </View>
      </ScrollView>

      {premiumDisabled && (
        <View style={styles.overlay} pointerEvents="none">
          <View style={styles.overlayCard}>
            <Text style={styles.overlayTitle}>Premium Feature</Text>
            <Text style={styles.overlaySubtitle}>
              Geo-fencing alerts keep your trusted circle updated when you arrive or leave safe zones. Upgrade to
              unlock this protection.
            </Text>
          </View>
        </View>
      )}
    </View>
  );
};

export default GeofenceAreaScreen;

const styles = StyleSheet.create({
  wrapper: {flex: 1, backgroundColor: '#F9FAFB'},
  scroll: {flex: 1},
  inner: {paddingHorizontal: 24, paddingVertical: 16},
  headerRow: {flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16},
  title: {fontSize: 24, fontWeight: 'bold', color: '#111827'},
  addButton: {backgroundColor: '#2563EB', paddingHorizontal: 16, paddingVertical: 8, borderRadius: 9},
  addButtonDisabled: {backgroundColor: '#9CA3AF'},
  addButtonText: {color: '#FFFFFF', fontWeight: '600'},
  card: {backgroundColor: '#FFFFFF', borderRadius: 12, padding: 16, marginBottom: 12, borderWidth: 1, borderColor: '#E5E7EB'},
  cardHeader: {flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center'},
  cardInfo: {flex: 1},
  cardTitle: {color: '#111827', fontSize: 18, fontWeight: '600', marginBottom: 4},
  cardSubtitle: {color: '#6B7280', fontSize: 14, marginBottom: 4},
  cardCoordinates: {color: '#6B7280', fontSize: 12},
  cardActions: {marginTop: 12, paddingTop: 12, borderTopWidth: 1, borderTopColor: '#F3F4F6', flexDirection: 'row', gap: 8},
  actionButton: {flex: 1, padding: 10, borderRadius: 8, alignItems: 'center', justifyContent: 'center'},
  actionPrimary: {backgroundColor: '#EFF6FF'},
  actionPrimaryText: {color: '#2563EB', fontWeight: '600'},
  actionDanger: {backgroundColor: '#FEF2F2'},
  actionDangerText: {color: '#DC2626', fontWeight: '600'},
  actionText: {fontSize: 14},
  actionDisabled: {opacity: 0.6},
  overlay: {position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, padding: 24, justifyContent: 'flex-end'},
  overlayCard: {
    backgroundColor: 'rgba(17, 24, 39, 0.88)',
    borderRadius: 16,
    padding: 20,
  },
  overlayTitle: {color: '#F9FAFB', fontSize: 18, fontWeight: '700', marginBottom: 8},
  overlaySubtitle: {color: '#E5E7EB', fontSize: 14, lineHeight: 20},
});
