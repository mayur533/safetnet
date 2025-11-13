import React, {useState} from 'react';
import {View, Text, ScrollView, TouchableOpacity, RefreshControl, Switch} from 'react-native';
import {mockGeofences} from '../../services/mockData';

const GeofenceAreaScreen = () => {
  const [refreshing, setRefreshing] = useState(false);
  const [geofences, setGeofences] = useState(mockGeofences);

  const onRefresh = async () => {
    setRefreshing(true);
    await new Promise<void>((resolve) => setTimeout(() => resolve(), 1000));
    setRefreshing(false);
  };

  const toggleGeofence = (id: string) => {
    setGeofences(
      geofences.map((geo) => (geo.id === id ? {...geo, isActive: !geo.isActive} : geo))
    );
  };

  return (
    <ScrollView
      style={{flex: 1, backgroundColor: '#F9FAFB'}}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}>
      <View style={{paddingHorizontal: 24, paddingVertical: 16}}>
        <View style={{flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16}}>
          <Text style={{fontSize: 24, fontWeight: 'bold', color: '#111827'}}>Geofence Areas</Text>
          <TouchableOpacity
            style={{backgroundColor: '#2563EB', paddingHorizontal: 16, paddingVertical: 8, borderRadius: 8}}>
            <Text style={{color: '#FFFFFF', fontWeight: '600'}}>+ Add</Text>
          </TouchableOpacity>
        </View>

        {geofences.map((geofence) => (
          <View
            key={geofence.id}
            style={{
              backgroundColor: '#FFFFFF',
              borderRadius: 12,
              padding: 16,
              marginBottom: 12,
            }}>
            <View style={{flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center'}}>
              <View style={{flex: 1}}>
                <Text style={{color: '#111827', fontSize: 18, fontWeight: '600', marginBottom: 4}}>
                  {geofence.name}
                </Text>
                <Text style={{color: '#6B7280', fontSize: 14, marginBottom: 4}}>
                  Radius: {geofence.radius}m
                </Text>
                <Text style={{color: '#6B7280', fontSize: 12}}>
                  📍 {geofence.center.lat.toFixed(4)}, {geofence.center.lng.toFixed(4)}
                </Text>
              </View>
              <Switch
                value={geofence.isActive}
                onValueChange={() => toggleGeofence(geofence.id)}
                trackColor={{false: '#D1D5DB', true: '#10B981'}}
                thumbColor={geofence.isActive ? '#FFFFFF' : '#9CA3AF'}
              />
            </View>
            <View
              style={{
                marginTop: 12,
                paddingTop: 12,
                borderTopWidth: 1,
                borderTopColor: '#F3F4F6',
                flexDirection: 'row',
                gap: 8,
              }}>
              <TouchableOpacity style={{flex: 1, backgroundColor: '#EFF6FF', padding: 8, borderRadius: 8}}>
                <Text style={{color: '#2563EB', textAlign: 'center', fontWeight: '600'}}>Edit</Text>
              </TouchableOpacity>
              <TouchableOpacity style={{flex: 1, backgroundColor: '#FEF2F2', padding: 8, borderRadius: 8}}>
                <Text style={{color: '#DC2626', textAlign: 'center', fontWeight: '600'}}>Delete</Text>
              </TouchableOpacity>
            </View>
          </View>
        ))}
      </View>
    </ScrollView>
  );
};

export default GeofenceAreaScreen;
