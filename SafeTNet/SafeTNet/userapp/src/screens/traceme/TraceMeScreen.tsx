import React, {useState} from 'react';
import {View, Text, ScrollView, TouchableOpacity, RefreshControl} from 'react-native';
import {useAuthStore} from '../../stores/authStore';

const TraceMeScreen = () => {
  const [refreshing, setRefreshing] = useState(false);
  const user = useAuthStore((state) => state.user);

  const onRefresh = async () => {
    setRefreshing(true);
    await new Promise<void>((resolve) => setTimeout(() => resolve(), 1000));
    setRefreshing(false);
  };

  return (
    <ScrollView
      style={{flex: 1, backgroundColor: '#F9FAFB'}}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}>
      <View style={{paddingHorizontal: 24, paddingVertical: 16}}>
        <Text style={{fontSize: 24, fontWeight: 'bold', color: '#111827', marginBottom: 16}}>
          Trace Me
        </Text>

        <View style={{backgroundColor: '#FFFFFF', borderRadius: 12, padding: 20, marginBottom: 16}}>
          <Text style={{color: '#6B7280', fontSize: 14, marginBottom: 8}}>Current Status</Text>
          <View style={{flexDirection: 'row', alignItems: 'center', marginBottom: 16}}>
            <View style={{width: 12, height: 12, backgroundColor: '#10B981', borderRadius: 6, marginRight: 8}} />
            <Text style={{color: '#111827', fontSize: 18, fontWeight: '600'}}>Location Active</Text>
          </View>
          <Text style={{color: '#6B7280', fontSize: 14, marginBottom: 4}}>User: {user?.name}</Text>
          <Text style={{color: '#6B7280', fontSize: 14}}>Last Updated: Just now</Text>
        </View>

        <View style={{backgroundColor: '#FFFFFF', borderRadius: 12, padding: 20, marginBottom: 16}}>
          <Text style={{color: '#111827', fontSize: 18, fontWeight: '600', marginBottom: 12}}>
            Location Details
          </Text>
          <View style={{marginBottom: 12}}>
            <Text style={{color: '#6B7280', fontSize: 12, marginBottom: 4}}>Latitude</Text>
            <Text style={{color: '#111827', fontSize: 16}}>37.7749° N</Text>
          </View>
          <View style={{marginBottom: 12}}>
            <Text style={{color: '#6B7280', fontSize: 12, marginBottom: 4}}>Longitude</Text>
            <Text style={{color: '#111827', fontSize: 16}}>122.4194° W</Text>
          </View>
          <View>
            <Text style={{color: '#6B7280', fontSize: 12, marginBottom: 4}}>Address</Text>
            <Text style={{color: '#111827', fontSize: 16}}>123 Main St, San Francisco, CA</Text>
          </View>
        </View>

        <TouchableOpacity
          style={{
            backgroundColor: '#2563EB',
            borderRadius: 12,
            padding: 16,
            alignItems: 'center',
            marginBottom: 16,
          }}>
          <Text style={{color: '#FFFFFF', fontSize: 16, fontWeight: '600'}}>Share Location</Text>
        </TouchableOpacity>

        <View style={{backgroundColor: '#FFFFFF', borderRadius: 12, padding: 20}}>
          <Text style={{color: '#111827', fontSize: 18, fontWeight: '600', marginBottom: 12}}>
            Tracking History
          </Text>
          {[1, 2, 3].map((item) => (
            <View
              key={item}
              style={{
                paddingVertical: 12,
                borderBottomWidth: item === 3 ? 0 : 1,
                borderBottomColor: '#F3F4F6',
              }}>
              <Text style={{color: '#111827', fontWeight: '500', marginBottom: 4}}>
                Location Update {item}
              </Text>
              <Text style={{color: '#6B7280', fontSize: 12}}>{item * 10} minutes ago</Text>
            </View>
          ))}
        </View>
      </View>
    </ScrollView>
  );
};

export default TraceMeScreen;
