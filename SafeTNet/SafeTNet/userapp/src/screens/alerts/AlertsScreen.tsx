import React, {useState} from 'react';
import {View, Text, ScrollView, TouchableOpacity, RefreshControl} from 'react-native';
import {mockAlerts} from '../../services/mockData';
import {format} from 'date-fns';

const AlertsScreen = () => {
  const [refreshing, setRefreshing] = useState(false);

  const onRefresh = async () => {
    setRefreshing(true);
    await new Promise<void>((resolve) => setTimeout(() => resolve(), 1000));
    setRefreshing(false);
  };

  const getAlertColor = (type: string) => {
    switch (type) {
      case 'emergency':
        return {bg: '#FEF2F2', border: '#FECACA'};
      case 'geofence':
        return {bg: '#EFF6FF', border: '#BFDBFE'};
      case 'report':
        return {bg: '#FEFCE8', border: '#FDE047'};
      default:
        return {bg: '#F9FAFB', border: '#E5E7EB'};
    }
  };

  const getAlertIcon = (type: string) => {
    switch (type) {
      case 'emergency':
        return '🚨';
      case 'geofence':
        return '📍';
      case 'report':
        return '📝';
      default:
        return '📢';
    }
  };

  return (
    <ScrollView
      style={{flex: 1, backgroundColor: '#F9FAFB'}}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}>
      <View style={{paddingHorizontal: 24, paddingVertical: 16}}>
        <Text style={{fontSize: 24, fontWeight: 'bold', color: '#111827', marginBottom: 16}}>
          Alerts
        </Text>

        {mockAlerts.map((alert) => {
          const colors = getAlertColor(alert.type);
          return (
            <TouchableOpacity
              key={alert.id}
              style={{
                marginBottom: 16,
                borderRadius: 12,
                padding: 16,
                borderWidth: 1,
                borderLeftWidth: !alert.read ? 4 : 1,
                backgroundColor: colors.bg,
                borderColor: colors.border,
              }}>
              <View style={{flexDirection: 'row', alignItems: 'flex-start'}}>
                <Text style={{fontSize: 24, marginRight: 12}}>{getAlertIcon(alert.type)}</Text>
                <View style={{flex: 1}}>
                  <View style={{flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 4}}>
                    <Text style={{color: '#111827', fontWeight: 'bold', fontSize: 16, flex: 1}}>
                      {alert.title}
                    </Text>
                    {!alert.read && (
                      <View style={{width: 8, height: 8, backgroundColor: '#EF4444', borderRadius: 4, marginLeft: 8}} />
                    )}
                  </View>
                  <Text style={{color: '#6B7280', fontSize: 14, marginBottom: 8}}>
                    {alert.message}
                  </Text>
                  <Text style={{color: '#9CA3AF', fontSize: 12}}>
                    {format(alert.timestamp, 'MMM d, h:mm a')}
                  </Text>
                  {alert.location && (
                    <Text style={{color: '#9CA3AF', fontSize: 12, marginTop: 4}}>
                      📍 Location available
                    </Text>
                  )}
                </View>
              </View>
            </TouchableOpacity>
          );
        })}
      </View>
    </ScrollView>
  );
};

export default AlertsScreen;
