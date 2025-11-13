import React from 'react';
import {View, Text, ScrollView} from 'react-native';

const AreaMapScreen = () => {
  return (
    <ScrollView style={{flex: 1, backgroundColor: '#F9FAFB'}}>
      <View style={{paddingHorizontal: 24, paddingVertical: 16}}>
        <Text style={{fontSize: 24, fontWeight: 'bold', color: '#111827', marginBottom: 16}}>
          Area Map
        </Text>
        <View
          style={{
            backgroundColor: '#FFFFFF',
            borderRadius: 12,
            padding: 32,
            alignItems: 'center',
            justifyContent: 'center',
            height: 384,
          }}>
          <Text style={{fontSize: 48, marginBottom: 16}}>📍</Text>
          <Text style={{color: '#111827', fontWeight: '600', fontSize: 18, marginBottom: 8}}>
            Maps View
          </Text>
          <Text style={{color: '#6B7280', textAlign: 'center'}}>
            Map integration will be added here{'\n'}
            (react-native-maps)
          </Text>
        </View>
        <View style={{backgroundColor: '#EFF6FF', borderRadius: 12, padding: 16, marginTop: 16}}>
          <Text style={{color: '#1E3A8A', fontWeight: '600', marginBottom: 8}}>Mock Geofences</Text>
          <Text style={{color: '#1E40AF', fontSize: 14, marginBottom: 4}}>📍 Downtown Area - Active</Text>
          <Text style={{color: '#1E40AF', fontSize: 14, marginBottom: 4}}>📍 University Campus - Active</Text>
          <Text style={{color: '#1E40AF', fontSize: 14}}>📍 Shopping Mall - Inactive</Text>
        </View>
      </View>
    </ScrollView>
  );
};

export default AreaMapScreen;


