import React, {useState} from 'react';
import {View, Text, ScrollView, TouchableOpacity, RefreshControl} from 'react-native';

const EmergencyContactScreen = () => {
  const [refreshing, setRefreshing] = useState(false);

  const mockContacts = [
    {id: '1', name: 'Emergency Services', phone: '911', type: 'Emergency'},
    {id: '2', name: 'John Doe', phone: '+1234567890', type: 'Family'},
    {id: '3', name: 'Jane Smith', phone: '+0987654321', type: 'Friend'},
  ];

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
        <View style={{flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16}}>
          <Text style={{fontSize: 24, fontWeight: 'bold', color: '#111827'}}>Emergency Contacts</Text>
          <TouchableOpacity
            style={{backgroundColor: '#2563EB', paddingHorizontal: 16, paddingVertical: 8, borderRadius: 8}}>
            <Text style={{color: '#FFFFFF', fontWeight: '600'}}>+ Add</Text>
          </TouchableOpacity>
        </View>

        {mockContacts.map((contact) => (
          <View
            key={contact.id}
            style={{
              backgroundColor: '#FFFFFF',
              borderRadius: 12,
              padding: 16,
              marginBottom: 12,
            }}>
            <View style={{flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start'}}>
              <View style={{flex: 1}}>
                <Text style={{color: '#111827', fontSize: 18, fontWeight: '600', marginBottom: 4}}>
                  {contact.name}
                </Text>
                <Text style={{color: '#6B7280', fontSize: 14, marginBottom: 8}}>{contact.phone}</Text>
                <View
                  style={{
                    backgroundColor: contact.type === 'Emergency' ? '#FEF2F2' : '#EFF6FF',
                    paddingHorizontal: 8,
                    paddingVertical: 4,
                    borderRadius: 12,
                    alignSelf: 'flex-start',
                  }}>
                  <Text
                    style={{
                      color: contact.type === 'Emergency' ? '#DC2626' : '#2563EB',
                      fontSize: 12,
                      fontWeight: '600',
                    }}>
                    {contact.type}
                  </Text>
                </View>
              </View>
              <TouchableOpacity>
                <Text style={{color: '#2563EB', fontSize: 24}}>📞</Text>
              </TouchableOpacity>
            </View>
          </View>
        ))}
      </View>
    </ScrollView>
  );
};

export default EmergencyContactScreen;
