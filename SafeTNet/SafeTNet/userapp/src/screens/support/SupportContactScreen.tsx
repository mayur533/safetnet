import React from 'react';
import {View, Text, ScrollView, TouchableOpacity} from 'react-native';

const SupportContactScreen = () => {
  const supportContacts = [
    {
      id: '1',
      department: 'Technical Support',
      email: 'support@safetnet.com',
      phone: '+1-800-SAFENET',
      hours: '24/7 Available',
    },
    {
      id: '2',
      department: 'Customer Service',
      email: 'customerservice@safetnet.com',
      phone: '+1-800-123-4567',
      hours: 'Mon-Fri 9AM-6PM',
    },
    {
      id: '3',
      department: 'Emergency Support',
      email: 'emergency@safetnet.com',
      phone: '+1-800-EMERGENCY',
      hours: '24/7 Available',
    },
  ];

  return (
    <ScrollView style={{flex: 1, backgroundColor: '#F9FAFB'}}>
      <View style={{paddingHorizontal: 24, paddingVertical: 16}}>
        <Text style={{fontSize: 24, fontWeight: 'bold', color: '#111827', marginBottom: 16}}>
          Support Contacts
        </Text>

        {supportContacts.map((contact) => (
          <View
            key={contact.id}
            style={{
              backgroundColor: '#FFFFFF',
              borderRadius: 12,
              padding: 20,
              marginBottom: 16,
            }}>
            <Text style={{color: '#111827', fontSize: 20, fontWeight: '600', marginBottom: 12}}>
              {contact.department}
            </Text>
            <View style={{marginBottom: 8}}>
              <Text style={{color: '#6B7280', fontSize: 12, marginBottom: 4}}>Email</Text>
              <TouchableOpacity>
                <Text style={{color: '#2563EB', fontSize: 14}}>{contact.email}</Text>
              </TouchableOpacity>
            </View>
            <View style={{marginBottom: 8}}>
              <Text style={{color: '#6B7280', fontSize: 12, marginBottom: 4}}>Phone</Text>
              <TouchableOpacity>
                <Text style={{color: '#2563EB', fontSize: 14}}>{contact.phone}</Text>
              </TouchableOpacity>
            </View>
            <View>
              <Text style={{color: '#6B7280', fontSize: 12, marginBottom: 4}}>Available Hours</Text>
              <Text style={{color: '#111827', fontSize: 14}}>{contact.hours}</Text>
            </View>
          </View>
        ))}
      </View>
    </ScrollView>
  );
};

export default SupportContactScreen;


