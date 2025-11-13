import React, {useState} from 'react';
import {View, Text, ScrollView, TouchableOpacity, RefreshControl} from 'react-native';
import {mockChatMessages} from '../../services/mockData';
import {format} from 'date-fns';

const ChatScreen = () => {
  const [refreshing, setRefreshing] = useState(false);

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
          Messages
        </Text>

        {mockChatMessages.map((message) => (
          <TouchableOpacity
            key={message.id}
            style={{
              backgroundColor: '#FFFFFF',
              borderRadius: 12,
              padding: 16,
              marginBottom: 12,
              flexDirection: 'row',
              alignItems: 'center',
            }}>
            <View
              style={{
                width: 48,
                height: 48,
                backgroundColor: '#2563EB',
                borderRadius: 24,
                alignItems: 'center',
                justifyContent: 'center',
                marginRight: 12,
              }}>
              <Text style={{color: '#FFFFFF', fontWeight: 'bold', fontSize: 18}}>
                {message.userName.charAt(0)}
              </Text>
            </View>
            <View style={{flex: 1}}>
              <View style={{flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4}}>
                <Text style={{color: '#111827', fontWeight: 'bold'}}>{message.userName}</Text>
                {!message.isRead && (
                  <View style={{width: 8, height: 8, backgroundColor: '#2563EB', borderRadius: 4}} />
                )}
              </View>
              <Text style={{color: '#6B7280', fontSize: 14, marginBottom: 4}} numberOfLines={1}>
                {message.message}
              </Text>
              <Text style={{color: '#9CA3AF', fontSize: 12}}>
                {format(message.timestamp, 'MMM d, h:mm a')}
              </Text>
            </View>
          </TouchableOpacity>
        ))}
      </View>
    </ScrollView>
  );
};

export default ChatScreen;
