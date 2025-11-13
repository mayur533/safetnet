import React from 'react';
import {View, Text, ScrollView, TouchableOpacity} from 'react-native';
import {useAuthStore} from '../../stores/authStore';

const ProfileScreen = ({navigation}: any) => {
  const user = useAuthStore((state) => state.user);
  const logout = useAuthStore((state) => state.logout);

  const handleLogout = () => {
    logout();
  };

  return (
    <ScrollView style={{flex: 1, backgroundColor: '#F9FAFB'}}>
      <View style={{backgroundColor: '#2563EB', paddingTop: 48, paddingBottom: 32, paddingHorizontal: 24}}>
        <View style={{alignItems: 'center'}}>
          <View style={{width: 96, height: 96, backgroundColor: '#FFFFFF', borderRadius: 48, alignItems: 'center', justifyContent: 'center', marginBottom: 12}}>
            <Text style={{color: '#2563EB', fontSize: 36, fontWeight: 'bold'}}>
              {user?.name?.charAt(0) || 'U'}
            </Text>
          </View>
          <Text style={{color: '#FFFFFF', fontSize: 24, fontWeight: 'bold', marginBottom: 4}}>
            {user?.name}
          </Text>
          <Text style={{color: '#BFDBFE', fontSize: 14}}>{user?.email}</Text>
          <View style={{flexDirection: 'row', alignItems: 'center', marginTop: 8}}>
            <View style={{width: 8, height: 8, backgroundColor: '#10B981', borderRadius: 4, marginRight: 8}} />
            <Text style={{color: '#86EFAC', fontSize: 12, textTransform: 'capitalize'}}>
              {user?.status}
            </Text>
          </View>
        </View>
      </View>

      <View style={{paddingHorizontal: 24, paddingVertical: 16}}>
        <View style={{backgroundColor: '#FFFFFF', borderRadius: 12, padding: 16, marginBottom: 16}}>
          <Text style={{color: '#111827', fontWeight: 'bold', fontSize: 18, marginBottom: 16}}>
            Profile Information
          </Text>

          <View style={{marginBottom: 12, paddingBottom: 12, borderBottomWidth: 1, borderBottomColor: '#F3F4F6'}}>
            <Text style={{color: '#6B7280', fontSize: 12, marginBottom: 4}}>Full Name</Text>
            <Text style={{color: '#111827', fontWeight: '600'}}>{user?.name}</Text>
          </View>

          <View style={{marginBottom: 12, paddingBottom: 12, borderBottomWidth: 1, borderBottomColor: '#F3F4F6'}}>
            <Text style={{color: '#6B7280', fontSize: 12, marginBottom: 4}}>Email</Text>
            <Text style={{color: '#111827', fontWeight: '600'}}>{user?.email}</Text>
          </View>

          <View style={{marginBottom: 12, paddingBottom: 12, borderBottomWidth: 1, borderBottomColor: '#F3F4F6'}}>
            <Text style={{color: '#6B7280', fontSize: 12, marginBottom: 4}}>Phone</Text>
            <Text style={{color: '#111827', fontWeight: '600'}}>{user?.phone}</Text>
          </View>

          <View>
            <Text style={{color: '#6B7280', fontSize: 12, marginBottom: 4}}>Role</Text>
            <Text style={{color: '#111827', fontWeight: '600', textTransform: 'capitalize'}}>
              {user?.role}
            </Text>
          </View>
        </View>

        <View style={{backgroundColor: '#FFFFFF', borderRadius: 12, marginBottom: 16}}>
          <TouchableOpacity style={{padding: 16, borderBottomWidth: 1, borderBottomColor: '#F3F4F6', flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between'}}>
            <Text style={{color: '#111827', fontWeight: '500'}}>Edit Profile</Text>
            <Text style={{color: '#9CA3AF'}}>›</Text>
          </TouchableOpacity>
          <TouchableOpacity style={{padding: 16, borderBottomWidth: 1, borderBottomColor: '#F3F4F6', flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between'}}>
            <Text style={{color: '#111827', fontWeight: '500'}}>Settings</Text>
            <Text style={{color: '#9CA3AF'}}>›</Text>
          </TouchableOpacity>
          <TouchableOpacity style={{padding: 16, borderBottomWidth: 1, borderBottomColor: '#F3F4F6', flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between'}}>
            <Text style={{color: '#111827', fontWeight: '500'}}>Notifications</Text>
            <Text style={{color: '#9CA3AF'}}>›</Text>
          </TouchableOpacity>
          <TouchableOpacity style={{padding: 16, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between'}}>
            <Text style={{color: '#111827', fontWeight: '500'}}>Help & Support</Text>
            <Text style={{color: '#9CA3AF'}}>›</Text>
          </TouchableOpacity>
        </View>

        <TouchableOpacity
          onPress={handleLogout}
          style={{
            backgroundColor: '#FEF2F2',
            borderRadius: 12,
            padding: 16,
            borderWidth: 1,
            borderColor: '#FECACA',
          }}>
          <Text style={{color: '#DC2626', fontWeight: '600', textAlign: 'center'}}>Logout</Text>
        </TouchableOpacity>
      </View>
    </ScrollView>
  );
};

export default ProfileScreen;


