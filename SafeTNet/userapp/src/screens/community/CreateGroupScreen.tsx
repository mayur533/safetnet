import React, {useState} from 'react';
import {
  View,
  Text,
  ScrollView,
  TouchableOpacity,
  StyleSheet,
  TextInput,
  FlatList,
  Alert,
  StatusBar,
} from 'react-native';
import {useSafeAreaInsets} from 'react-native-safe-area-context';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useNavigation, useRoute} from '@react-navigation/native';
import {useAuthStore} from '../../stores/authStore';

interface User {
  id: string;
  name: string;
  email: string;
  avatar?: string;
}

const CreateGroupScreen = () => {
  const navigation = useNavigation<any>();
  const route = useRoute();
  const insets = useSafeAreaInsets();
  const user = useAuthStore((state) => state.user);
  const {onGroupCreated} = (route.params as any) || {};

  const [newGroupName, setNewGroupName] = useState('');
  const [newGroupDescription, setNewGroupDescription] = useState('');
  const [selectedUsers, setSelectedUsers] = useState<string[]>([]);

  // Mock users for selection
  const availableUsers: User[] = [
    {id: '1', name: 'John Doe', email: 'john@example.com'},
    {id: '2', name: 'Jane Smith', email: 'jane@example.com'},
    {id: '3', name: 'Mike Johnson', email: 'mike@example.com'},
    {id: '4', name: 'Sarah Williams', email: 'sarah@example.com'},
    {id: '5', name: 'David Brown', email: 'david@example.com'},
  ];

  const handleCreateGroup = () => {
    if (!newGroupName.trim()) {
      Alert.alert('Error', 'Please enter a group name');
      return;
    }

    if (selectedUsers.length === 0) {
      Alert.alert('Error', 'Please select at least one member');
      return;
    }

    const newGroup = {
      id: Date.now().toString(),
      name: newGroupName,
      description: newGroupDescription,
      memberCount: selectedUsers.length + 1,
      isUnread: false,
    };

    if (onGroupCreated) {
      onGroupCreated(newGroup);
    }

    navigation.goBack();
  };

  const toggleUserSelection = (userId: string) => {
    setSelectedUsers((prev) =>
      prev.includes(userId) ? prev.filter((id) => id !== userId) : [...prev, userId],
    );
  };

  const renderUserItem = ({item}: {item: User}) => {
    const isSelected = selectedUsers.includes(item.id);
    return (
      <TouchableOpacity
        style={[styles.userItem, isSelected && styles.userItemSelected]}
        onPress={() => toggleUserSelection(item.id)}
        activeOpacity={0.7}>
        <View style={styles.userAvatar}>
          <Text style={styles.userAvatarText}>{item.name.charAt(0)}</Text>
        </View>
        <View style={styles.userInfo}>
          <Text style={styles.userName}>{item.name}</Text>
          <Text style={styles.userEmail}>{item.email}</Text>
        </View>
        {isSelected && <MaterialIcons name="check-circle" size={24} color="#2563EB" />}
      </TouchableOpacity>
    );
  };

  return (
    <View style={styles.container}>
      <StatusBar barStyle="dark-content" backgroundColor="#FFFFFF" />
      {/* Header */}
      <View style={[styles.header, {paddingTop: insets.top + 8}]}>
        <TouchableOpacity
          style={styles.backButton}
          onPress={() => navigation.goBack()}
          activeOpacity={0.7}>
          <MaterialIcons name="arrow-back" size={24} color="#374151" />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Create New Group</Text>
        <View style={styles.headerRight} />
      </View>

      <ScrollView style={styles.scrollView} contentContainerStyle={styles.scrollContent}>
        <View style={styles.form}>
          <Text style={styles.label}>Group Name *</Text>
          <TextInput
            style={styles.input}
            placeholder="Enter group name"
            value={newGroupName}
            onChangeText={setNewGroupName}
            placeholderTextColor="#9CA3AF"
          />

          <Text style={styles.label}>Description (Optional)</Text>
          <TextInput
            style={[styles.input, styles.textArea]}
            placeholder="Enter group description"
            value={newGroupDescription}
            onChangeText={setNewGroupDescription}
            multiline
            numberOfLines={3}
            placeholderTextColor="#9CA3AF"
          />

          <Text style={styles.label}>Members *</Text>
          <Text style={styles.memberCountText}>
            {selectedUsers.length} member{selectedUsers.length !== 1 ? 's' : ''} selected
          </Text>

          <FlatList
            data={availableUsers}
            keyExtractor={(item) => item.id}
            renderItem={renderUserItem}
            scrollEnabled={false}
            style={styles.usersList}
          />

          <TouchableOpacity
            style={[
              styles.createButton,
              (!newGroupName.trim() || selectedUsers.length === 0) && styles.createButtonDisabled,
            ]}
            onPress={handleCreateGroup}
            disabled={!newGroupName.trim() || selectedUsers.length === 0}
            activeOpacity={0.7}>
            <Text
              style={[
                styles.createButtonText,
                (!newGroupName.trim() || selectedUsers.length === 0) && styles.createButtonTextDisabled,
              ]}>
              Create Group
            </Text>
          </TouchableOpacity>
        </View>
      </ScrollView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFFFFF',
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingBottom: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#E5E7EB',
  },
  backButton: {
    padding: 8,
    width: 40,
  },
  headerTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#111827',
    flex: 1,
    textAlign: 'center',
  },
  headerRight: {
    width: 40,
  },
  scrollView: {
    flex: 1,
  },
  scrollContent: {
    padding: 20,
  },
  form: {
    flex: 1,
  },
  label: {
    fontSize: 14,
    fontWeight: '600',
    color: '#374151',
    marginBottom: 8,
    marginTop: 16,
  },
  input: {
    backgroundColor: '#F9FAFB',
    borderWidth: 1,
    borderColor: '#E5E7EB',
    borderRadius: 8,
    padding: 12,
    fontSize: 16,
    color: '#111827',
  },
  textArea: {
    height: 80,
    textAlignVertical: 'top',
  },
  memberCountText: {
    fontSize: 14,
    color: '#6B7280',
    marginBottom: 12,
  },
  usersList: {
    marginBottom: 20,
  },
  userItem: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 16,
    backgroundColor: '#FFFFFF',
    borderRadius: 12,
    marginBottom: 8,
    borderWidth: 1,
    borderColor: '#E5E7EB',
  },
  userItemSelected: {
    backgroundColor: '#EFF6FF',
    borderColor: '#2563EB',
  },
  userAvatar: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#2563EB',
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 12,
  },
  userAvatarText: {
    color: '#FFFFFF',
    fontWeight: 'bold',
    fontSize: 16,
  },
  userInfo: {
    flex: 1,
  },
  userName: {
    fontSize: 16,
    fontWeight: '600',
    color: '#111827',
  },
  userEmail: {
    fontSize: 14,
    color: '#6B7280',
    marginTop: 2,
  },
  createButton: {
    backgroundColor: '#2563EB',
    paddingVertical: 14,
    borderRadius: 8,
    alignItems: 'center',
    marginTop: 20,
  },
  createButtonDisabled: {
    backgroundColor: '#D1D5DB',
  },
  createButtonText: {
    color: '#FFFFFF',
    fontSize: 16,
    fontWeight: '600',
  },
  createButtonTextDisabled: {
    color: '#9CA3AF',
  },
});

export default CreateGroupScreen;

