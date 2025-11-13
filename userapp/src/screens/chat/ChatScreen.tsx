import React, {useState, useEffect, useRef} from 'react';
import {
  View,
  Text,
  ScrollView,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  KeyboardAvoidingView,
  Platform,
  FlatList,
  Alert,
  StatusBar,
  PermissionsAndroid,
} from 'react-native';
import {useSafeAreaInsets} from 'react-native-safe-area-context';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useRoute, useNavigation} from '@react-navigation/native';
import {useAuthStore} from '../../stores/authStore';
import {format} from 'date-fns';
import {
  launchImageLibrary,
  launchCamera,
  ImagePickerResponse,
  MediaType,
  ImageLibraryOptions,
} from 'react-native-image-picker';
import DocumentPicker, {types} from 'react-native-document-picker';

interface Message {
  id: string;
  text: string;
  userId: string;
  userName: string;
  timestamp: Date;
  isOwn: boolean;
}

interface GroupMember {
  id: string;
  name: string;
  email: string;
  avatar?: string;
  isAdmin?: boolean;
}

interface GroupDetails {
  id: string;
  name: string;
  description?: string;
  members: GroupMember[];
  createdAt: Date;
  createdBy: string;
}

const ChatScreen = () => {
  const route = useRoute();
  const navigation = useNavigation<any>();
  const user = useAuthStore((state) => state.user);
  const insets = useSafeAreaInsets();
  const {groupId, groupName} = route.params as {groupId: string; groupName: string};

  const [messages, setMessages] = useState<Message[]>([]);
  const [messageText, setMessageText] = useState('');
  const [groupDetails, setGroupDetails] = useState<GroupDetails | null>(null);
  const scrollViewRef = useRef<ScrollView>(null);

  // Mock group details
  useEffect(() => {
    const currentUserId = user?.id ? `current-user-${user.id}` : 'current-user-default';
    setGroupDetails({
      id: groupId,
      name: groupName,
      description: 'Local community safety group',
      createdAt: new Date(),
      createdBy: user?.name || 'Admin',
      members: [
        {id: 'member-1', name: 'John Doe', email: 'john@example.com', isAdmin: true},
        {id: 'member-2', name: 'Jane Smith', email: 'jane@example.com'},
        {id: 'member-3', name: 'Mike Johnson', email: 'mike@example.com'},
        {id: 'member-4', name: 'Sarah Williams', email: 'sarah@example.com'},
        {id: currentUserId, name: user?.name || 'You', email: user?.email || 'you@example.com'},
      ],
    });

    // Mock messages
    setMessages([
      {
        id: '1',
        text: 'Welcome to the group!',
        userId: '1',
        userName: 'John Doe',
        timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2),
        isOwn: false,
      },
      {
        id: '2',
        text: 'Thanks for joining!',
        userId: '2',
        userName: 'Jane Smith',
        timestamp: new Date(Date.now() - 1000 * 60 * 60),
        isOwn: false,
      },
    ]);
  }, [groupId, groupName, user]);

  useEffect(() => {
    if (messages.length > 0) {
      scrollViewRef.current?.scrollToEnd({animated: true});
    }
  }, [messages]);

  const handleSendMessage = () => {
    if (!messageText.trim()) return;

    const newMessage: Message = {
      id: Date.now().toString(),
      text: messageText.trim(),
      userId: user?.id || 'current',
      userName: user?.name || 'You',
      timestamp: new Date(),
      isOwn: true,
    };

    setMessages([...messages, newMessage]);
    setMessageText('');
  };


  const handleImagePicker = () => {
    // Use system default picker - directly open gallery
    openImageLibrary();
  };

  const openCamera = async () => {
    try {
      if (Platform.OS === 'android') {
        const granted = await PermissionsAndroid.request(
          PermissionsAndroid.PERMISSIONS.CAMERA,
          {
            title: 'Camera Permission',
            message: 'App needs access to your camera',
            buttonNeutral: 'Ask Me Later',
            buttonNegative: 'Cancel',
            buttonPositive: 'OK',
          },
        );
        if (granted !== PermissionsAndroid.RESULTS.GRANTED) {
          Alert.alert('Permission Denied', 'Camera permission is required');
          return;
        }
      }

      launchCamera(
        {
          mediaType: 'photo',
          quality: 0.8,
          includeBase64: false,
        },
        (response: ImagePickerResponse) => {
          if (response.didCancel) {
            return;
          }
          if (response.errorMessage) {
            Alert.alert('Error', response.errorMessage);
            return;
          }
          if (response.assets && response.assets.length > 0) {
            const asset = response.assets[0];
            handleFileSelected('image', asset.uri || '', asset.fileName || 'image.jpg', asset.fileSize || 0);
          }
        },
      );
    } catch (error) {
      console.error('Camera error:', error);
      Alert.alert('Error', 'Failed to open camera');
    }
  };

  const openImageLibrary = () => {
    try {
      if (!launchImageLibrary) {
        Alert.alert('Error', 'Image picker is not available. Please reinstall the app.');
        return;
      }

      const options: ImageLibraryOptions = {
        mediaType: 'photo' as MediaType,
        quality: 0.8,
        includeBase64: false,
        selectionLimit: 1,
        maxWidth: 1920,
        maxHeight: 1920,
      };

      launchImageLibrary(options, (response: ImagePickerResponse) => {
        if (response.didCancel) {
          return;
        }
        if (response.errorCode) {
          let errorMessage = 'Failed to open image library';
          if (response.errorCode === 'permission') {
            errorMessage = 'Permission denied. Please grant photo library access.';
          } else if (response.errorCode === 'others') {
            errorMessage = response.errorMessage || errorMessage;
          }
          Alert.alert('Error', errorMessage);
          return;
        }
        if (response.errorMessage) {
          Alert.alert('Error', response.errorMessage);
          return;
        }
        if (response.assets && response.assets.length > 0) {
          const asset = response.assets[0];
          if (asset.uri) {
            handleFileSelected(
              'image',
              asset.uri,
              asset.fileName || asset.originalFileName || 'image.jpg',
              asset.fileSize || 0,
            );
          }
        }
      });
    } catch (error: any) {
      console.error('Image picker error:', error);
      Alert.alert('Error', error?.message || 'Failed to open image library. Please try again.');
    }
  };

  const handleFilePicker = async () => {
    try {
      if (!DocumentPicker || !DocumentPicker.pick) {
        Alert.alert('Error', 'File picker is not available. Please reinstall the app.');
        return;
      }

      const result = await DocumentPicker.pick({
        type: [types.allFiles],
        allowMultiSelection: false,
        copyTo: 'cachesDirectory',
      });

      if (result && Array.isArray(result) && result.length > 0) {
        const file = result[0];
        handleFileSelected('file', file.uri || '', file.name || 'file', file.size || 0);
      } else if (result && !Array.isArray(result)) {
        // Handle single file result (for older API)
        const file = result as any;
        handleFileSelected('file', file.uri || '', file.name || 'file', file.size || 0);
      }
    } catch (err: any) {
      if (DocumentPicker && DocumentPicker.isCancel && DocumentPicker.isCancel(err)) {
        // User cancelled - no error
        return;
      }
      if (err.code === 'DOCUMENT_PICKER_CANCELED' || err.message?.includes('cancel')) {
        // User cancelled
        return;
      }
      console.error('File picker error:', err);
      Alert.alert('Error', err?.message || 'Failed to pick file. Please reinstall the app if the issue persists.');
    }
  };

  const handleFileSelected = (type: 'image' | 'file', uri: string, fileName: string, fileSize: number) => {
    // In a real app, you would upload the file and send it as a message
    // For now, we'll just add it as a message
    const fileSizeMB = (fileSize / (1024 * 1024)).toFixed(2);
    const newMessage: Message = {
      id: Date.now().toString(),
      text: type === 'image' ? `📷 Image: ${fileName}` : `📎 File: ${fileName} (${fileSizeMB} MB)`,
      userId: user?.id || 'current',
      userName: user?.name || 'You',
      timestamp: new Date(),
      isOwn: true,
    };

    setMessages([...messages, newMessage]);
    // In production, you would upload the file to a server first
    // and then send a proper message with the file URL
  };

  const renderMessage = ({item}: {item: Message}) => (
    <View
      style={[
        styles.messageContainer,
        item.isOwn ? styles.ownMessageContainer : styles.otherMessageContainer,
      ]}>
      {!item.isOwn && (
        <View style={styles.messageAvatar}>
          <Text style={styles.messageAvatarText}>{item.userName.charAt(0)}</Text>
        </View>
      )}
      <View style={styles.messageBubbleWrapper}>
        <View
          style={[
            styles.messageBubble,
            item.isOwn ? styles.ownMessageBubble : styles.otherMessageBubble,
          ]}>
          {!item.isOwn && <Text style={styles.messageSender}>{item.userName}</Text>}
          <Text style={[styles.messageText, item.isOwn && styles.ownMessageText]}>
            {item.text}
          </Text>
        </View>
        <Text style={[styles.messageTime, item.isOwn && styles.ownMessageTime]}>
          {format(item.timestamp, 'h:mm a')}
        </Text>
      </View>
    </View>
  );


  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      keyboardVerticalOffset={Platform.OS === 'ios' ? 90 : 0}>
      <StatusBar barStyle="dark-content" backgroundColor="#FFFFFF" />
      {/* Group Header */}
      <View style={[styles.groupHeader, {paddingTop: insets.top + 12}]}>
        <TouchableOpacity
          style={styles.backButton}
          onPress={() => navigation.goBack()}
          activeOpacity={0.7}>
          <MaterialIcons name="arrow-back" size={24} color="#374151" />
        </TouchableOpacity>
        <TouchableOpacity
          style={styles.groupHeaderButton}
          onPress={() => navigation.navigate('GroupDetails', {groupId, groupName})}
          activeOpacity={0.7}>
          <View style={styles.groupHeaderAvatar}>
            <MaterialIcons name="groups" size={24} color="#2563EB" />
          </View>
          <View style={styles.groupHeaderInfo}>
            <Text style={styles.groupHeaderName}>{groupName}</Text>
            <Text style={styles.groupHeaderMembers}>
              {groupDetails?.members.length || 0} members
            </Text>
          </View>
          <MaterialIcons name="chevron-right" size={24} color="#6B7280" />
        </TouchableOpacity>
      </View>

      {/* Messages List */}
      <FlatList
        ref={scrollViewRef as any}
        data={messages}
        renderItem={renderMessage}
        keyExtractor={(item) => item.id}
        contentContainerStyle={styles.messagesList}
        inverted={false}
        onContentSizeChange={() => scrollViewRef.current?.scrollToEnd({animated: true})}
      />

      {/* Message Input */}
      <View style={[styles.inputContainer, {paddingBottom: insets.bottom + 8}]}>
        <View style={styles.inputRow}>
          <TouchableOpacity
            style={styles.attachButton}
            onPress={handleFilePicker}
            activeOpacity={0.7}>
            <MaterialIcons name="attach-file" size={24} color="#6B7280" />
          </TouchableOpacity>
          <TouchableOpacity
            style={styles.attachButton}
            onPress={handleImagePicker}
            activeOpacity={0.7}>
            <MaterialIcons name="image" size={24} color="#6B7280" />
          </TouchableOpacity>
          <TextInput
            style={styles.input}
            placeholder="Type a message..."
            value={messageText}
            onChangeText={setMessageText}
            multiline
            placeholderTextColor="#9CA3AF"
          />
          <TouchableOpacity
            style={[styles.sendButton, !messageText.trim() && styles.sendButtonDisabled]}
            onPress={handleSendMessage}
            disabled={!messageText.trim()}
            activeOpacity={0.7}>
            <MaterialIcons
              name="send"
              size={24}
              color={messageText.trim() ? '#FFFFFF' : '#9CA3AF'}
            />
          </TouchableOpacity>
        </View>
      </View>

    </KeyboardAvoidingView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#F9FAFB',
  },
  groupHeader: {
    backgroundColor: '#FFFFFF',
    borderBottomWidth: 1,
    borderBottomColor: '#E5E7EB',
    paddingHorizontal: 16,
    paddingVertical: 12,
    flexDirection: 'row',
    alignItems: 'center',
  },
  backButton: {
    padding: 8,
    marginRight: 8,
  },
  groupHeaderButton: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
  },
  groupHeaderAvatar: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#EFF6FF',
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 12,
  },
  groupHeaderInfo: {
    flex: 1,
  },
  groupHeaderName: {
    fontSize: 16,
    fontWeight: '600',
    color: '#111827',
  },
  groupHeaderMembers: {
    fontSize: 12,
    color: '#6B7280',
    marginTop: 2,
  },
  messagesList: {
    padding: 16,
    paddingBottom: 8,
  },
  messageContainer: {
    flexDirection: 'row',
    marginBottom: 16,
    alignItems: 'flex-start',
  },
  ownMessageContainer: {
    justifyContent: 'flex-end',
  },
  otherMessageContainer: {
    justifyContent: 'flex-start',
  },
  messageAvatar: {
    width: 32,
    height: 32,
    borderRadius: 16,
    backgroundColor: '#2563EB',
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 8,
  },
  messageAvatarText: {
    color: '#FFFFFF',
    fontWeight: 'bold',
    fontSize: 14,
  },
  messageBubbleWrapper: {
    flex: 1,
    alignItems: 'flex-start',
  },
  messageBubble: {
    maxWidth: '75%',
    padding: 12,
    borderRadius: 16,
  },
  ownMessageBubble: {
    backgroundColor: '#2563EB',
    borderBottomRightRadius: 4,
    alignSelf: 'flex-end',
  },
  otherMessageBubble: {
    backgroundColor: '#FFFFFF',
    borderBottomLeftRadius: 4,
    shadowColor: '#000',
    shadowOffset: {width: 0, height: 1},
    shadowOpacity: 0.05,
    shadowRadius: 2,
    elevation: 1,
  },
  messageSender: {
    fontSize: 12,
    fontWeight: '600',
    color: '#2563EB',
    marginBottom: 4,
  },
  messageText: {
    fontSize: 15,
    color: '#111827',
    lineHeight: 20,
  },
  ownMessageText: {
    color: '#FFFFFF',
  },
  messageTime: {
    fontSize: 11,
    color: '#9CA3AF',
    marginTop: 4,
    paddingHorizontal: 4,
  },
  ownMessageTime: {
    alignSelf: 'flex-end',
  },
  inputContainer: {
    backgroundColor: '#FFFFFF',
    borderTopWidth: 1,
    borderTopColor: '#E5E7EB',
    paddingTop: 8,
    paddingHorizontal: 8,
  },
  inputRow: {
    flexDirection: 'row',
    alignItems: 'flex-end',
    paddingHorizontal: 8,
  },
  attachButton: {
    padding: 8,
    marginRight: 4,
  },
  input: {
    flex: 1,
    backgroundColor: '#F9FAFB',
    borderWidth: 1,
    borderColor: '#E5E7EB',
    borderRadius: 20,
    paddingHorizontal: 16,
    paddingVertical: 10,
    maxHeight: 100,
    fontSize: 15,
    color: '#111827',
    marginRight: 8,
    marginLeft: 4,
  },
  sendButton: {
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: '#2563EB',
    alignItems: 'center',
    justifyContent: 'center',
  },
  sendButtonDisabled: {
    backgroundColor: '#F3F4F6',
  },
});

export default ChatScreen;