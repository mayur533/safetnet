import React, {useState, useEffect} from 'react';
import {
  View,
  Text,
  ScrollView,
  TouchableOpacity,
  StyleSheet,
  StatusBar,
  FlatList,
  Modal,
} from 'react-native';
import {useSafeAreaInsets} from 'react-native-safe-area-context';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useNavigation, useRoute} from '@react-navigation/native';
import {useAuthStore} from '../../stores/authStore';

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

const GroupDetailsScreen = () => {
  const navigation = useNavigation<any>();
  const route = useRoute();
  const insets = useSafeAreaInsets();
  const user = useAuthStore((state) => state.user);
  const {groupId, groupName} = (route.params as any) || {};

  const [groupDetails, setGroupDetails] = useState<GroupDetails | null>(null);
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [confirmAction, setConfirmAction] = useState<{
    type: 'leave' | 'remove';
    memberId?: string;
    memberName?: string;
  } | null>(null);

  const isCurrentUserAdmin = () => {
    if (!groupDetails || !user) return false;
    const currentUserId = user.id ? `current-user-${user.id}` : 'current-user-default';
    const currentMember = groupDetails.members.find(
      (m) => m.id === currentUserId || m.email === user.email,
    );
    return currentMember?.isAdmin || false;
  };

  useEffect(() => {
    // Load group details - in real app, fetch from API
    const currentUserId = user?.id ? `current-user-${user.id}` : 'current-user-default';
    setGroupDetails({
      id: groupId,
      name: groupName,
      description: 'Local community safety group',
      createdAt: new Date(),
      createdBy: user?.name || 'Admin',
      members: [
        {id: 'member-1', name: 'John Doe', email: 'john@example.com', isAdmin: false},
        {id: 'member-2', name: 'Jane Smith', email: 'jane@example.com'},
        {id: 'member-3', name: 'Mike Johnson', email: 'mike@example.com'},
        {id: 'member-4', name: 'Sarah Williams', email: 'sarah@example.com'},
        {id: currentUserId, name: user?.name || 'You', email: user?.email || 'you@example.com', isAdmin: true},
      ],
    });
  }, [groupId, groupName, user]);

  const handleLeaveGroup = () => {
    setConfirmAction({type: 'leave'});
    setShowConfirmModal(true);
  };

  const handleAddMember = () => {
    // TODO: Open member selection screen
  };

  const handleRemoveMember = (memberId: string, memberName: string) => {
    setConfirmAction({type: 'remove', memberId, memberName});
    setShowConfirmModal(true);
  };

  const confirmActionHandler = () => {
    if (!confirmAction || !groupDetails) return;

    if (confirmAction.type === 'leave') {
      navigation.goBack();
    } else if (confirmAction.type === 'remove' && confirmAction.memberId) {
      setGroupDetails({
        ...groupDetails,
        members: groupDetails.members.filter((m) => m.id !== confirmAction.memberId),
      });
    }

    setShowConfirmModal(false);
    setConfirmAction(null);
  };

  if (!groupDetails) {
    return (
      <View style={styles.container}>
        <Text>Loading...</Text>
      </View>
    );
  }

  const activeMembersCount = groupDetails.members.length;

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
        <Text style={styles.headerTitle}>Group Details</Text>
        <TouchableOpacity
          style={styles.leaveGroupButton}
          onPress={handleLeaveGroup}
          activeOpacity={0.7}>
          <MaterialIcons name="exit-to-app" size={20} color="#EF4444" />
          <Text style={styles.leaveGroupText}>Leave</Text>
        </TouchableOpacity>
      </View>

      <ScrollView
        style={styles.scrollView}
        contentContainerStyle={styles.scrollContent}
        showsVerticalScrollIndicator={true}>
        {/* Group Icon and Name Section */}
        <View style={styles.groupInfoSection}>
          <View style={styles.groupInfoAvatar}>
            <MaterialIcons name="groups" size={64} color="#2563EB" />
          </View>
          <Text style={styles.groupInfoName}>{groupDetails.name}</Text>
          {groupDetails.description && (
            <Text style={styles.groupInfoDescription}>{groupDetails.description}</Text>
          )}
          <View style={styles.memberStatsContainer}>
            <View style={styles.memberStatItem}>
              <Text style={styles.memberStatValue}>{groupDetails.members.length}</Text>
              <Text style={styles.memberStatLabel}>Members</Text>
            </View>
            <View style={styles.memberStatDivider} />
            <View style={styles.memberStatItem}>
              <Text style={styles.memberStatValue}>{activeMembersCount}</Text>
              <Text style={styles.memberStatLabel}>Active</Text>
            </View>
          </View>
        </View>

        {/* Members Section */}
        <View style={styles.membersSection}>
          <View style={styles.membersHeader}>
            <Text style={styles.membersTitle}>Group Members</Text>
            <TouchableOpacity
              style={styles.addMemberButton}
              onPress={handleAddMember}
              activeOpacity={0.7}>
              <MaterialIcons name="person-add" size={20} color="#2563EB" />
              <Text style={styles.addMemberText}>Add Member</Text>
            </TouchableOpacity>
          </View>

          {groupDetails.members && groupDetails.members.length > 0 ? (
            groupDetails.members.map((item) => {
              const currentUserId = user?.id ? `current-user-${user.id}` : 'current-user-default';
              const isCurrentUser = item.id === currentUserId || item.email === user?.email;
              return (
                <View key={item.id} style={styles.memberItem}>
                  <View style={styles.memberAvatar}>
                    <Text style={styles.memberAvatarText}>{item.name.charAt(0)}</Text>
                  </View>
                  <View style={styles.memberInfo}>
                    <View style={styles.memberNameRow}>
                      <Text style={styles.memberName}>
                        {item.name}
                        {isCurrentUser && ' (You)'}
                      </Text>
                      {item.isAdmin && (
                        <View style={styles.adminBadge}>
                          <Text style={styles.adminBadgeText}>Admin</Text>
                        </View>
                      )}
                    </View>
                    <Text style={styles.memberEmail}>{item.email}</Text>
                  </View>
                  {!isCurrentUser && isCurrentUserAdmin() && (
                    <TouchableOpacity
                      style={styles.removeMemberButton}
                      onPress={() => handleRemoveMember(item.id, item.name)}
                      activeOpacity={0.7}>
                      <MaterialIcons name="remove-circle" size={24} color="#EF4444" />
                    </TouchableOpacity>
                  )}
                </View>
              );
            })
          ) : (
            <Text style={styles.noMembersText}>No members found</Text>
          )}
        </View>
      </ScrollView>

      {/* Modern Confirmation Modal */}
      <Modal
        visible={showConfirmModal}
        transparent
        animationType="fade"
        onRequestClose={() => {
          setShowConfirmModal(false);
          setConfirmAction(null);
        }}>
        <View style={styles.modalOverlay}>
          <View style={styles.confirmModal}>
            <View style={styles.confirmIconContainer}>
              <MaterialIcons
                name={confirmAction?.type === 'leave' ? 'exit-to-app' : 'person-remove'}
                size={48}
                color="#EF4444"
              />
            </View>
            <Text style={styles.confirmTitle}>
              {confirmAction?.type === 'leave' ? 'Leave Group' : 'Remove Member'}
            </Text>
            <Text style={styles.confirmMessage}>
              {confirmAction?.type === 'leave'
                ? 'Are you sure you want to leave this group? You will no longer receive messages.'
                : `Are you sure you want to remove ${confirmAction?.memberName} from this group?`}
            </Text>
            <View style={styles.confirmButtons}>
              <TouchableOpacity
                style={styles.confirmCancelButton}
                onPress={() => {
                  setShowConfirmModal(false);
                  setConfirmAction(null);
                }}
                activeOpacity={0.7}>
                <Text style={styles.confirmCancelText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.confirmActionButton}
                onPress={confirmActionHandler}
                activeOpacity={0.7}>
                <Text style={styles.confirmActionText}>
                  {confirmAction?.type === 'leave' ? 'Leave' : 'Remove'}
                </Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
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
  leaveGroupButton: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#EF4444',
  },
  leaveGroupText: {
    fontSize: 14,
    fontWeight: '600',
    color: '#EF4444',
  },
  scrollView: {
    flex: 1,
  },
  scrollContent: {
    paddingBottom: 20,
  },
  groupInfoSection: {
    alignItems: 'center',
    padding: 24,
    borderBottomWidth: 1,
    borderBottomColor: '#E5E7EB',
  },
  groupInfoAvatar: {
    width: 100,
    height: 100,
    borderRadius: 50,
    backgroundColor: '#EFF6FF',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 16,
  },
  groupInfoName: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#111827',
    marginBottom: 8,
    textAlign: 'center',
  },
  groupInfoDescription: {
    fontSize: 14,
    color: '#6B7280',
    textAlign: 'center',
    marginBottom: 16,
  },
  memberStatsContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 16,
    marginTop: 8,
  },
  memberStatItem: {
    alignItems: 'center',
  },
  memberStatValue: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#2563EB',
  },
  memberStatLabel: {
    fontSize: 12,
    color: '#6B7280',
    marginTop: 4,
  },
  memberStatDivider: {
    width: 1,
    height: 30,
    backgroundColor: '#E5E7EB',
  },
  membersSection: {
    padding: 20,
  },
  membersHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  membersTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#111827',
  },
  addMemberButton: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderRadius: 8,
    backgroundColor: '#EFF6FF',
  },
  addMemberText: {
    fontSize: 14,
    fontWeight: '600',
    color: '#2563EB',
  },
  memberItem: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#F3F4F6',
  },
  memberAvatar: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#2563EB',
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 12,
  },
  memberAvatarText: {
    color: '#FFFFFF',
    fontWeight: 'bold',
    fontSize: 16,
  },
  memberInfo: {
    flex: 1,
  },
  memberNameRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 4,
  },
  memberName: {
    fontSize: 16,
    fontWeight: '600',
    color: '#111827',
  },
  adminBadge: {
    backgroundColor: '#DCFCE7',
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 4,
  },
  adminBadgeText: {
    fontSize: 10,
    fontWeight: '600',
    color: '#16A34A',
  },
  memberEmail: {
    fontSize: 14,
    color: '#6B7280',
  },
  removeMemberButton: {
    padding: 4,
  },
  noMembersText: {
    fontSize: 14,
    color: '#6B7280',
    textAlign: 'center',
    paddingVertical: 20,
  },
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.6)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  },
  confirmModal: {
    backgroundColor: '#FFFFFF',
    borderRadius: 16,
    padding: 24,
    width: '100%',
    maxWidth: 400,
    alignItems: 'center',
  },
  confirmIconContainer: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: '#FEE2E2',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 16,
  },
  confirmTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#111827',
    marginBottom: 12,
    textAlign: 'center',
  },
  confirmMessage: {
    fontSize: 15,
    color: '#6B7280',
    textAlign: 'center',
    marginBottom: 24,
    lineHeight: 22,
  },
  confirmButtons: {
    flexDirection: 'row',
    gap: 12,
    width: '100%',
  },
  confirmCancelButton: {
    flex: 1,
    paddingVertical: 12,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#E5E7EB',
    alignItems: 'center',
  },
  confirmCancelText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#374151',
  },
  confirmActionButton: {
    flex: 1,
    paddingVertical: 12,
    borderRadius: 8,
    backgroundColor: '#EF4444',
    alignItems: 'center',
  },
  confirmActionText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#FFFFFF',
  },
});

export default GroupDetailsScreen;

