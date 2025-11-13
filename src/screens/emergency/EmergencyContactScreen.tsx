import React, {useMemo, useState} from 'react';
import { View, Text, ScrollView, TouchableOpacity, Alert } from 'react-native';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useSubscription, FREE_CONTACT_LIMIT} from '../../lib/hooks/useSubscription';
import {useContactStore, EmergencyContact} from '../../stores/contactStore';

const EmergencyContactScreen = () => {
  const {isPremium, requirePremium} = useSubscription();
  const [refreshing, setRefreshing] = useState(false);
  const contacts = useContactStore((state) => state.contacts);
  const primaryContactId = useContactStore((state) => state.primaryContactId);
  const addContact = useContactStore((state) => state.addContact);
  const updateContact = useContactStore((state) => state.updateContact);
  const removeContact = useContactStore((state) => state.removeContact);
  const setPrimaryContact = useContactStore((state) => state.setPrimaryContact);
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingContact, setEditingContact] = useState<EmergencyContact | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    phone: '',
    email: '',
    relationship: '',
    type: 'Family' as EmergencyContact['type'],
  });

  const onRefresh = async () => {
    setRefreshing(true);
    await new Promise<void>((resolve) => setTimeout(() => resolve(), 1000));
    setRefreshing(false);
  };

  const maxContacts = useMemo(() => (isPremium ? Infinity : FREE_CONTACT_LIMIT), [isPremium]);
  const reachedFreeLimit = !isPremium && contacts.length >= FREE_CONTACT_LIMIT;

  const handleAddContact = () => {
    if (reachedFreeLimit) {
      requirePremium('Add unlimited emergency contacts with Premium.');
      return;
    }
    setEditingContact(null);
    setFormData({
      name: '',
      phone: '',
      email: '',
      relationship: '',
      type: 'Family',
    });
    setShowAddModal(true);
  };

  const handleEditContact = (contact: EmergencyContact) => {
    setEditingContact(contact);
    setFormData({
      name: contact.name,
      phone: contact.phone,
      email: contact.email || '',
      relationship: contact.relationship || '',
      type: contact.type,
    });
    setShowAddModal(true);
  };

  const handleDeleteContact = (id: string) => {
    Alert.alert(
      'Delete Contact',
      'Are you sure you want to delete this contact?',
      [
        {text: 'Cancel', style: 'cancel'},
        {
          text: 'Delete',
          style: 'destructive',
          onPress: () => {
            removeContact(id);
          },
        },
      ]
    );
  };

  const handleSaveContact = () => {
    if (editingContact) {
      updateContact(editingContact.id, {...formData});
    } else {
      if (contacts.length >= maxContacts) {
        requirePremium('You have reached the contact limit. Upgrade to add more.');
        return;
      }
      addContact({...formData});
    }
    setShowAddModal(false);
    setEditingContact(null);
  };

  const getContactColor = (type: EmergencyContact['type']) => {
    switch (type) {
      case 'Family':
        return '#4CAF50'; // Green
      case 'Emergency':
        return '#F44336'; // Red
      case 'Friend':
        return '#2196F3'; // Blue
      default:
        return '#9E9E9E'; // Gray
    }
  };

  const getContactIcon = (type: EmergencyContact['type']) => {
    switch (type) {
      case 'Family':
        return 'person';
      case 'Emergency':
        return 'emergency';
      case 'Friend':
        return 'group';
      default:
        return 'person';
    }
  };

  return (
    <View style={styles.container}>
      <ScrollView
        refreshControl={
          <TouchableOpacity onPress={onRefresh} style={styles.refreshButton}>
            <MaterialIcons name="refresh" size={24} color="#fff" />
          </TouchableOpacity>
        }
      >
        <View style={styles.header}>
          <Text style={styles.title}>Emergency Contacts</Text>
          <TouchableOpacity style={styles.addButton} onPress={handleAddContact}>
            <MaterialIcons name="add" size={24} color="#fff" />
          </TouchableOpacity>
        </View>

        {contacts.length === 0 ? (
          <View style={styles.emptyState}>
            <MaterialIcons name="contacts" size={60} color="#ccc" />
            <Text style={styles.emptyStateText}>No emergency contacts added yet.</Text>
            <Text style={styles.emptyStateSubtext}>Add your first emergency contact to stay prepared.</Text>
          </View>
        ) : (
          <View style={styles.contactList}>
            {contacts.map((contact) => (
              <View key={contact.id} style={[styles.contactCard, primaryContactId === contact.id && styles.contactCardPrimary]}>
                <View style={styles.contactHeader}>
                  <View style={[styles.contactIconContainer, {backgroundColor: getContactColor(contact.type) + '15'}]}>
                    <MaterialIcons 
                      name={getContactIcon(contact.type)} 
                      size={28} 
                      color={getContactColor(contact.type)} 
                    />
                  </View>
                  <View style={styles.contactInfo}>
                    <Text style={styles.contactName}>{contact.name}</Text>
                    <Text style={styles.contactPhone}>{contact.phone}</Text>
                    {contact.email && <Text style={styles.contactEmail}>{contact.email}</Text>}
                    {contact.relationship && (
                      <Text style={styles.contactRelationship}>{contact.relationship}</Text>
                    )}
                    {primaryContactId === contact.id && (
                      <View style={styles.primaryBadge}>
                        <MaterialIcons name="star" size={14} color="#FACC15" />
                        <Text style={styles.primaryBadgeText}>Priority contact</Text>
                      </View>
                    )}
                  </View>
                  <TouchableOpacity onPress={() => handleEditContact(contact)}>
                    <MaterialIcons name="edit" size={24} color="#333" />
                  </TouchableOpacity>
                  <TouchableOpacity onPress={() => handleDeleteContact(contact.id)}>
                    <MaterialIcons name="delete" size={24} color="#F44336" />
                  </TouchableOpacity>
                </View>
                <View style={styles.contactTypeOptions}>
                  {(['Family', 'Emergency', 'Friend'] as Array<EmergencyContact['type']>).map((type) => (
                    <TouchableOpacity
                      key={type}
                      style={[
                        styles.typeOption,
                        formData.type === type && styles.typeOptionActive,
                      ]}
                      onPress={() => setFormData((prev) => ({ ...prev, type }))}
                    >
                      <Text style={styles.typeOptionText}>{type}</Text>
                    </TouchableOpacity>
                  ))}
                </View>
              </View>
            ))}
          </View>
        )}
      </ScrollView>

      {showAddModal && (
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <Text style={styles.modalTitle}>
              {editingContact ? 'Edit Contact' : 'Add New Contact'}
            </Text>
            <TextInput
              style={styles.input}
              placeholder="Name"
              value={formData.name}
              onChangeText={(text) => setFormData((prev) => ({ ...prev, name: text }))}
            />
            <TextInput
              style={styles.input}
              placeholder="Phone"
              value={formData.phone}
              onChangeText={(text) => setFormData((prev) => ({ ...prev, phone: text }))}
            />
            <TextInput
              style={styles.input}
              placeholder="Email (optional)"
              value={formData.email}
              onChangeText={(text) => setFormData((prev) => ({ ...prev, email: text }))}
            />
            <TextInput
              style={styles.input}
              placeholder="Relationship (optional)"
              value={formData.relationship}
              onChangeText={(text) => setFormData((prev) => ({ ...prev, relationship: text }))}
            />
            <TouchableOpacity style={styles.saveButton} onPress={handleSaveContact}>
              <Text style={styles.saveButtonText}>
                {editingContact ? 'Save Changes' : 'Add Contact'}
              </Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.cancelButton} onPress={() => setShowAddModal(false)}>
              <Text style={styles.cancelButtonText}>Cancel</Text>
            </TouchableOpacity>
          </View>
        </View>
      )}
    </View>
  );
};

const styles = {
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 15,
    backgroundColor: '#fff',
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#333',
  },
  addButton: {
    backgroundColor: '#4CAF50',
    borderRadius: 20,
    width: 40,
    height: 40,
    justifyContent: 'center',
    alignItems: 'center',
  },
  refreshButton: {
    backgroundColor: '#4CAF50',
    borderRadius: 20,
    width: 40,
    height: 40,
    justifyContent: 'center',
    alignItems: 'center',
    position: 'absolute',
    top: 10,
    right: 10,
    zIndex: 1,
  },
  emptyState: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
    backgroundColor: '#fff',
  },
  emptyStateText: {
    fontSize: 18,
    color: '#666',
    marginTop: 10,
  },
  emptyStateSubtext: {
    fontSize: 14,
    color: '#999',
    marginTop: 5,
  },
  contactList: {
    padding: 10,
  },
  contactCard: {
    backgroundColor: '#fff',
    borderRadius: 10,
    padding: 15,
    marginBottom: 10,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 2,
  },
  contactCardPrimary: {
    borderColor: '#4CAF50', // Green
    backgroundColor: '#4CAF5015', // Green with 10% opacity
  },
  contactHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 10,
  },
  contactIconContainer: {
    width: 50,
    height: 50,
    borderRadius: 25,
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 15,
  },
  contactInfo: {
    flex: 1,
  },
  contactName: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#333',
  },
  contactPhone: {
    fontSize: 14,
    color: '#666',
    marginTop: 2,
  },
  contactEmail: {
    fontSize: 14,
    color: '#666',
    marginTop: 2,
  },
  contactRelationship: {
    fontSize: 14,
    color: '#666',
    marginTop: 2,
  },
  contactTypeOptions: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    marginTop: 10,
    paddingHorizontal: 10,
  },
  typeOption: {
    paddingVertical: 8,
    paddingHorizontal: 15,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: '#eee',
  },
  typeOptionActive: {
    backgroundColor: '#4CAF50',
    borderColor: '#4CAF50',
  },
  typeOptionText: {
    fontSize: 14,
    color: '#333',
  },
  modalOverlay: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(0,0,0,0.5)',
    justifyContent: 'center',
    alignItems: 'center',
    zIndex: 10,
  },
  modalContent: {
    backgroundColor: '#fff',
    borderRadius: 10,
    padding: 20,
    width: '80%',
    alignItems: 'center',
  },
  modalTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 20,
    color: '#333',
  },
  input: {
    width: '100%',
    height: 50,
    borderColor: '#eee',
    borderWidth: 1,
    borderRadius: 8,
    paddingHorizontal: 10,
    marginBottom: 15,
    backgroundColor: '#f9f9f9',
  },
  saveButton: {
    backgroundColor: '#4CAF50',
    borderRadius: 8,
    paddingVertical: 12,
    paddingHorizontal: 25,
    width: '100%',
    alignItems: 'center',
    marginTop: 10,
  },
  saveButtonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: 'bold',
  },
  cancelButton: {
    backgroundColor: '#ccc',
    borderRadius: 8,
    paddingVertical: 12,
    paddingHorizontal: 25,
    width: '100%',
    alignItems: 'center',
    marginTop: 10,
  },
  cancelButtonText: {
    color: '#333',
    fontSize: 16,
    fontWeight: 'bold',
  },
  primaryBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    marginTop: 6,
  },
  primaryBadgeText: {
    fontSize: 12,
    fontWeight: '600',
    color: '#666', // Changed from tokens.secondaryTextColor to a default color
  },
};

export default EmergencyContactScreen;
