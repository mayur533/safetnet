import {create} from 'zustand';

export type ContactType = 'Family' | 'Emergency' | 'Friend';

export interface EmergencyContact {
  id: string;
  name: string;
  phone: string;
  email?: string;
  type: ContactType;
  relationship?: string;
}

interface ContactState {
  contacts: EmergencyContact[];
  primaryContactId?: string;
  addContact: (contact: Omit<EmergencyContact, 'id'>) => EmergencyContact;
  updateContact: (id: string, updates: Omit<EmergencyContact, 'id'>) => void;
  removeContact: (id: string) => void;
  setPrimaryContact: (id: string) => void;
}

const seedContacts: EmergencyContact[] = [
  {id: '1', name: 'Emergency Services', phone: '100', type: 'Emergency', relationship: 'Police'},
  {id: '2', name: 'Ambulance', phone: '108', type: 'Emergency', relationship: 'Ambulance'},
  {id: '3', name: 'John Doe', phone: '+91 98765 43210', email: 'john.doe@example.com', type: 'Family', relationship: 'Father'},
];

export const useContactStore = create<ContactState>((set, get) => ({
  contacts: seedContacts,
  primaryContactId: seedContacts[0]?.id,
  addContact: (contact) => {
    const newContact: EmergencyContact = {
      id: Date.now().toString(),
      ...contact,
    };
    set((state) => ({contacts: [newContact, ...state.contacts]}));

    if (!get().primaryContactId) {
      set({primaryContactId: newContact.id});
    }

    return newContact;
  },
  updateContact: (id, updates) => {
    set((state) => ({
      contacts: state.contacts.map((contact) =>
        contact.id === id ? {...updates, id} : contact,
      ),
    }));
  },
  removeContact: (id) => {
    set((state) => ({
      contacts: state.contacts.filter((contact) => contact.id !== id),
      primaryContactId:
        state.primaryContactId === id
          ? state.contacts.find((contact) => contact.id !== id)?.id
          : state.primaryContactId,
    }));
  },
  setPrimaryContact: (id) => {
    const exists = get().contacts.some((contact) => contact.id === id);
    if (!exists) {
      return;
    }
    set({primaryContactId: id});
  },
}));
