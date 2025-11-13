import {Alert, Linking, Platform} from 'react-native';
import {useContactStore} from '../stores/contactStore';
import {requestDirectCall} from './callService';
import {useIncidentStore} from '../stores/incidentStore';
import {checkNetworkStatus} from './networkService';
import {sendSmsDirect} from './smsService';

interface DispatchResult {
  smsInitiated: boolean;
  callInitiated: boolean;
  recipients: string[];
}

const buildSmsUrl = (phones: string[], message: string) => {
  if (phones.length === 0) {
    return null;
  }

  const encodedMessage = encodeURIComponent(message);

  if (Platform.OS === 'ios') {
    const primaryRecipient = phones[0];
    return `sms:${primaryRecipient}&body=${encodedMessage}`;
  }

  const recipients = phones.join(',');
  return `sms:${recipients}?body=${encodedMessage}`;
};

const selectPrimaryContact = (
  contacts: {id: string; type: string; phone: string}[],
  preferredId?: string,
) => {
  if (preferredId) {
    const preferred = contacts.find((contact) => contact.id === preferredId);
    if (preferred) {
      return preferred;
    }
  }

  const emergencyContact = contacts.find((contact) => contact.type === 'Emergency');
  return emergencyContact ?? contacts[0];
};

export const dispatchSOSAlert = async (message: string): Promise<DispatchResult> => {
  const {contacts, primaryContactId} = useContactStore.getState();
  const sanitizedContacts = contacts
    .filter((contact) => contact.phone.trim().length > 0)
    .map((contact) => ({
      id: contact.id,
      phone: contact.phone.trim(),
      type: contact.type,
    }));

  if (sanitizedContacts.length === 0) {
    Alert.alert(
      'No Contacts Available',
      'Add emergency contacts to automatically notify them during an SOS.',
    );
    return {smsInitiated: false, callInitiated: false, recipients: []};
  }

  let smsInitiated = false;
  let callInitiated = false;

  const smsRecipients = sanitizedContacts.map((contact) => contact.phone);
  const smsUrl = buildSmsUrl(smsRecipients, message);
  const networkStatus = await checkNetworkStatus();

  if (smsUrl && networkStatus.isInternetReachable) {
    try {
      const supported = await Linking.canOpenURL(smsUrl);
      if (supported) {
        await Linking.openURL(smsUrl);
        smsInitiated = true;
      } else {
        console.warn('Device cannot open SMS composer.');
      }
    } catch (error) {
      console.warn('Failed to open SMS composer', error);
    }
  }

  if (!smsInitiated) {
    const fallbackSuccess = await sendSmsDirect(smsRecipients, message);
    smsInitiated = fallbackSuccess;
  }

  const primaryContact = selectPrimaryContact(sanitizedContacts, primaryContactId);
  if (primaryContact?.phone) {
    const callResult = await requestDirectCall(primaryContact.phone);
    callInitiated = callResult;
  }

  if (!smsInitiated) {
    Alert.alert(
      'SMS Not Sent',
      'We could not automatically compose the SMS. Please send an emergency message manually.',
    );
  }

  const incidentStore = useIncidentStore.getState();
  incidentStore.addIncident({
    message,
    smsSent: smsInitiated,
    callPlaced: callInitiated,
    callNumber: primaryContact?.phone,
    recipients: smsRecipients,
  });

  return {
    smsInitiated,
    callInitiated,
    recipients: smsRecipients,
  };
};
