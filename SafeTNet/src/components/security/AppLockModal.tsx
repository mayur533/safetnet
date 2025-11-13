import React, {useMemo, useState} from 'react';
import {
  Modal,
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  TextInput,
  KeyboardAvoidingView,
  Platform,
} from 'react-native';
import {useTheme} from '@react-navigation/native';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useAppLockStore} from '../../stores/appLockStore';

const withAlpha = (hex: string, alpha: number) => {
  const sanitized = hex.replace('#', '');
  const expanded =
    sanitized.length === 3
      ? sanitized
          .split('')
          .map((char) => char + char)
          .join('')
      : sanitized;
  const bigint = parseInt(expanded, 16);
  const r = (bigint >> 16) & 255;
  const g = (bigint >> 8) & 255;
  const b = bigint & 255;

  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
};

const AppLockModal = () => {
  const theme = useTheme();
  const {colors} = theme;
  const modal = useAppLockStore((state) => state.modal);
  const lockType = useAppLockStore((state) => state.lockType);
  const completeSetup = useAppLockStore((state) => state.completeSetup);
  const unlock = useAppLockStore((state) => state.unlock);
  const dismissModal = useAppLockStore((state) => state.dismissModal);
  const verifyForDisable = useAppLockStore((state) => state.verifyForDisable);
  const changePasscode = useAppLockStore((state) => state.changePasscode);
  const passcode = useAppLockStore((state) => state.passcode);

  const [setupType, setSetupType] = useState<'numeric' | 'alphanumeric'>('numeric');
  const [setupPasscode, setSetupPasscode] = useState('');
  const [setupConfirm, setSetupConfirm] = useState('');
  const [setupError, setSetupError] = useState<string | null>(null);

  const [unlockInput, setUnlockInput] = useState('');
  const [unlockError, setUnlockError] = useState<string | null>(null);

  const [disablePasscode, setDisablePasscode] = useState('');
  const [disableError, setDisableError] = useState<string | null>(null);

  const [changeCurrent, setChangeCurrent] = useState('');
  const [changeType, setChangeType] = useState<'numeric' | 'alphanumeric'>(lockType);
  const [changeNew, setChangeNew] = useState('');
  const [changeConfirm, setChangeConfirm] = useState('');
  const [changeError, setChangeError] = useState<string | null>(null);

  const isVisible = modal.type !== null;

  const resetFields = () => {
    setSetupPasscode('');
    setSetupConfirm('');
    setSetupError(null);
    setUnlockInput('');
    setUnlockError(null);
    setDisablePasscode('');
    setDisableError(null);
    setChangeCurrent('');
    setChangeNew('');
    setChangeConfirm('');
    setChangeError(null);
  };

  const closeModal = () => {
    resetFields();
    dismissModal();
  };

  const handleSetup = async () => {
    if (setupPasscode !== setupConfirm) {
      setSetupError('Passcodes do not match.');
      return;
    }
    try {
      await completeSetup(setupPasscode, setupType);
      resetFields();
    } catch (error: any) {
      setSetupError(error?.message ?? 'Unable to save passcode.');
    }
  };

  const handleUnlock = () => {
    const success = unlock(unlockInput);
    if (!success) {
      setUnlockError('Incorrect passcode. Try again.');
    } else {
      resetFields();
    }
  };

  const handleDisable = async () => {
    const success = await verifyForDisable(disablePasscode);
    if (!success) {
      setDisableError('Incorrect passcode.');
    } else {
      resetFields();
    }
  };

  const handleChangePasscode = async () => {
    if (changeNew !== changeConfirm) {
      setChangeError('New passcodes do not match.');
      return;
    }
    try {
      const success = await changePasscode(changeCurrent, changeNew, changeType);
      if (!success) {
        setChangeError('Current passcode is incorrect.');
        return;
      }
      resetFields();
    } catch (error: any) {
      setChangeError(error?.message ?? 'Unable to update passcode.');
    }
  };

  const renderHeader = (title: string, subtitle?: string) => (
    <View style={styles.header}>
      <Text style={[styles.headerTitle, {color: colors.text}]}>{title}</Text>
      {subtitle ? (
        <Text style={[styles.headerSubtitle, {color: theme.colors.notification}]}>{subtitle}</Text>
      ) : null}
    </View>
  );

  const renderTypeSelector = (value: 'numeric' | 'alphanumeric', onSelect: (t: 'numeric' | 'alphanumeric') => void) => (
    <View style={styles.typeRow}>
      {[
        {label: '4-digit PIN', value: 'numeric' as const, icon: 'pin'},
        {label: 'Text & number', value: 'alphanumeric' as const, icon: 'password'},
      ].map((option) => {
        const isActive = option.value === value;
        return (
          <TouchableOpacity
            key={option.value}
            style={[styles.typeOption, {borderColor: isActive ? colors.primary : '#D1D5DB', backgroundColor: isActive ? withAlpha(colors.primary, 0.12) : 'transparent'}]}
            onPress={() => onSelect(option.value)}
            activeOpacity={0.85}>
            <MaterialIcons name={option.icon} size={18} color={isActive ? colors.primary : '#6B7280'} />
            <Text style={[styles.typeOptionLabel, {color: isActive ? colors.primary : '#374151'}]}>{option.label}</Text>
          </TouchableOpacity>
        );
      })}
    </View>
  );

  const renderSetupContent = () => (
    <View style={styles.modalBody}>
      {renderHeader('Create app lock passcode', 'Choose how you would like to protect the app.')}
      {renderTypeSelector(setupType, setSetupType)}
      <View style={styles.inputGroup}>
        <Text style={[styles.inputLabel, {color: colors.text}]}>Passcode</Text>
        <TextInput
          style={[styles.textInput, {borderColor: '#D1D5DB', color: colors.text}]}
          placeholder={setupType === 'numeric' ? 'Enter 4-digit PIN' : 'Enter password (letters & numbers)'}
          placeholderTextColor="#9CA3AF"
          value={setupPasscode}
          onChangeText={(text) => {
            setSetupPasscode(setupType === 'numeric' ? text.replace(/[^0-9]/g, '') : text.replace(/[^A-Za-z0-9]/g, ''));
            setSetupError(null);
          }}
          keyboardType={setupType === 'numeric' ? 'number-pad' : 'default'}
          secureTextEntry
          maxLength={setupType === 'numeric' ? 4 : 12}
        />
      </View>
      <View style={styles.inputGroup}>
        <Text style={[styles.inputLabel, {color: colors.text}]}>Confirm Passcode</Text>
        <TextInput
          style={[styles.textInput, {borderColor: '#D1D5DB', color: colors.text}]}
          placeholder="Re-enter passcode"
          placeholderTextColor="#9CA3AF"
          value={setupConfirm}
          onChangeText={(text) => {
            setSetupConfirm(setupType === 'numeric' ? text.replace(/[^0-9]/g, '') : text.replace(/[^A-Za-z0-9]/g, ''));
            setSetupError(null);
          }}
          keyboardType={setupType === 'numeric' ? 'number-pad' : 'default'}
          secureTextEntry
          maxLength={setupType === 'numeric' ? 4 : 12}
        />
      </View>
      {setupError ? <Text style={styles.errorText}>{setupError}</Text> : null}
      <TouchableOpacity style={[styles.primaryButton, {backgroundColor: colors.primary}]} onPress={handleSetup} activeOpacity={0.9}>
        <Text style={styles.primaryButtonText}>Save Passcode</Text>
      </TouchableOpacity>
      {passcode ? (
        <TouchableOpacity style={styles.secondaryButton} onPress={closeModal} activeOpacity={0.85}>
          <Text style={[styles.secondaryButtonText, {color: colors.primary}]}>Cancel</Text>
        </TouchableOpacity>
      ) : null}
    </View>
  );

  const renderUnlockContent = () => (
    <View style={styles.modalBody}>
      {renderHeader('App locked', 'Enter your passcode to continue.')}
      <TextInput
        style={[styles.textInput, {borderColor: '#D1D5DB', color: colors.text}]}
        placeholder={lockType === 'numeric' ? 'Enter 4-digit PIN' : 'Enter password'}
        placeholderTextColor="#9CA3AF"
        value={unlockInput}
        onChangeText={(text) => {
          setUnlockInput(lockType === 'numeric' ? text.replace(/[^0-9]/g, '') : text.replace(/[^A-Za-z0-9]/g, ''));
          setUnlockError(null);
        }}
        keyboardType={lockType === 'numeric' ? 'number-pad' : 'default'}
        secureTextEntry
        maxLength={lockType === 'numeric' ? 4 : 24}
      />
      {unlockError ? <Text style={styles.errorText}>{unlockError}</Text> : null}
      <TouchableOpacity style={[styles.primaryButton, {backgroundColor: colors.primary}]} onPress={handleUnlock} activeOpacity={0.9}>
        <Text style={styles.primaryButtonText}>Unlock</Text>
      </TouchableOpacity>
    </View>
  );

  const renderDisableContent = () => (
    <View style={styles.modalBody}>
      {renderHeader('Disable app lock', 'Enter your passcode to turn off app lock.')}
      <TextInput
        style={[styles.textInput, {borderColor: '#D1D5DB', color: colors.text}]}
        placeholder="Current passcode"
        placeholderTextColor="#9CA3AF"
        value={disablePasscode}
        onChangeText={(text) => {
          setDisablePasscode(lockType === 'numeric' ? text.replace(/[^0-9]/g, '') : text.replace(/[^A-Za-z0-9]/g, ''));
          setDisableError(null);
        }}
        keyboardType={lockType === 'numeric' ? 'number-pad' : 'default'}
        secureTextEntry
        maxLength={lockType === 'numeric' ? 4 : 24}
      />
      {disableError ? <Text style={styles.errorText}>{disableError}</Text> : null}
      <TouchableOpacity style={[styles.primaryButton, {backgroundColor: colors.primary}]} onPress={handleDisable} activeOpacity={0.9}>
        <Text style={styles.primaryButtonText}>Disable</Text>
      </TouchableOpacity>
      <TouchableOpacity style={styles.secondaryButton} onPress={closeModal} activeOpacity={0.85}>
        <Text style={[styles.secondaryButtonText, {color: colors.primary}]}>Cancel</Text>
      </TouchableOpacity>
    </View>
  );

  const renderChangeContent = () => (
    <View style={styles.modalBody}>
      {renderHeader('Change passcode', 'Update your app lock passcode.')}
      <TextInput
        style={[styles.textInput, {borderColor: '#D1D5DB', color: colors.text}]}
        placeholder="Current passcode"
        placeholderTextColor="#9CA3AF"
        value={changeCurrent}
        onChangeText={(text) => {
          setChangeCurrent(lockType === 'numeric' ? text.replace(/[^0-9]/g, '') : text.replace(/[^A-Za-z0-9]/g, ''));
          setChangeError(null);
        }}
        keyboardType={lockType === 'numeric' ? 'number-pad' : 'default'}
        secureTextEntry
        maxLength={lockType === 'numeric' ? 4 : 24}
      />
      {renderTypeSelector(changeType, setChangeType)}
      <TextInput
        style={[styles.textInput, {borderColor: '#D1D5DB', color: colors.text}]}
        placeholder={changeType === 'numeric' ? 'New 4-digit PIN' : 'New password'}
        placeholderTextColor="#9CA3AF"
        value={changeNew}
        onChangeText={(text) => {
          setChangeNew(changeType === 'numeric' ? text.replace(/[^0-9]/g, '') : text.replace(/[^A-Za-z0-9]/g, ''));
          setChangeError(null);
        }}
        keyboardType={changeType === 'numeric' ? 'number-pad' : 'default'}
        secureTextEntry
        maxLength={changeType === 'numeric' ? 4 : 24}
      />
      <TextInput
        style={[styles.textInput, {borderColor: '#D1D5DB', color: colors.text}]}
        placeholder="Confirm new passcode"
        placeholderTextColor="#9CA3AF"
        value={changeConfirm}
        onChangeText={(text) => {
          setChangeConfirm(changeType === 'numeric' ? text.replace(/[^0-9]/g, '') : text.replace(/[^A-Za-z0-9]/g, ''));
          setChangeError(null);
        }}
        keyboardType={changeType === 'numeric' ? 'number-pad' : 'default'}
        secureTextEntry
        maxLength={changeType === 'numeric' ? 4 : 24}
      />
      {changeError ? <Text style={styles.errorText}>{changeError}</Text> : null}
      <TouchableOpacity style={[styles.primaryButton, {backgroundColor: colors.primary}]} onPress={handleChangePasscode} activeOpacity={0.9}>
        <Text style={styles.primaryButtonText}>Update Passcode</Text>
      </TouchableOpacity>
      <TouchableOpacity style={styles.secondaryButton} onPress={closeModal} activeOpacity={0.85}>
        <Text style={[styles.secondaryButtonText, {color: colors.primary}]}>Cancel</Text>
      </TouchableOpacity>
    </View>
  );

  const content = useMemo(() => {
    switch (modal.type) {
      case 'setup':
        return renderSetupContent();
      case 'unlock':
        return renderUnlockContent();
      case 'verifyDisable':
        return renderDisableContent();
      case 'change':
        return renderChangeContent();
      default:
        return null;
    }
  }, [modal.type, lockType, setupType, setupPasscode, setupConfirm, setupError, unlockInput, unlockError, disablePasscode, disableError, changeType, changeNew, changeConfirm, changeError, colors.primary, colors.text, theme.colors.notification]);

  if (!isVisible || !content) {
    return null;
  }

  return (
    <Modal visible transparent animationType="fade" onRequestClose={() => {}}>
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
        style={styles.overlay}>
        <View style={[styles.modalContainer, {backgroundColor: colors.card}]}> 
          {content}
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
};

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: 'rgba(15, 23, 42, 0.7)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: 24,
  },
  modalContainer: {
    width: '100%',
    borderRadius: 20,
    padding: 20,
  },
  modalBody: {
    gap: 16,
  },
  header: {
    gap: 6,
  },
  headerTitle: {
    fontSize: 18,
    fontWeight: '700',
  },
  headerSubtitle: {
    fontSize: 13,
    lineHeight: 19,
  },
  typeRow: {
    flexDirection: 'row',
    gap: 12,
  },
  typeOption: {
    flex: 1,
    borderWidth: 1,
    borderRadius: 12,
    paddingVertical: 12,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 6,
  },
  typeOptionLabel: {
    fontSize: 13,
    fontWeight: '600',
  },
  inputGroup: {
    gap: 6,
  },
  inputLabel: {
    fontSize: 13,
    fontWeight: '600',
  },
  textInput: {
    borderWidth: 1,
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: Platform.OS === 'ios' ? 12 : 10,
    fontSize: 15,
  },
  primaryButton: {
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
  },
  primaryButtonText: {
    color: '#FFFFFF',
    fontSize: 15,
    fontWeight: '600',
  },
  secondaryButton: {
    paddingVertical: 12,
    alignItems: 'center',
  },
  secondaryButtonText: {
    fontSize: 14,
    fontWeight: '600',
  },
  errorText: {
    color: '#EF4444',
    fontSize: 12,
    fontWeight: '600',
  },
  broadcastTitle: {},
  broadcastSubtitle: {},
});

export default AppLockModal;
