import React, {useState, useEffect, useRef, useCallback} from 'react';
import {useRoute, useTheme} from '@react-navigation/native';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Dimensions,
  Platform,
  Animated,
  PanResponder,
  Vibration,
  Modal,
  Linking,
  TextInput,
  PermissionsAndroid,
  Alert,
} from 'react-native';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useAuthStore} from '../../stores/authStore';
import {useSettingsStore} from '../../stores/settingsStore';
import {CustomVibration} from '../../modules/VibrationModule';
import {shakeDetectionService} from '../../services/shakeDetectionService';

const COMMUNITY_CONTACTS = [
  {id: 'watch', label: 'Neighborhood Watch', phone: '+18005550140'},
  {id: 'residents', label: 'Apartment Residents', phone: '+18005550141'},
  {id: 'verified', label: 'Verified Responders', phone: '+18005550142'},
];

const COMMUNITY_MESSAGES = [
  'Suspicious activity near my location.',
  'Medical assistance needed urgently.',
  'Please check in, safety concern reported.',
];

const categoryCards = [
  {
    key: 'police',
    title: 'Police',
    icon: 'local-police',
    iconColor: '#1D4ED8',
    lightBackground: '#EFF6FF',
    lightBorder: '#DBEAFE',
    phone: '9561606066',
    smsBody: 'Emergency! Please send help immediately.',
    type: 'call' as const,
  },
  {
    key: 'security',
    title: 'Security',
    icon: 'security',
    iconColor: '#047857',
    lightBackground: '#ECFDF5',
    lightBorder: '#A7F3D0',
    phone: '+18005550101',
    smsBody: 'Security alert needed. Please respond ASAP.',
    type: 'call' as const,
  },
  {
    key: 'family',
    title: 'Family',
    icon: 'favorite',
    iconColor: '#7C3AED',
    lightBackground: '#F5F3FF',
    lightBorder: '#DDD6FE',
    phone: '+18005550123',
    smsBody: 'I need your help. Please call me back.',
    type: 'sms' as const,
  },
  {
    key: 'community',
    title: 'Community',
    icon: 'groups',
    iconColor: '#B91C1C',
    lightBackground: '#FEF2F2',
    lightBorder: '#FECACA',
    phone: '+18005550999',
    smsBody: 'Alerting the community—please check in.',
    type: 'community' as const,
    contacts: COMMUNITY_CONTACTS,
    quickMessages: COMMUNITY_MESSAGES,
  },
  {
    key: 'ambulance',
    title: 'Ambulance',
    icon: 'local-hospital',
    iconColor: '#DC2626',
    lightBackground: '#FEE2E2',
    lightBorder: '#FCA5A5',
    phone: '108',
    smsBody: 'Medical emergency. Please dispatch assistance immediately.',
    type: 'call' as const,
  },
  {
    key: 'location',
    title: 'Share\nLocation',
    icon: 'my-location',
    iconColor: '#0EA5E9',
    lightBackground: '#E0F2FE',
    lightBorder: '#BAE6FD',
    phone: '+18005550155',
    smsBody: 'Here is my current location. Please monitor me closely.',
    type: 'sms' as const,
  },
];

type CategoryCard = typeof categoryCards[number];

const {width, height} = Dimensions.get('window');

const HomeScreen = ({navigation}: any) => {
  const route = useRoute();
  const user = useAuthStore((state) => state.user);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const shakeToSendSOS = useSettingsStore((state) => state.shakeToSendSOS);
  const theme = useTheme();
  const colors = theme.colors;
  const [countdown, setCountdown] = useState<number | null>(null);
  const [isSendingAlert, setIsSendingAlert] = useState(false);
  const [isButtonPressed, setIsButtonPressed] = useState(false);
  const [showSuccess, setShowSuccess] = useState(false);
  const [showLoginModal, setShowLoginModal] = useState(false);
  const [actionCard, setActionCard] = useState<CategoryCard | null>(null);
  const [customFamilyMessage, setCustomFamilyMessage] = useState('');
  const [selectedCommunityContact, setSelectedCommunityContact] = useState(COMMUNITY_CONTACTS[0]);
  const [selectedQuickMessage, setSelectedQuickMessage] = useState(COMMUNITY_MESSAGES[0]);
  const [customCommunityMessage, setCustomCommunityMessage] = useState(COMMUNITY_MESSAGES[0]);
  const hasRequestedInitialPermissions = useRef(false);

  const cardRows: CategoryCard[][] = [];
  for (let i = 0; i < categoryCards.length; i += 2) {
    cardRows.push(categoryCards.slice(i, i + 2));
  }

  // Check route params for showLoginModal
  useEffect(() => {
    if (route?.params?.showLoginModal) {
      setShowLoginModal(true);
      // Clear the param after showing modal
      navigation.setParams({showLoginModal: undefined});
    }
  }, [route?.params?.showLoginModal, navigation]);
  const countdownTimerRef = useRef<NodeJS.Timeout | null>(null);
  const alertTimerRef = useRef<NodeJS.Timeout | null>(null);
  const hapticIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const countdownAnim = useRef(new Animated.Value(1)).current;
  const sliderAnim = useRef(new Animated.Value(0)).current;
  const sliderPosition = useRef(0);
  const sliderThumbSize = 64;
  const sliderStartX = useRef(0);

  useEffect(() => {
    if (Platform.OS === 'android' && !hasRequestedInitialPermissions.current) {
      hasRequestedInitialPermissions.current = true;
      void requestInitialPermissions();
    }
  }, [requestInitialPermissions]);

  const triggerVibration = (duration: number = 200) => {
    try {
      // Use custom vibration module that uses USAGE_NOTIFICATION instead of USAGE_TOUCH
      // This ensures vibrations work even when touch vibrations are disabled
      // Use shorter duration (200ms) for discrete pulses that stop between vibrations
      CustomVibration.vibrate(duration);
    } catch (err) {
      console.error('Vibration error:', err);
      // Fallback to React Native's Vibration API
      try {
        Vibration.vibrate(duration);
      } catch (e) {
        console.error('Vibration fallback failed:', e);
      }
    }
  };

  const handleSOSPressIn = () => {
    if (!isAuthenticated) {
      setShowLoginModal(true);
      return;
    }
    
    setIsButtonPressed(true);
    // Haptic feedback on initial press - short pulse that stops
    triggerVibration(200);
    
    // Start 3 second timer to trigger alert sequence with haptic feedback each second
    // Vibrate at 1 second, 2 seconds, 3 seconds (each is a discrete pulse that stops)
    let secondsElapsed = 0;
    hapticIntervalRef.current = setInterval(() => {
      secondsElapsed++;
      // Vibrate at each second during the 3-second hold (1s, 2s, 3s)
      // Each vibration is a short pulse (200ms) that stops before the next one
      triggerVibration(200);
    }, 1000);
    
    countdownTimerRef.current = setTimeout(() => {
      // Clear haptic interval before countdown starts
      if (hapticIntervalRef.current) {
        clearInterval(hapticIntervalRef.current);
        hapticIntervalRef.current = null;
      }
      setIsButtonPressed(false); // Reset button pressed state
      startAlertSequence();
    }, 3000);
  };

  const handleSOSPressOut = () => {
    // Cancel the 3 second hold timer if user releases early
    if (countdownTimerRef.current) {
      clearTimeout(countdownTimerRef.current);
      countdownTimerRef.current = null;
    }
    // Clear haptic interval
    if (hapticIntervalRef.current) {
      clearInterval(hapticIntervalRef.current);
      hapticIntervalRef.current = null;
    }
    // Only cancel if not already in alert sequence
    if (!isSendingAlert) {
      setIsButtonPressed(false);
      setCountdown(null);
    }
  };

  const startAlertSequence = () => {
    // Clear any existing timers
    if (alertTimerRef.current) {
      clearInterval(alertTimerRef.current);
      alertTimerRef.current = null;
    }
    
    setIsSendingAlert(true);
    setCountdown(3);
    // NO vibration when countdown starts
    
    // Start alert sending countdown (3 to 1, then 0 triggers send)
    alertTimerRef.current = setInterval(() => {
      setCountdown((prev) => {
        if (prev === null || prev === undefined) {
          return 3;
        }
        
        // NO haptic feedback on countdown number change
        
        // Animate countdown
        Animated.sequence([
          Animated.timing(countdownAnim, {
            toValue: 0.8,
            duration: 100,
            useNativeDriver: true,
          }),
          Animated.timing(countdownAnim, {
            toValue: 1,
            duration: 100,
            useNativeDriver: true,
          }),
        ]).start();
        
        if (prev <= 1) {
          // Clear interval first
          if (alertTimerRef.current) {
            clearInterval(alertTimerRef.current);
            alertTimerRef.current = null;
          }
          // Send alert after showing "01" briefly
          setTimeout(() => {
            sendAlert();
          }, 500);
          return 0;
        }
        
        return prev - 1;
      });
    }, 1000);
  };

  const sendAlert = (fromShake: boolean = false) => {
    if (!isAuthenticated) {
      return;
    }

    // If called from shake detection, skip UI updates and just send
    // Vibration is already handled in shakeDetectionService when 3 shakes are detected
    if (fromShake) {
      // Send alert directly without UI countdown or vibration
      // Vibration already happened when 3 shakes were detected
      // Notification is already shown by shakeDetectionService
      return;
    }

    // Normal UI flow
    setShowSuccess(true);
    // Haptic feedback when alert is sent - use pattern for success
    try {
      // On Android: odd indices = vibration duration, even indices = separation time
      // Pattern: wait 0ms, vibrate 1000ms, wait 200ms, vibrate 1000ms
      CustomVibration.vibratePattern([0, 1000, 200, 1000], -1);
    } catch (err) {
      console.warn('Vibration pattern error:', err);
      // Fallback to simple vibration
      CustomVibration.vibrate(1000);
    }
    // Reset after 3 seconds
    setTimeout(() => {
      resetState();
    }, 3000);
  };

  const resetState = () => {
    if (countdownTimerRef.current) {
      clearTimeout(countdownTimerRef.current);
      countdownTimerRef.current = null;
    }
    setIsButtonPressed(false);
    setIsSendingAlert(false);
    setShowSuccess(false);
    setCountdown(null);
    sliderPosition.current = 0;
    sliderAnim.setValue(0);
    countdownAnim.setValue(1);
  };

  // Pan responder for cancel slider - use useMemo to recreate when state changes
  const panResponder = React.useMemo(
    () =>
      PanResponder.create({
        onStartShouldSetPanResponder: () => isSendingAlert && !showSuccess,
        onMoveShouldSetPanResponder: () => isSendingAlert && !showSuccess,
        onPanResponderGrant: (evt) => {
          sliderStartX.current = sliderPosition.current;
          // Vibration when clicking/touching the slider - short pulse
          triggerVibration(200);
        },
        onPanResponderMove: (evt, gestureState) => {
          const sliderWidth = width * 0.75;
          const newValue = Math.max(0, Math.min(sliderStartX.current + gestureState.dx, sliderWidth - sliderThumbSize - 6));
          const previousValue = sliderPosition.current;
          sliderPosition.current = newValue;
          sliderAnim.setValue(newValue);
          
          // Haptic feedback when slider touches the right side
          if (newValue >= sliderWidth - sliderThumbSize - 15 && previousValue < sliderWidth - sliderThumbSize - 15) {
            // First time reaching the end - vibrate here (short pulse)
            triggerVibration(200);
            cancelAlert();
          }
        },
        onPanResponderRelease: (evt, gestureState) => {
          // Clear vibration interval on release
          if (hapticIntervalRef.current) {
            clearInterval(hapticIntervalRef.current);
            hapticIntervalRef.current = null;
          }
          const sliderWidth = width * 0.75;
          if (sliderPosition.current < sliderWidth - sliderThumbSize - 15) {
            // Return to start if not fully slid
            sliderPosition.current = 0;
            sliderStartX.current = 0;
            Animated.spring(sliderAnim, {
              toValue: 0,
              useNativeDriver: false,
              tension: 50,
              friction: 7,
            }).start();
          }
        },
      }),
    [isSendingAlert, showSuccess]
  );

  // Recreate pan responder when isSendingAlert changes
  useEffect(() => {
    if (isSendingAlert) {
      // Reset slider position when alert starts
      sliderPosition.current = 0;
      sliderStartX.current = 0;
      sliderAnim.setValue(0);
    }
  }, [isSendingAlert]);

  const cancelAlert = () => {
    if (alertTimerRef.current) {
      clearInterval(alertTimerRef.current);
      alertTimerRef.current = null;
    }
    if (countdownTimerRef.current) {
      clearTimeout(countdownTimerRef.current);
      countdownTimerRef.current = null;
    }
    resetState();
  };

  // Load settings on mount
  useEffect(() => {
    const loadSettings = async () => {
      const {loadSettings} = useSettingsStore.getState();
      await loadSettings();
    };
    loadSettings();
  }, []);

  // Shake detection setup
  useEffect(() => {
    if (shakeToSendSOS && isAuthenticated) {
      // Start shake detection
      shakeDetectionService.start(() => {
        // This callback is called when shake is detected
        sendAlert(true); // Pass true to indicate it's from shake
      });
    } else {
      // Stop shake detection only if setting is disabled
      if (!shakeToSendSOS) {
        shakeDetectionService.stop();
      }
    }

    // Cleanup on unmount or when settings change
    return () => {
      // Don't stop if setting is enabled - let it run in background
      if (!shakeToSendSOS) {
        shakeDetectionService.stop();
      }
    };
  }, [shakeToSendSOS, isAuthenticated]);

  useEffect(() => {
    // Test vibration on component mount after a short delay
    const testTimer = setTimeout(() => {
      try {
        CustomVibration.vibrate(500);
      } catch (err) {
        console.error('Vibration test failed:', err);
      }
    }, 1000);
    
    return () => {
      clearTimeout(testTimer);
      if (countdownTimerRef.current) {
        clearTimeout(countdownTimerRef.current);
      }
      if (alertTimerRef.current) {
        clearInterval(alertTimerRef.current);
      }
    };
  }, []);

  const handleCardPress = (card: CategoryCard) => {
    if (!isAuthenticated) {
      setShowLoginModal(true);
      return;
    }

    triggerVibration(200);

    if (card.type === 'community') {
      const initialMessage = card.quickMessages?.[0] || '';
      setSelectedCommunityContact(card.contacts[0]);
      setSelectedQuickMessage(initialMessage);
      setCustomCommunityMessage(initialMessage);
    } else if (card.type === 'sms') {
      setCustomFamilyMessage(card.smsBody || '');
    }

    setActionCard(card);
  };

  const showCategories = !isButtonPressed && !isSendingAlert && !showSuccess;

  const closeActionModal = () => {
    setActionCard(null);
  };

  const requestCallPermission = async () => {
    if (Platform.OS !== 'android') {
      return true;
    }

    try {
      const permission = PermissionsAndroid.PERMISSIONS.CALL_PHONE;
      const hasPermission = await PermissionsAndroid.check(permission);
      if (hasPermission) {
        return true;
      }

      const status = await PermissionsAndroid.request(permission, {
        title: 'Allow Phone Calls',
        message: 'Grant phone call access to contact emergency services directly.',
        buttonPositive: 'Allow',
        buttonNegative: 'Deny',
      });

      return status === PermissionsAndroid.RESULTS.GRANTED;
    } catch (error) {
      console.warn('Call permission request failed:', error);
      return false;
    }
  };

  const handleCall = async (phone?: string) => {
    if (!phone) {
      closeActionModal();
      return;
    }

    const canCall = await requestCallPermission();
    if (!canCall) {
      Alert.alert(
        'Permission Required',
        'Please allow phone call access in settings to place emergency calls automatically.',
      );
      closeActionModal();
      return;
    }

    try {
      await Linking.openURL(`tel:${phone}`);
    } catch (error) {
      console.warn('Failed to initiate call:', error);
      Alert.alert('Call Failed', 'Unable to place the call. Please try again from your dialer.');
    } finally {
      closeActionModal();
    }
  };

  const requestInitialPermissions = useCallback(async () => {
    if (Platform.OS !== 'android') {
      return;
    }

    try {
      const permissions: string[] = [
        PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
        PermissionsAndroid.PERMISSIONS.ACCESS_COARSE_LOCATION,
        PermissionsAndroid.PERMISSIONS.CALL_PHONE,
        PermissionsAndroid.PERMISSIONS.SEND_SMS,
      ];

      if (Platform.Version >= 29 && PermissionsAndroid.PERMISSIONS.ACCESS_BACKGROUND_LOCATION) {
        permissions.push(PermissionsAndroid.PERMISSIONS.ACCESS_BACKGROUND_LOCATION);
      }

      const results = await PermissionsAndroid.requestMultiple(permissions);
      const denied = Object.entries(results).filter(([, value]) => value !== PermissionsAndroid.RESULTS.GRANTED);

      if (denied.length > 0) {
        Alert.alert(
          'Permissions Needed',
          'Some permissions were denied. Certain safety features may be limited until they are granted.',
        );
      }
    } catch (error) {
      console.warn('Initial permission request failed:', error);
    }
  }, []);

  const handleSendSMS = (phone?: string, message?: string) => {
    if (phone) {
      const body = message ? `?body=${encodeURIComponent(message)}` : '';
      Linking.openURL(`sms:${phone}${body}`).catch(() => {});
    }
    closeActionModal();
  };

  const handleSendCommunityMessage = () => {
    const message = customCommunityMessage.trim() || selectedQuickMessage;
    handleSendSMS(selectedCommunityContact.phone, message);
  };

  const renderActionContent = () => {
    if (!actionCard) {
      return null;
    }

    const cancelButtonStyle = [
      styles.modalButton,
      {
        backgroundColor: softSurface,
        borderColor: withAlpha(colors.border, isDarkMode ? 0.7 : 1),
      },
    ];

    const cancelButtonTextStyle = [styles.modalCancelText, {color: colors.text}];

    const primaryButtonStyle = [
      styles.modalButton,
      {backgroundColor: colors.primary, borderColor: colors.primary},
    ];

    if (actionCard.type === 'call') {
      return (
        <>
          <View style={styles.actionHeader}>
            <MaterialIcons name={actionCard.icon} size={32} color={actionCard.iconColor} />
            <Text style={[styles.actionTitle, {color: colors.text}]}>{actionCard.title}</Text>
          </View>
          <Text style={[styles.actionDescription, {color: mutedTextColor}]}>Are you sure you want to call {actionCard.title.toLowerCase()} at {actionCard.phone}?</Text>
          <View style={styles.actionButtonRow}>
            <TouchableOpacity style={cancelButtonStyle} onPress={closeActionModal} activeOpacity={0.7}>
              <Text style={cancelButtonTextStyle}>Cancel</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={primaryButtonStyle}
              onPress={() => {
                void handleCall(actionCard.phone);
              }}
              activeOpacity={0.7}>
              <Text style={styles.primaryButtonText}>Call</Text>
            </TouchableOpacity>
          </View>
        </>
      );
    }

    if (actionCard.type === 'sms') {
      return (
        <>
          <View style={styles.actionHeader}>
            <MaterialIcons name={actionCard.icon} size={32} color={actionCard.iconColor} />
            <Text style={[styles.actionTitle, {color: colors.text}]}>{actionCard.title}</Text>
          </View>
          <Text style={[styles.actionDescription, {color: mutedTextColor}]}>Send a quick update to your family contact.</Text>
          <TextInput
            style={[
              styles.actionInput,
              {
                backgroundColor: inputSurface,
                borderColor: colors.border,
                color: colors.text,
              },
            ]}
            multiline
            numberOfLines={3}
            value={customFamilyMessage}
            onChangeText={setCustomFamilyMessage}
            placeholder="Type your emergency message"
            placeholderTextColor={placeholderColor}
          />
          <View style={styles.actionButtonRow}>
            <TouchableOpacity style={cancelButtonStyle} onPress={closeActionModal} activeOpacity={0.7}>
              <Text style={cancelButtonTextStyle}>Cancel</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={primaryButtonStyle}
              onPress={() => handleSendSMS(actionCard.phone, customFamilyMessage.trim() || actionCard.smsBody)}
              activeOpacity={0.7}>
              <Text style={styles.primaryButtonText}>Send Message</Text>
            </TouchableOpacity>
          </View>
        </>
      );
    }

    if (actionCard.type === 'community') {
      return (
        <>
          <View style={styles.actionHeader}>
            <MaterialIcons name={actionCard.icon} size={32} color={actionCard.iconColor} />
            <Text style={[styles.actionTitle, {color: colors.text}]}>{actionCard.title}</Text>
          </View>
          <Text style={[styles.actionDescription, {color: mutedTextColor}]}>Choose a circle to alert.</Text>
          <View style={styles.chipRow}>
            {actionCard.contacts.map((contact) => {
              const isActive = contact.id === selectedCommunityContact.id;
              return (
                <TouchableOpacity
                  key={contact.id}
                  style={[
                    styles.chip,
                    {
                      backgroundColor: softSurface,
                      borderColor: withAlpha(colors.border, isDarkMode ? 0.7 : 1),
                    },
                    isActive && {backgroundColor: colors.primary, borderColor: colors.primary},
                  ]}
                  onPress={() => {
                    setSelectedCommunityContact(contact);
                  }}
                  activeOpacity={0.7}>
                  <Text
                    style={[
                      styles.chipText,
                      {color: mutedTextColor},
                      isActive && {color: isDarkMode ? colors.background : '#FFFFFF'},
                    ]}>
                    {contact.label}
                  </Text>
                </TouchableOpacity>
              );
            })}
          </View>
          <Text style={[styles.actionDescription, {marginTop: 12, color: mutedTextColor}]}>Quick messages</Text>
          <View style={styles.chipRow}>
            {actionCard.quickMessages.map((message) => {
              const isActive = message === selectedQuickMessage;
              return (
                <TouchableOpacity
                  key={message}
                  style={[
                    styles.chip,
                    {
                      backgroundColor: softSurface,
                      borderColor: withAlpha(colors.border, isDarkMode ? 0.7 : 1),
                    },
                    isActive && {backgroundColor: colors.primary, borderColor: colors.primary},
                  ]}
                  onPress={() => {
                    setSelectedQuickMessage(message);
                    setCustomCommunityMessage(message);
                  }}
                  activeOpacity={0.7}>
                  <Text
                    style={[
                      styles.chipText,
                      {color: mutedTextColor},
                      isActive && {color: isDarkMode ? colors.background : '#FFFFFF'},
                    ]}>
                    {message}
                  </Text>
                </TouchableOpacity>
              );
            })}
          </View>
          <TextInput
            style={[
              styles.actionInput,
              {
                marginTop: 12,
                backgroundColor: inputSurface,
                borderColor: colors.border,
                color: colors.text,
              },
            ]}
            multiline
            numberOfLines={3}
            value={customCommunityMessage}
            onChangeText={(text) => {
              setCustomCommunityMessage(text);
              setSelectedQuickMessage(text);
            }}
            placeholder="Custom message to your community"
            placeholderTextColor={placeholderColor}
          />
          <View style={styles.actionButtonRow}>
            <TouchableOpacity style={cancelButtonStyle} onPress={closeActionModal} activeOpacity={0.7}>
              <Text style={cancelButtonTextStyle}>Cancel</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={primaryButtonStyle}
              onPress={handleSendCommunityMessage}
              activeOpacity={0.7}>
              <Text style={styles.primaryButtonText}>Send Message</Text>
            </TouchableOpacity>
          </View>
        </>
      );
    }

    return null;
  };

  return (
    <View style={[styles.container, {backgroundColor: colors.background}]}> 
      {/* Top SOS Section */}
      <View style={styles.sosSection}>
        {/* Fixed position SOS Button */}
        <TouchableOpacity
          style={[
            styles.sosButton,
            {
              borderColor: colors.border,
              shadowColor: cardShadowColor,
            },
          ]}
          onPressIn={handleSOSPressIn}
          onPressOut={handleSOSPressOut}
          activeOpacity={0.8}
          disabled={showSuccess}>
          <Animated.Text
            style={[
              styles.sosText,
              {
                transform: [{scale: isSendingAlert && countdown !== null ? countdownAnim : 1}],
              },
            ]}>
            {showSuccess ? '✓' : isSendingAlert && countdown !== null && countdown > 0 ? (countdown < 10 ? `0${countdown}` : String(countdown)) : 'SOS'}
          </Animated.Text>
        </TouchableOpacity>

        {/* Fixed position text container below button */}
        <View style={styles.messageContainer}>
          {!isSendingAlert && !showSuccess && (
            <Text style={[styles.instructionText, {color: colors.text}]}>Press and hold for 3 seconds to send an alert.</Text>
          )}

          {isSendingAlert && !showSuccess && countdown !== null && countdown > 0 && (
            <Text style={styles.alertMessageText}>
              Alert will be sent to officials in {countdown} second{countdown !== 1 ? 's' : ''}
            </Text>
          )}
          
          {isSendingAlert && !showSuccess && countdown === 0 && (
            <Text style={styles.alertMessageText}>Sending alert...</Text>
          )}

          {showSuccess && (
            <View style={styles.successContainer}>
              <Text style={styles.successMessageText}>
                Successfully sent and action will be taken
              </Text>
              <Text style={[styles.quoteText, {color: subtleTextColor}]}>
                Your safety is our priority
              </Text>
            </View>
          )}
        </View>
      </View>

      {/* Cancel Slider - Only show when alert is being sent */}
      {isSendingAlert && !showSuccess && (
        <View style={styles.sliderContainer}>
          <Text style={[styles.sliderText, {color: colors.notification}]}>Slide to cancel alert</Text>
          <View
            style={[
              styles.sliderTrack,
              {
                backgroundColor: sliderTrackColor,
                borderColor: sliderBorderColor,
                shadowColor: cardShadowColor,
              },
            ]}
            {...panResponder.panHandlers}
            collapsable={false}>
            <View style={styles.sliderCancelTextContainer}>
              <Text style={[styles.sliderCancelText, {color: colors.notification}]}>Cancel</Text>
            </View>
            <Animated.View
              style={[
                styles.sliderThumb,
                {
                  backgroundColor: sliderThumbColor,
                  shadowColor: cardShadowColor,
                  transform: [
                    {
                      translateX: sliderAnim,
                    },
                  ],
                },
              ]}
              collapsable={false}>
              <MaterialIcons name="close" size={28} color="#FFFFFF" />
            </Animated.View>
          </View>
        </View>
      )}

      {/* Bottom Categories Section - Hide when countdown or alert is active */}
      {showCategories && (
        <View style={styles.categoriesSection}>
          {cardRows.map((rowCards, rowIndex) => (
            <View key={rowIndex} style={styles.row}>
              {rowCards.map((card) => (
                <TouchableOpacity
                  key={card.key}
                  style={[
                    styles.categoryCard,
                    {
                      backgroundColor: isDarkMode ? withAlpha(card.iconColor, 0.15) : card.lightBackground,
                      borderColor: isDarkMode ? withAlpha(card.iconColor, 0.35) : card.lightBorder,
                      shadowColor: cardShadowColor,
                    },
                  ]}
                  onPress={() => handleCardPress(card)}
                  activeOpacity={0.85}>
                  <View
                    style={[
                      styles.cardIconContainer,
                      {
                        backgroundColor: isDarkMode
                          ? withAlpha(card.iconColor, 0.25)
                          : 'rgba(255,255,255,0.75)',
                      },
                    ]}>
                    <MaterialIcons name={card.icon} size={20} color={card.iconColor} />
                  </View>
                  <View style={styles.cardTextContainer}>
                    <Text style={[styles.cardTitle, {color: colors.text}]}>{card.title}</Text>
                  </View>
                </TouchableOpacity>
              ))}
              {rowCards.length < 2 && <View style={{width: CARD_WIDTH}} />}
            </View>
          ))}
        </View>
      )}

      {/* Footer with Logo - Hide when countdown or alert is active */}
      {showCategories && (
        <View style={styles.footer}>
          <MaterialIcons name="security" size={20} color={colors.notification} />
          <Text style={[styles.footerText, {color: colors.notification}]}>Safe T Net</Text>
        </View>
      )}

      <Modal
        visible={actionCard !== null}
        transparent
        animationType="fade"
        onRequestClose={closeActionModal}>
        <View style={styles.actionOverlay}>
          <View style={styles.actionContainer}>{renderActionContent()}</View>
        </View>
      </Modal>

      {/* Modern Login Modal */}
      <Modal
        visible={showLoginModal}
        transparent
        animationType="fade"
        onRequestClose={() => setShowLoginModal(false)}>
        <View style={styles.modalOverlay}>
          <View style={[styles.modalContent, {backgroundColor: colors.card}]}>
            <View
              style={[
                styles.modalIconContainer,
                {backgroundColor: withAlpha(colors.primary, isDarkMode ? 0.2 : 0.1)},
              ]}>
              <MaterialIcons name="lock" size={48} color={colors.primary} />
            </View>
            <Text style={[styles.modalTitle, {color: colors.text}]}>Login Required</Text>
            <Text style={[styles.modalMessage, {color: colors.notification}]}>Login to use this feature</Text>
            <View style={styles.modalButtons}>
              <TouchableOpacity
                style={[
                  styles.modalCancelButton,
                  {
                    backgroundColor: softSurface,
                    borderColor: withAlpha(colors.border, isDarkMode ? 0.7 : 1),
                  },
                ]}
                onPress={() => setShowLoginModal(false)}
                activeOpacity={0.7}>
                <Text style={[styles.modalCancelText, {color: colors.text}]}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.modalLoginButton, {backgroundColor: colors.primary}]}
                onPress={() => {
                  setShowLoginModal(false);
                  navigation.navigate('Login');
                }}
                activeOpacity={0.7}>
                <Text style={styles.modalLoginText}>Login</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
};

const CARD_HORIZONTAL_PADDING = 20;
const CARD_GAP = 12;
const CARD_WIDTH = (width - CARD_HORIZONTAL_PADDING * 2 - CARD_GAP) / 2;

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFFFFF',
    justifyContent: 'space-between',
  },
  sosSection: {
    flex: 1,
    justifyContent: 'flex-start',
    alignItems: 'center',
    position: 'relative',
    paddingTop: 60,
  },
  sosButton: {
    width: width * 0.5,
    height: width * 0.5,
    borderRadius: (width * 0.5) / 2,
    backgroundColor: '#B91C1C',
    borderWidth: 4,
    borderColor: '#9CA3AF',
    justifyContent: 'center',
    alignItems: 'center',
    elevation: 8,
    shadowColor: '#000',
    shadowOffset: {width: 0, height: 4},
    shadowOpacity: 0.3,
    shadowRadius: 5,
  },
  messageContainer: {
    width: '100%',
    paddingHorizontal: 40,
    alignItems: 'center',
    marginTop: 20,
  },
  sosText: {
    color: '#FFFFFF',
    fontSize: 48,
    fontWeight: 'bold',
  },
  instructionText: {
    color: '#374151',
    fontSize: 16,
    textAlign: 'center',
  },
  successMessageText: {
    fontSize: 18,
    fontWeight: '600',
    color: '#10B981',
    textAlign: 'center',
  },
  alertMessageText: {
    fontSize: 18,
    fontWeight: '600',
    color: '#B91C1C',
    textAlign: 'center',
  },
  successContainer: {
    alignItems: 'center',
  },
  quoteText: {
    fontSize: 14,
    fontStyle: 'italic',
    color: '#6B7280',
    textAlign: 'center',
    marginTop: 8,
  },
  sliderContainer: {
    paddingHorizontal: 20,
    paddingBottom: 40,
    alignItems: 'center',
  },
  sliderText: {
    fontSize: 14,
    color: '#6B7280',
    marginBottom: 16,
    fontWeight: '500',
  },
  sliderTrack: {
    width: width * 0.75,
    height: 70,
    backgroundColor: '#E5E7EB',
    borderRadius: 35,
    justifyContent: 'center',
    overflow: 'hidden',
    borderWidth: 3,
    borderColor: '#D1D5DB',
    position: 'relative',
  },
  sliderCancelTextContainer: {
    position: 'absolute',
    right: 20,
    top: 0,
    bottom: 0,
    justifyContent: 'center',
    alignItems: 'center',
    zIndex: 1,
  },
  sliderCancelText: {
    color: '#6B7280',
    fontSize: 16,
    fontWeight: '600',
  },
  sliderThumb: {
    width: 64,
    height: 64,
    borderRadius: 32,
    backgroundColor: '#EF4444',
    justifyContent: 'center',
    alignItems: 'center',
    position: 'absolute',
    left: 3,
    zIndex: 2,
    elevation: 8,
    shadowColor: '#000',
    shadowOffset: {width: 0, height: 4},
    shadowOpacity: 0.3,
    shadowRadius: 4.65,
  },
  categoriesSection: {
    paddingHorizontal: CARD_HORIZONTAL_PADDING,
    paddingBottom: 32,
    gap: CARD_GAP,
  },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: CARD_GAP,
  },
  categoryCard: {
    width: CARD_WIDTH,
    borderRadius: 14,
    borderWidth: 1,
    paddingVertical: 12,
    paddingHorizontal: 12,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    shadowColor: '#000',
    shadowOffset: {width: 0, height: 1},
    shadowOpacity: 0.07,
    shadowRadius: 2.5,
    elevation: 2,
    minHeight: 88,
  },
  cardIconContainer: {
    width: 38,
    height: 38,
    borderRadius: 11,
    backgroundColor: 'rgba(255,255,255,0.75)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  cardTextContainer: {
    flex: 1,
    justifyContent: 'center',
  },
  cardTitle: {
    fontSize: 13,
    fontWeight: '700',
    color: '#111827',
    lineHeight: 16,
    flexShrink: 1,
  },
  actionOverlay: {
    flex: 1,
    backgroundColor: 'rgba(15, 23, 42, 0.6)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: 24,
  },
  actionContainer: {
    width: '100%',
    maxWidth: 420,
    backgroundColor: '#FFFFFF',
    borderRadius: 20,
    padding: 20,
    shadowColor: '#000',
    shadowOffset: {width: 0, height: 8},
    shadowOpacity: 0.2,
    shadowRadius: 16,
    elevation: 12,
  },
  actionHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    marginBottom: 12,
  },
  actionTitle: {
    fontSize: 20,
    fontWeight: '700',
    color: '#111827',
  },
  actionDescription: {
    fontSize: 14,
    color: '#4B5563',
  },
  actionButtonRow: {
    flexDirection: 'row',
    gap: 12,
    marginTop: 20,
  },
  actionInput: {
    marginTop: 16,
    borderRadius: 14,
    borderWidth: 1,
    borderColor: '#E5E7EB',
    backgroundColor: '#F9FAFB',
    padding: 12,
    minHeight: 80,
    textAlignVertical: 'top',
    fontSize: 14,
    color: '#111827',
  },
  chipRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
    marginTop: 12,
  },
  chip: {
    borderRadius: 999,
    borderWidth: 1,
    borderColor: '#E5E7EB',
    paddingHorizontal: 12,
    paddingVertical: 6,
    backgroundColor: '#F3F4F6',
  },
  chipActive: {
    backgroundColor: '#2563EB',
    borderColor: '#2563EB',
  },
  chipText: {
    fontSize: 13,
    color: '#4B5563',
    fontWeight: '500',
  },
  chipTextActive: {
    color: '#FFFFFF',
  },
  modalButton: {
    flex: 1,
    paddingVertical: 12,
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
  },
  cancelButton: {
    backgroundColor: '#F3F4F6',
    borderWidth: 1,
    borderColor: '#E5E7EB',
  },
  cancelButtonText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#374151',
  },
  primaryButton: {
    backgroundColor: '#2563EB',
  },
  primaryButtonText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#FFFFFF',
  },
  footer: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 16,
    paddingBottom: 24,
  },
  footerText: {
    color: '#374151',
    fontSize: 16,
    fontWeight: '500',
    fontFamily: Platform.OS === 'ios' ? 'System' : 'sans-serif',
    letterSpacing: -0.2,
    marginLeft: 8,
  },
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
    justifyContent: 'center',
    alignItems: 'center',
  },
  modalContent: {
    backgroundColor: '#FFFFFF',
    borderRadius: 20,
    padding: 24,
    width: '85%',
    maxWidth: 400,
    alignItems: 'center',
    shadowColor: '#000',
    shadowOffset: {width: 0, height: 4},
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 10,
  },
  modalIconContainer: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: '#EFF6FF',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 20,
  },
  modalTitle: {
    fontSize: 22,
    fontWeight: 'bold',
    color: '#111827',
    marginBottom: 8,
  },
  modalMessage: {
    fontSize: 16,
    color: '#6B7280',
    textAlign: 'center',
    marginBottom: 24,
  },
  modalButtons: {
    flexDirection: 'row',
    gap: 12,
    width: '100%',
  },
  modalCancelButton: {
    flex: 1,
    paddingVertical: 12,
    paddingHorizontal: 24,
    borderRadius: 10,
    backgroundColor: '#F3F4F6',
    alignItems: 'center',
  },
  modalCancelText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#374151',
  },
  modalLoginButton: {
    flex: 1,
    paddingVertical: 12,
    paddingHorizontal: 24,
    borderRadius: 10,
    backgroundColor: '#2563EB',
    alignItems: 'center',
  },
  modalLoginText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#FFFFFF',
  },
});

export default HomeScreen;
