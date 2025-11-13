import React, {useState, useEffect, useRef} from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Dimensions,
  Alert,
  Platform,
  Animated,
  PanResponder,
  Vibration,
} from 'react-native';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useAuthStore} from '../../stores/authStore';
import {CustomVibration} from '../../modules/VibrationModule';

const {width, height} = Dimensions.get('window');

const HomeScreen = ({navigation}: any) => {
  const user = useAuthStore((state) => state.user);
  const [countdown, setCountdown] = useState<number | null>(null);
  const [isSendingAlert, setIsSendingAlert] = useState(false);
  const [isButtonPressed, setIsButtonPressed] = useState(false);
  const [showSuccess, setShowSuccess] = useState(false);
  const countdownTimerRef = useRef<NodeJS.Timeout | null>(null);
  const alertTimerRef = useRef<NodeJS.Timeout | null>(null);
  const hapticIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const countdownAnim = useRef(new Animated.Value(1)).current;
  const sliderAnim = useRef(new Animated.Value(0)).current;
  const sliderPosition = useRef(0);
  const sliderThumbSize = 64;
  const sliderStartX = useRef(0);

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

  const sendAlert = () => {
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

  const handleCategoryPress = (category: string) => {
    // Vibrate on category button press
    triggerVibration(200);
    
    // Navigate to corresponding screen based on category
    const categoryMap: {[key: string]: string} = {
      'Community': 'Community',
      'Security': 'More', // Security can navigate to More or create a Security screen
      'Police': 'Alert',
      'Family': 'Family',
    };
    
    const screenName = categoryMap[category] || 'Home';
    navigation.navigate(screenName);
  };

  const showCategories = !isButtonPressed && !isSendingAlert && !showSuccess;

  return (
    <View style={styles.container}>
      {/* Top SOS Section */}
      <View style={styles.sosSection}>
        {/* Fixed position SOS Button */}
        <TouchableOpacity
          style={styles.sosButton}
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
            <Text style={styles.instructionText}>
              Press and hold for 3 seconds to send an alert.
            </Text>
          )}

          {isSendingAlert && !showSuccess && countdown !== null && countdown > 0 && (
            <Text style={styles.alertMessageText}>
              Alert will be sent to officials in {countdown} second{countdown !== 1 ? 's' : ''}
            </Text>
          )}
          
          {isSendingAlert && !showSuccess && countdown === 0 && (
            <Text style={styles.alertMessageText}>
              Sending alert...
            </Text>
          )}

          {showSuccess && (
            <View style={styles.successContainer}>
              <Text style={styles.successMessageText}>
                Successfully sent and action will be taken
              </Text>
              <Text style={styles.quoteText}>
                Your safety is our priority
              </Text>
            </View>
          )}
        </View>
      </View>

      {/* Cancel Slider - Only show when alert is being sent */}
      {isSendingAlert && !showSuccess && (
        <View style={styles.sliderContainer}>
          <Text style={styles.sliderText}>Slide to cancel alert</Text>
          <View 
            style={styles.sliderTrack}
            {...panResponder.panHandlers}
            collapsable={false}>
            <View style={styles.sliderCancelTextContainer}>
              <Text style={styles.sliderCancelText}>Cancel</Text>
            </View>
            <Animated.View
              style={[
                styles.sliderThumb,
                {
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
          <View style={styles.row}>
            <TouchableOpacity
              style={styles.categoryButton}
              onPress={() => handleCategoryPress('Community')}>
              <MaterialIcons name="groups" size={28} color="#FFFFFF" />
              <Text style={styles.categoryText}>Community</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={styles.categoryButton}
              onPress={() => handleCategoryPress('Security')}>
              <MaterialIcons name="security" size={28} color="#FFFFFF" />
              <Text style={styles.categoryText}>Security</Text>
            </TouchableOpacity>
          </View>
          <View style={styles.row}>
            <TouchableOpacity
              style={styles.categoryButton}
              onPress={() => handleCategoryPress('Police')}>
              <MaterialIcons name="local-police" size={28} color="#FFFFFF" />
              <Text style={styles.categoryText}>Police</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={styles.categoryButton}
              onPress={() => handleCategoryPress('Family')}>
              <MaterialIcons name="favorite" size={28} color="#FFFFFF" />
              <Text style={styles.categoryText}>Family</Text>
            </TouchableOpacity>
          </View>
        </View>
      )}

      {/* Footer with Logo - Hide when countdown or alert is active */}
      {showCategories && (
        <View style={styles.footer}>
          <MaterialIcons name="security" size={20} color="#6B7280" />
          <Text style={styles.footerText}>Safe T Net</Text>
        </View>
      )}
    </View>
  );
};

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
    paddingHorizontal: 20,
    paddingBottom: 40,
  },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    marginBottom: 20,
  },
  categoryButton: {
    width: width * 0.28,
    height: width * 0.28,
    borderRadius: (width * 0.28) / 2,
    backgroundColor: '#2563EB',
    justifyContent: 'center',
    alignItems: 'center',
    marginHorizontal: 10,
    elevation: 4,
    shadowColor: '#000',
    shadowOffset: {width: 0, height: 2},
    shadowOpacity: 0.2,
    shadowRadius: 3,
  },
  categoryText: {
    color: '#FFFFFF',
    fontSize: 13,
    fontWeight: '500',
    marginTop: 6,
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
});

export default HomeScreen;
