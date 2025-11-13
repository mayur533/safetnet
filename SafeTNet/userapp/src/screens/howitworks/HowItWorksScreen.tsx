import React, {useState, useRef} from 'react';
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  Dimensions,
  TouchableOpacity,
  StatusBar,
} from 'react-native';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useNavigation} from '@react-navigation/native';
import {useAuthStore} from '../../stores/authStore';

const {width: SCREEN_WIDTH} = Dimensions.get('window');

interface Step {
  id: string;
  title: string;
  description: string;
  icon: string;
  color: string;
}

const HowItWorksScreen = () => {
  const navigation = useNavigation<any>();
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const [currentPage, setCurrentPage] = useState(0);
  const flatListRef = useRef<FlatList>(null);

  const steps: Step[] = [
    {
      id: '1',
      title: 'Create Your Profile',
      description: 'Set up your account with personal information and emergency contacts. This helps us provide better safety services.',
      icon: 'person',
      color: '#2563EB',
    },
    {
      id: '2',
      title: 'Set Geofence Areas',
      description: 'Define safe zones and areas you want to monitor for alerts. Get notified when entering or leaving these zones.',
      icon: 'location-on',
      color: '#10B981',
    },
    {
      id: '3',
      title: 'Enable Location Tracking',
      description: 'Allow the app to track your location for safety and emergency purposes. Your privacy is always protected.',
      icon: 'gps-fixed',
      color: '#F59E0B',
    },
    {
      id: '4',
      title: 'Use Panic Button',
      description: 'In case of emergency, press and hold the panic button for 3 seconds to alert all contacts instantly.',
      icon: 'warning',
      color: '#EF4444',
    },
    {
      id: '5',
      title: 'Stay Connected',
      description: 'Communicate with your safety network through reports, chat features, and community groups.',
      icon: 'chat',
      color: '#8B5CF6',
    },
  ];

  const isLastPage = currentPage === steps.length - 1;

  const onViewableItemsChanged = useRef(({viewableItems}: any) => {
    if (viewableItems && viewableItems.length > 0) {
      const index = viewableItems[0].index;
      if (index !== null && index !== undefined) {
        setCurrentPage(index);
      }
    }
  }).current;

  const viewabilityConfig = useRef({
    itemVisiblePercentThreshold: 50,
  }).current;

  const handleContinue = () => {
    // Always navigate to Home - Home is now in both AuthNavigator and AppNavigator
    navigation.navigate('Home');
  };

  const goToNext = () => {
    if (currentPage < steps.length - 1) {
      const nextIndex = currentPage + 1;
      try {
        flatListRef.current?.scrollToIndex({index: nextIndex, animated: true});
        setCurrentPage(nextIndex);
      } catch (error) {
        // Fallback to scrollToOffset if scrollToIndex fails
        flatListRef.current?.scrollToOffset({offset: nextIndex * SCREEN_WIDTH, animated: true});
        setCurrentPage(nextIndex);
      }
    }
  };

  const renderStep = ({item, index}: {item: Step; index: number}) => {
    return (
      <View style={[styles.pageContainer, {width: SCREEN_WIDTH}]}>
        <View style={styles.contentContainer}>
          <View style={[styles.iconCircle, {backgroundColor: item.color}]}>
            <MaterialIcons name={item.icon as any} size={64} color="#FFFFFF" />
          </View>
          <Text style={styles.stepNumber}>Step {index + 1} of {steps.length}</Text>
          <Text style={styles.stepTitle}>{item.title}</Text>
          <Text style={styles.stepDescription}>{item.description}</Text>
        </View>
      </View>
    );
  };

  const renderPaginationDots = () => {
    return (
      <View style={styles.paginationContainer}>
        {steps.map((_, index) => (
          <View
            key={index}
            style={[
              styles.paginationDot,
              index === currentPage && styles.paginationDotActive,
            ]}
          />
        ))}
      </View>
    );
  };

  return (
    <View style={styles.container}>
      <StatusBar barStyle="dark-content" backgroundColor="#F9FAFB" />
      
      <FlatList
        ref={flatListRef}
        data={steps}
        renderItem={renderStep}
        keyExtractor={(item) => item.id}
        horizontal
        pagingEnabled
        showsHorizontalScrollIndicator={false}
        onViewableItemsChanged={onViewableItemsChanged}
        viewabilityConfig={viewabilityConfig}
        getItemLayout={(_, index) => ({
          length: SCREEN_WIDTH,
          offset: SCREEN_WIDTH * index,
          index,
        })}
        onScrollToIndexFailed={(info) => {
          const wait = new Promise((resolve) => setTimeout(resolve, 500));
          wait.then(() => {
            flatListRef.current?.scrollToIndex({index: info.index, animated: true});
          });
        }}
      />
      
      <View style={styles.paginationWrapper}>
        {renderPaginationDots()}
        {/* Terms and Service Text - Only on last page */}
        {isLastPage && (
          <View style={styles.termsTextContainer}>
            <Text style={styles.termsServiceText}>
              By clicking Continue, you agree to our{' '}
              <Text style={styles.termsServiceLink}>Terms of Service</Text>
              {' '}and{' '}
              <Text style={styles.termsServiceLink}>Privacy Policy</Text>
            </Text>
          </View>
        )}
      </View>
      
      <View style={styles.navigationContainer}>
        {isLastPage ? (
          // Continue Button - Always shown on last page
          <TouchableOpacity
            style={styles.continueButton}
            onPress={handleContinue}
            activeOpacity={0.8}>
            <Text style={styles.continueButtonText}>Continue</Text>
            <MaterialIcons name="arrow-forward" size={24} color="#FFFFFF" />
          </TouchableOpacity>
        ) : (
          // Next Button
          <View style={styles.nextButtonContainer}>
            <TouchableOpacity
              style={styles.nextButton}
              onPress={goToNext}
              activeOpacity={0.8}>
              <Text style={styles.nextButtonText}>Next</Text>
              <MaterialIcons name="arrow-forward" size={24} color="#2563EB" />
            </TouchableOpacity>
          </View>
        )}
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#F9FAFB',
  },
  pageContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  contentContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 32,
    paddingTop: 80,
    paddingBottom: 120,
  },
  iconCircle: {
    width: 120,
    height: 120,
    borderRadius: 60,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 32,
    shadowColor: '#000',
    shadowOffset: {width: 0, height: 4},
    shadowOpacity: 0.1,
    shadowRadius: 8,
    elevation: 8,
  },
  stepNumber: {
    fontSize: 14,
    fontWeight: '600',
    color: '#6B7280',
    marginBottom: 16,
    textTransform: 'uppercase',
    letterSpacing: 1,
  },
  stepTitle: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#111827',
    textAlign: 'center',
    marginBottom: 16,
  },
  stepDescription: {
    fontSize: 16,
    color: '#6B7280',
    textAlign: 'center',
    lineHeight: 24,
    paddingHorizontal: 16,
    marginBottom: 32,
  },
  paginationWrapper: {
    position: 'absolute',
    bottom: 100,
    left: 0,
    right: 0,
    alignItems: 'center',
  },
  paginationContainer: {
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
    paddingVertical: 16,
  },
  paginationDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: '#D1D5DB',
    marginHorizontal: 4,
  },
  paginationDotActive: {
    width: 24,
    backgroundColor: '#2563EB',
  },
  termsTextContainer: {
    paddingHorizontal: 32,
    paddingBottom: 8,
    alignItems: 'center',
  },
  termsServiceText: {
    fontSize: 12,
    color: '#6B7280',
    textAlign: 'center',
    lineHeight: 16,
  },
  termsServiceLink: {
    color: '#2563EB',
    fontWeight: '600',
  },
  navigationContainer: {
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 24,
    paddingBottom: 32,
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    backgroundColor: '#F9FAFB',
    minHeight: 70,
  },
  nextButtonContainer: {
    flex: 1,
    alignItems: 'flex-end',
  },
  nextButton: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 14,
    paddingHorizontal: 24,
    borderRadius: 8,
    backgroundColor: '#FFFFFF',
    borderWidth: 1,
    borderColor: '#E5E7EB',
    gap: 8,
  },
  placeholderButton: {
    flex: 1,
  },
  nextButtonText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#2563EB',
  },
  continueButton: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 14,
    paddingHorizontal: 32,
    borderRadius: 8,
    backgroundColor: '#2563EB',
    gap: 8,
    shadowColor: '#2563EB',
    shadowOffset: {width: 0, height: 2},
    shadowOpacity: 0.2,
    shadowRadius: 4,
    elevation: 4,
  },
  continueButtonText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#FFFFFF',
  },
});

export default HowItWorksScreen;
