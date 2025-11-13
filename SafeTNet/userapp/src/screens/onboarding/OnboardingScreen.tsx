import React, {useState, useRef} from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  Dimensions,
  TouchableOpacity,
  Image,
  StatusBar,
} from 'react-native';
import LinearGradient from 'react-native-linear-gradient';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useAuthStore} from '../../stores/authStore';
import {useNavigation} from '@react-navigation/native';

const {width, height} = Dimensions.get('window');

interface OnboardingPageProps {
  children: React.ReactNode;
}

const OnboardingPage: React.FC<OnboardingPageProps> = ({children}) => (
  <View style={styles.page}>{children}</View>
);

const OnboardingScreen = () => {
  const [currentPage, setCurrentPage] = useState(0);
  const [agreeTerms, setAgreeTerms] = useState(false);
  const scrollViewRef = useRef<ScrollView>(null);
  const login = useAuthStore((state) => state.login);
  const navigation = useNavigation<any>();

  const totalPages = 6;

  const handleScroll = (event: any) => {
    const offsetX = event.nativeEvent.contentOffset.x;
    const page = Math.round(offsetX / width);
    setCurrentPage(page);
  };

  const handleGetStarted = () => {
    if (!agreeTerms) {
      return;
    }
    login('demo@example.com', 'demo123');
  };

  const renderPaginationDots = () => {
    return (
      <View style={styles.paginationContainer}>
        {Array.from({length: totalPages}).map((_, index) => (
          <View
            key={index}
            style={[
              styles.paginationDot,
              currentPage === index && styles.paginationDotActive,
            ]}
          />
        ))}
      </View>
    );
  };

  const renderPanicDiagram = (highlightedSegment: 'family' | 'community' | 'police' | 'security' | 'none' = 'none') => {
    const getSegmentColor = (segment: string) => {
      if (segment === highlightedSegment) return '#2563eb';
      return '#E5E7EB';
    };

    const getTextColor = (segment: string) => {
      if (segment === highlightedSegment) return '#FFFFFF';
      return '#6B7280';
    };

    return (
      <View style={styles.diagramContainer}>
        <View style={styles.circleOuter}>
          {/* Family Segment - Top Left */}
          <View style={[styles.segment, styles.segmentTopLeft, {backgroundColor: getSegmentColor('family')}]}>
            <MaterialIcons name="people" size={28} color={getTextColor('family')} />
            <Text style={[styles.segmentText, {color: getTextColor('family')}]}>Family</Text>
          </View>
          
          {/* Community Segment - Top Right */}
          <View style={[styles.segment, styles.segmentTopRight, {backgroundColor: getSegmentColor('community')}]}>
            <MaterialIcons name="groups" size={28} color={getTextColor('community')} />
            <Text style={[styles.segmentText, {color: getTextColor('community')}]}>Community</Text>
          </View>
          
          {/* Police Segment - Bottom Left */}
          <View style={[styles.segment, styles.segmentBottomLeft, {backgroundColor: getSegmentColor('police')}]}>
            <MaterialIcons name="local-police" size={28} color={getTextColor('police')} />
            <Text style={[styles.segmentText, {color: getTextColor('police')}]}>Police</Text>
          </View>
          
          {/* Security Segment - Bottom Right */}
          <View style={[styles.segment, styles.segmentBottomRight, {backgroundColor: getSegmentColor('security')}]}>
            <MaterialIcons name="security" size={28} color={getTextColor('security')} />
            <Text style={[styles.segmentText, {color: getTextColor('security')}]}>Security</Text>
          </View>
          
          {/* Central PANIC Button */}
          <View style={styles.panicButton}>
            <Text style={styles.panicText}>PANIC</Text>
          </View>
        </View>
      </View>
    );
  };

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#2563eb" />
      <ScrollView
        ref={scrollViewRef}
        horizontal
        pagingEnabled
        showsHorizontalScrollIndicator={false}
        onScroll={handleScroll}
        scrollEventThrottle={16}
        style={styles.scrollView}
        contentContainerStyle={styles.scrollContent}>
        
        {/* Page 1: Welcome Screen */}
        <OnboardingPage>
          <LinearGradient
            colors={['#60A5FA', '#2563EB']}
            style={styles.welcomeContainer}>
            <View style={styles.logoContainer}>
              <MaterialIcons name="security" size={120} color="#FFFFFF" />
            </View>
            <Text style={styles.welcomeTitle}>Welcome to SafeTNet, the #1</Text>
            <Text style={styles.welcomeTitle}>personal safety app.</Text>
            <Text style={styles.welcomeSubtitle}>Let's take a couple of minutes to</Text>
            <Text style={styles.welcomeSubtitle}>walk through how the app works.</Text>
          </LinearGradient>
        </OnboardingPage>

        {/* Page 2: Family Feature */}
        <OnboardingPage>
          <View style={styles.pageContent}>
            <View style={styles.diagramSection}>
              {renderPanicDiagram('family')}
            </View>
            <View style={styles.infoBoxContainer}>
              <View style={styles.infoBox}>
                <Text style={styles.infoText}>
                  Family button will send a notification to up to three people when you need help. It will provide your location via text, email and within the app. Family member must download free version of the app.
                </Text>
                <Text style={styles.infoText}>
                  Set up your family members by clicking on the menu in the top, left hand corner of the app and selecting Emergency Contacts.
                </Text>
              </View>
            </View>
          </View>
        </OnboardingPage>

        {/* Page 3: Community Feature */}
        <OnboardingPage>
          <View style={styles.pageContent}>
            <View style={styles.diagramSection}>
              {renderPanicDiagram('community')}
            </View>
            <View style={styles.infoBoxContainer}>
              <View style={styles.infoBox}>
                <Text style={styles.infoText}>
                  Community allows you to create or be a part of a community. This is anywhere you work, live or play, and includes neighborhoods and work teams.
                </Text>
                <Text style={styles.infoText}>
                  This feature allows you to send an emergency message to the members in your community or upload pictures, video and audio to share with your group.
                </Text>
              </View>
            </View>
          </View>
        </OnboardingPage>

        {/* Page 4: Police Feature */}
        <OnboardingPage>
          <View style={styles.pageContent}>
            <View style={styles.diagramSection}>
              {renderPanicDiagram('police')}
            </View>
            <View style={styles.infoBoxContainer}>
              <View style={styles.infoBox}>
                <Text style={styles.infoText}>
                  Police, Family, Community and Security are features in the app. They will show in blue when it is available.
                </Text>
                <Text style={styles.infoText}>
                  If you downloaded the free version, only Police will be available. Police will contact 911 directly.
                </Text>
              </View>
            </View>
          </View>
        </OnboardingPage>

        {/* Page 5: Security Feature */}
        <OnboardingPage>
          <View style={styles.pageContent}>
            <View style={styles.diagramSection}>
              {renderPanicDiagram('security')}
            </View>
            <View style={styles.infoBoxContainer}>
              <View style={styles.infoBox}>
                <Text style={styles.infoText}>
                  The Security feature will turn blue or be available when businesses*, schools and venues are a SafeTNet partner and have onsite security/law enforcement. By selecting this button, security will notified of your location and respond quickly to your request for help. This button will remain gray when security is not available.
                </Text>
                <Text style={styles.infoTextSmall}>*malls, apartment complexes, etc.</Text>
              </View>
            </View>
          </View>
        </OnboardingPage>

        {/* Page 6: Panic Button + Get Started */}
        <OnboardingPage>
          <View style={styles.pageContent}>
            <View style={styles.diagramSection}>
              {renderPanicDiagram('police')}
            </View>
            <View style={styles.infoBoxContainer}>
              <View style={styles.infoBox}>
                <Text style={styles.infoText}>
                  Selecting the Panic button will activate all communications to Police, Family, Community and Security, if contacts have been set up and security is available.
                </Text>
              </View>
              
              <View style={styles.bottomSection}>
              <TouchableOpacity
                style={styles.videoButton}
                onPress={() => {
                  // TODO: Open video instructions
                }}>
                <Text style={styles.videoButtonText}>CLICK HERE TO OPEN VIDEO INSTRUCTIONS.</Text>
              </TouchableOpacity>

              <View style={styles.checkboxContainer}>
                <TouchableOpacity
                  onPress={() => setAgreeTerms(!agreeTerms)}
                  style={styles.checkbox}>
                  {agreeTerms ? (
                    <MaterialIcons name="check-box" size={24} color="#FFFFFF" />
                  ) : (
                    <MaterialIcons name="check-box-outline-blank" size={24} color="#FFFFFF" />
                  )}
                </TouchableOpacity>
                <TouchableOpacity
                  onPress={() => setAgreeTerms(!agreeTerms)}
                  style={styles.checkboxLabel}>
                  <Text style={styles.checkboxText}>
                    I agree to the{' '}
                    <Text style={styles.linkText}>Term of services</Text>
                    {' '}and{' '}
                    <Text style={styles.linkText}>Privacy Policy</Text>
                  </Text>
                </TouchableOpacity>
              </View>

              <TouchableOpacity
                style={[
                  styles.getStartedButton,
                  agreeTerms && styles.getStartedButtonActive,
                  !agreeTerms && styles.getStartedButtonDisabled,
                ]}
                onPress={handleGetStarted}
                disabled={!agreeTerms}>
                <Text style={[styles.getStartedText, agreeTerms && styles.getStartedTextActive]}>GET STARTED</Text>
              </TouchableOpacity>
            </View>
            </View>
          </View>
        </OnboardingPage>
      </ScrollView>
      
      {renderPaginationDots()}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#2563eb',
  },
  scrollView: {
    flex: 1,
  },
  scrollContent: {
    flexGrow: 1,
  },
  page: {
    width,
    flex: 1,
  },
  welcomeContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 40,
    paddingBottom: 60,
  },
  logoContainer: {
    width: 140,
    height: 140,
    marginBottom: 50,
    alignItems: 'center',
    justifyContent: 'center',
  },
  logoImage: {
    width: '100%',
    height: '100%',
  },
  welcomeTitle: {
    color: '#FFFFFF',
    fontSize: 28,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 4,
  },
  welcomeSubtitle: {
    color: '#FFFFFF',
    fontSize: 16,
    textAlign: 'center',
    marginTop: 24,
    lineHeight: 24,
  },
  pageContent: {
    flex: 1,
  },
  infoBoxContainer: {
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    height: height * 0.42,
    justifyContent: 'center',
    backgroundColor: '#2563eb',
  },
  diagramSection: {
    backgroundColor: '#FFFFFF',
    paddingTop: 50,
    paddingHorizontal: 20,
    paddingBottom: 20,
    height: height * 0.58,
    justifyContent: 'center',
    alignItems: 'center',
  },
  diagramContainer: {
    width: '100%',
    height: '100%',
    alignItems: 'center',
    justifyContent: 'center',
  },
  circleOuter: {
    width: width * 0.68,
    height: width * 0.68,
    borderRadius: (width * 0.68) / 2,
    backgroundColor: '#E5E7EB',
    position: 'relative',
    overflow: 'hidden',
    borderWidth: 2,
    borderColor: '#FFFFFF',
  },
  segment: {
    position: 'absolute',
    width: '50%',
    height: '50%',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1,
  },
  segmentTopLeft: {
    top: 0,
    left: 0,
    borderTopLeftRadius: width * 0.34,
  },
  segmentTopRight: {
    top: 0,
    right: 0,
    borderTopRightRadius: width * 0.34,
  },
  segmentBottomLeft: {
    bottom: 0,
    left: 0,
    borderBottomLeftRadius: width * 0.34,
  },
  segmentBottomRight: {
    bottom: 0,
    right: 0,
    borderBottomRightRadius: width * 0.34,
  },
  segmentText: {
    fontSize: 12,
    fontWeight: '600',
    marginTop: 4,
  },
  panicButton: {
    position: 'absolute',
    top: (width * 0.68) / 2 - 45,
    left: (width * 0.68) / 2 - 45,
    width: 90,
    height: 90,
    borderRadius: 45,
    backgroundColor: '#FFFFFF',
    borderWidth: 3,
    borderColor: '#E5E7EB',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 100,
    elevation: 5,
    shadowColor: '#000',
    shadowOffset: {width: 0, height: 2},
    shadowOpacity: 0.25,
    shadowRadius: 3.84,
  },
  panicText: {
    color: '#1E40AF',
    fontSize: 15,
    fontWeight: 'bold',
  },
  infoBox: {
    backgroundColor: '#1e40af',
    borderRadius: 12,
    padding: 12,
    marginHorizontal: 20,
  },
  bottomSection: {
    paddingHorizontal: 20,
    paddingTop: 8,
    paddingBottom: 50,
  },
  infoText: {
    color: '#FFFFFF',
    fontSize: 13,
    lineHeight: 18,
    marginBottom: 8,
  },
  infoTextSmall: {
    color: '#FFFFFF',
    fontSize: 13,
    lineHeight: 18,
    marginTop: 8,
  },
  videoButton: {
    backgroundColor: '#FFFFFF',
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#E5E7EB',
    paddingVertical: 12,
    paddingHorizontal: 16,
    marginBottom: 12,
  },
  videoButtonText: {
    color: '#6B7280',
    fontSize: 11,
    fontWeight: '600',
    textAlign: 'center',
  },
  checkboxContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
    paddingHorizontal: 4,
  },
  checkbox: {
    marginRight: 8,
  },
  checkboxLabel: {
    flex: 1,
  },
  checkboxText: {
    color: '#FFFFFF',
    fontSize: 11,
    lineHeight: 16,
  },
  linkText: {
    textDecorationLine: 'underline',
    fontWeight: '600',
  },
  getStartedButton: {
    backgroundColor: '#9CA3AF',
    borderRadius: 10,
    paddingVertical: 16,
    alignItems: 'center',
    marginTop: 4,
  },
  getStartedButtonActive: {
    backgroundColor: '#FFFFFF',
  },
  getStartedButtonDisabled: {
    backgroundColor: '#9CA3AF',
    opacity: 0.5,
  },
  getStartedText: {
    color: '#FFFFFF',
    fontSize: 16,
    fontWeight: 'bold',
    letterSpacing: 1,
  },
  getStartedTextActive: {
    color: '#2563eb',
  },
  paginationContainer: {
    position: 'absolute',
    bottom: 30,
    left: 0,
    right: 0,
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
    zIndex: 100,
  },
  paginationDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: 'rgba(255, 255, 255, 0.4)',
    marginHorizontal: 4,
  },
  paginationDotActive: {
    width: 10,
    height: 10,
    borderRadius: 5,
    backgroundColor: '#FFFFFF',
  },
});

export default OnboardingScreen;

