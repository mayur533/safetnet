import React, {useState} from 'react';
import {createStackNavigator} from '@react-navigation/stack';
import {useNavigation} from '@react-navigation/native';
import {Alert} from 'react-native';
import CustomHeader from '../components/common/CustomHeader';
import CustomDrawer from '../components/common/CustomDrawer';
import {useAuthStore} from '../stores/authStore';
import HomeScreen from '../screens/main/HomeScreen';
import TraceMeScreen from '../screens/traceme/TraceMeScreen';
import EmergencyContactScreen from '../screens/emergency/EmergencyContactScreen';
import GeofenceAreaScreen from '../screens/geofence/GeofenceAreaScreen';
import AreaMapScreen from '../screens/maps/AreaMapScreen';
import SafetyTipsScreen from '../screens/safety/SafetyTipsScreen';
import HowItWorksScreen from '../screens/howitworks/HowItWorksScreen';
import SupportContactScreen from '../screens/support/SupportContactScreen';
import ProfileScreen from '../screens/profile/ProfileScreen';
import SettingsScreen from '../screens/settings/SettingsScreen';
import AlertsScreen from '../screens/alerts/AlertsScreen';
import ChatScreen from '../screens/chat/ChatScreen';
import CommunityScreen from '../screens/community/CommunityScreen';
import CreateGroupScreen from '../screens/community/CreateGroupScreen';
import GroupDetailsScreen from '../screens/community/GroupDetailsScreen';

const Stack = createStackNavigator();

const AppNavigator = () => {
  const [drawerVisible, setDrawerVisible] = useState(false);
  const navigation = useNavigation<any>();
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  const handleUpgradePress = () => {
    Alert.alert('Upgrade to Premium', 'Premium purchase options will be available soon.');
  };

  // Screen configurations with icons and subtitles
  const getScreenConfig = (routeName: string) => {
    const configs: {[key: string]: {icon: string; title: string; subtitle: string}} = {
      'Home': {icon: 'home', title: 'HOME', subtitle: isAuthenticated ? 'Your safety dashboard' : 'Login to use this feature'},
      'Alert': {icon: 'notifications', title: 'ALERT', subtitle: 'View and manage alerts'},
      'Community': {icon: 'groups', title: 'COMMUNITY', subtitle: 'Connect with your community'},
      'Chat': {icon: 'chat', title: 'CHAT', subtitle: 'Group conversation'},
      'Family': {icon: 'family-restroom', title: 'Family & Emergency', subtitle: 'Manage your emergency contacts'},
      'SafetyTips': {icon: 'security', title: 'SAFETY TIPS', subtitle: 'Learn how to stay safe'},
      'HowItWorks': {icon: 'help-outline', title: 'HOW IT WORKS', subtitle: 'Learn about the app features'},
      'Profile': {icon: 'account-circle', title: 'PROFILE', subtitle: 'Manage your account information'},
      'Settings': {icon: 'settings', title: 'SETTINGS', subtitle: 'Configure app preferences'},
    };
    return configs[routeName] || {icon: '', title: routeName, subtitle: ''};
  };

  return (
    <>
      <Stack.Navigator
        initialRouteName="Home"
        screenOptions={{
          headerShown: true,
          header: ({route, options}) => {
            const config = getScreenConfig(route.name);
            return (
              <CustomHeader
                title={config.title}
                onMenuPress={() => setDrawerVisible(true)}
                onUpgradePress={handleUpgradePress}
                showPremiumCTA={route.name === 'Home'}
              />
            );
          },
          gestureEnabled: false, // Disable swipe back gesture
        }}>
        <Stack.Screen
          name="Home"
          component={HomeScreen}
          options={{headerTitle: 'HOME'}}
        />
        <Stack.Screen
          name="Alert"
          component={AlertsScreen}
          options={{headerTitle: 'ALERT'}}
        />
        <Stack.Screen
          name="Community"
          component={CommunityScreen}
          options={{headerTitle: 'COMMUNITY'}}
        />
        <Stack.Screen
          name="Chat"
          component={ChatScreen}
          options={{headerShown: false}}
        />
        <Stack.Screen
          name="CreateGroup"
          component={CreateGroupScreen}
          options={{headerShown: false}}
        />
        <Stack.Screen
          name="GroupDetails"
          component={GroupDetailsScreen}
          options={{headerShown: false}}
        />
        <Stack.Screen
          name="Family"
          component={EmergencyContactScreen}
          options={{headerTitle: 'FAMILY'}}
        />
        <Stack.Screen
          name="SafetyTips"
          component={SafetyTipsScreen}
          options={{headerTitle: 'SAFETY TIPS'}}
        />
        <Stack.Screen
          name="HowItWorks"
          component={HowItWorksScreen}
          options={{headerShown: false}}
        />
        <Stack.Screen
          name="Profile"
          component={ProfileScreen}
          options={{headerTitle: 'PROFILE'}}
        />
        <Stack.Screen
          name="Settings"
          component={SettingsScreen}
          options={{headerTitle: 'SETTINGS'}}
        />
        {/* Keep other screens for backwards compatibility */}
        <Stack.Screen
          name="TraceMe"
          component={TraceMeScreen}
          options={{headerTitle: 'TRACE ME'}}
        />
        <Stack.Screen
          name="EmergencyContact"
          component={EmergencyContactScreen}
          options={{headerTitle: 'EMERGENCY CONTACT'}}
        />
        <Stack.Screen
          name="GeofenceArea"
          component={GeofenceAreaScreen}
          options={{headerTitle: 'GEOFENCE AREA'}}
        />
        <Stack.Screen
          name="AreaMap"
          component={AreaMapScreen}
          options={{headerTitle: 'AREA MAP'}}
        />
        <Stack.Screen
          name="SupportContact"
          component={SupportContactScreen}
          options={{headerTitle: 'SUPPORT CONTACTS'}}
        />
      </Stack.Navigator>
      <CustomDrawer 
        visible={drawerVisible} 
        onClose={() => setDrawerVisible(false)} 
        navigation={navigation}
        showLoginModal={() => {
          setDrawerVisible(false);
          // Navigate to Home and trigger login modal
          navigation.navigate('Home', {showLoginModal: true});
        }}
      />
    </>
  );
};

export default AppNavigator;
