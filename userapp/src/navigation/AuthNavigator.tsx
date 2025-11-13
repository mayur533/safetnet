import React, {useState} from 'react';
import {createStackNavigator} from '@react-navigation/stack';
import {useNavigation} from '@react-navigation/native';
import LoginScreen from '../screens/auth/LoginScreen';
import RegistrationScreen from '../screens/auth/RegistrationScreen';
import OnboardingScreen from '../screens/onboarding/OnboardingScreen';
import HowItWorksScreen from '../screens/howitworks/HowItWorksScreen';
import HomeScreen from '../screens/main/HomeScreen';
import CustomHeader from '../components/common/CustomHeader';
import CustomDrawer from '../components/common/CustomDrawer';

const Stack = createStackNavigator();

const AuthNavigator = () => {
  const [drawerVisible, setDrawerVisible] = useState(false);
  const navigation = useNavigation<any>();

  return (
    <>
      <Stack.Navigator
        screenOptions={{
          headerShown: true,
          header: ({route}) => {
            if (route.name === 'Home') {
              return (
                <CustomHeader
                  title="HOME"
                  onMenuPress={() => setDrawerVisible(true)}
                />
              );
            }
            return null;
          },
        }}>
        <Stack.Screen name="Login" component={LoginScreen} options={{headerShown: false}} />
        <Stack.Screen name="Registration" component={RegistrationScreen} options={{headerShown: false}} />
        <Stack.Screen name="Onboarding" component={OnboardingScreen} options={{headerShown: false}} />
        <Stack.Screen name="HowItWorks" component={HowItWorksScreen} options={{headerShown: false}} />
        <Stack.Screen name="Home" component={HomeScreen} />
      </Stack.Navigator>
      <CustomDrawer 
        visible={drawerVisible} 
        onClose={() => setDrawerVisible(false)} 
        navigation={navigation}
        showLoginModal={() => {
          setDrawerVisible(false);
          // Trigger login modal in HomeScreen
          navigation.navigate('Home', {showLoginModal: true});
        }}
      />
    </>
  );
};

export default AuthNavigator;


