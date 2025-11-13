import React, {useState, useEffect, useMemo} from 'react';
import {View, Text, TouchableOpacity, Modal, BackHandler, StyleSheet} from 'react-native';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import Ionicons from 'react-native-vector-icons/Ionicons';
import {useTheme} from '@react-navigation/native';
import type {Theme} from '@react-navigation/native';
import {useAuthStore} from '../../stores/authStore';

interface CustomDrawerProps {
  visible: boolean;
  onClose: () => void;
  navigation: any;
  showLoginModal?: () => void;
}

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

type DrawerThemeTokens = {
  borderColor: string;
  cardShadowColor: string;
  mutedTextColor: string;
  iconMutedColor: string;
  activeBackground: string;
  overlayColor: string;
};

const CustomDrawer = ({visible, onClose, navigation, showLoginModal}: CustomDrawerProps) => {
  const theme = useTheme();
  const {colors} = theme;
  const isDarkMode = theme.dark;

  const themeTokens = useMemo<DrawerThemeTokens>(() => ({
    borderColor: withAlpha(colors.border, isDarkMode ? 0.7 : 1),
    cardShadowColor: isDarkMode ? 'rgba(15, 23, 42, 0.5)' : '#000000',
    mutedTextColor: isDarkMode ? 'rgba(226, 232, 240, 0.75)' : '#6B7280',
    iconMutedColor: isDarkMode ? 'rgba(203, 213, 225, 0.85)' : '#6B7280',
    activeBackground: isDarkMode ? withAlpha(colors.primary, 0.3) : withAlpha(colors.primary, 0.12),
    overlayColor: 'rgba(0, 0, 0, 0.5)',
  }), [colors, isDarkMode]);

  const styles = useMemo(() => createStyles(colors, themeTokens, isDarkMode), [colors, themeTokens, isDarkMode]);
  const {mutedTextColor, iconMutedColor} = themeTokens;

  const logout = useAuthStore((state) => state.logout);
  const user = useAuthStore((state) => state.user);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const [activeScreen, setActiveScreen] = useState('Home');
  
  // Get user name - use email if name is not available
  const userName = user?.name || user?.email?.split('@')[0] || 'User';
  
  // Get time-based greeting
  const getGreeting = () => {
    const hour = new Date().getHours();
    if (hour < 12) {
      return 'Good Morning';
    } else if (hour < 17) {
      return 'Good Afternoon';
    } else {
      return 'Good Evening';
    }
  };
  
  const greeting = getGreeting();

  useEffect(() => {
    if (visible) {
      const backHandler = BackHandler.addEventListener('hardwareBackPress', () => {
        onClose();
        return true;
      });
      return () => backHandler.remove();
    }
  }, [visible, onClose]);

  // Get current route name
  useEffect(() => {
    const unsubscribe = navigation.addListener('state', () => {
      const route = navigation.getState()?.routes[navigation.getState()?.index || 0];
      if (route) {
        setActiveScreen(route.name);
      }
    });
    return unsubscribe;
  }, [navigation]);

  const handleNavigate = (screenName: string) => {
    // Check if user is authenticated for protected screens
    const protectedScreens = ['Alert', 'Community', 'Family', 'Profile', 'Settings'];
    
    if (!isAuthenticated && protectedScreens.includes(screenName)) {
      // Close drawer and show login modal
      onClose();
      if (showLoginModal) {
        showLoginModal();
      }
      return;
    }

    // Allow navigation to Home and HowItWorks without authentication
    if (screenName === 'Home' || screenName === 'HowItWorks' || screenName === 'SafetyTips') {
      setActiveScreen(screenName);
      navigation.navigate(screenName);
      onClose();
      return;
    }

    // For authenticated users, navigate normally
    if (isAuthenticated) {
      setActiveScreen(screenName);
      navigation.navigate(screenName);
      onClose();
    } else {
      // Close drawer and show login modal
      onClose();
      if (showLoginModal) {
        showLoginModal();
      }
    }
  };

  const handleSettings = () => {
    if (!isAuthenticated) {
      onClose();
      if (showLoginModal) {
        showLoginModal();
      }
      return;
    }
    navigation.navigate('Settings');
    onClose();
  };

  const handleProfile = () => {
    if (!isAuthenticated) {
      onClose();
      if (showLoginModal) {
        showLoginModal();
      }
      return;
    }
    navigation.navigate('Profile');
    onClose();
  };

  const menuItems = [
    {name: 'Home', screen: 'Home', icon: 'home', iconType: 'MaterialIcons'},
    {name: 'Alert', screen: 'Alert', icon: 'notifications', iconType: 'MaterialIcons'},
    {name: 'Community', screen: 'Community', icon: 'groups', iconType: 'MaterialIcons'},
    {name: 'Family', screen: 'Family', icon: 'family-restroom', iconType: 'MaterialIcons'},
    {name: 'Safety Tips', screen: 'SafetyTips', icon: 'security', iconType: 'MaterialIcons'},
    {name: 'How it works', screen: 'HowItWorks', icon: 'help-outline', iconType: 'MaterialIcons'},
  ];

  return (
    <Modal
      visible={visible}
      transparent
      animationType="fade"
      onRequestClose={onClose}>
      <View style={styles.drawerContainer}>
        {/* Drawer Content - Left Side */}
        <View style={styles.drawerContent}>
          {/* Profile/User Section - White background matching home screen */}
          <TouchableOpacity
            style={styles.profileSection}
            onPress={handleProfile}
            activeOpacity={0.7}>
            <View style={styles.userIconCircle}>
              <MaterialIcons name="account-circle" size={60} color={colors.primary} />
            </View>
            <Text style={styles.greetingText}>{greeting}</Text>
            <Text style={styles.userNameText}>{userName}</Text>
          </TouchableOpacity>

          {/* Menu Items */}
          <View style={styles.menuContainer}>
            {menuItems.map((item, index) => {
              const isActive = activeScreen === item.screen;
              const IconComponent = item.iconType === 'MaterialIcons' ? MaterialIcons : Ionicons;
              return (
                <TouchableOpacity
                  key={index}
                  style={[styles.menuItem, isActive && styles.menuItemActive]}
                  onPress={() => handleNavigate(item.screen)}
                  activeOpacity={0.7}>
                  <IconComponent
                    name={item.icon}
                    size={24}
                    color={isActive ? colors.primary : iconMutedColor}
                    style={styles.menuIcon}
                  />
                  <Text style={[styles.menuText, isActive && styles.menuTextActive]}>{item.name}</Text>
                </TouchableOpacity>
              );
            })}
          </View>

          {/* Settings Button */}
          <TouchableOpacity
            style={styles.settingsButton}
            onPress={handleSettings}
            activeOpacity={0.7}>
            <MaterialIcons name="settings" size={24} color={colors.primary} style={styles.menuIcon} />
            <Text style={styles.settingsText}>Settings</Text>
          </TouchableOpacity>
        </View>
        
        {/* Overlay - Right Side */}
        <TouchableOpacity
          style={styles.overlay}
          activeOpacity={1}
          onPress={onClose}
        />
      </View>
    </Modal>
  );
};

const createStyles = (colors: Theme['colors'], tokens: DrawerThemeTokens, isDarkMode: boolean) =>
  StyleSheet.create({
    drawerContainer: {
      flex: 1,
      flexDirection: 'row',
    },
    drawerContent: {
      width: '75%',
      maxWidth: 320,
      backgroundColor: colors.card,
      paddingTop: 20,
      paddingBottom: 20,
      shadowColor: tokens.cardShadowColor,
      shadowOffset: {width: 2, height: 0},
      shadowOpacity: isDarkMode ? 0.35 : 0.25,
      shadowRadius: isDarkMode ? 6 : 3.84,
      elevation: isDarkMode ? 6 : 5,
    },
    profileSection: {
      alignItems: 'center',
      paddingVertical: 24,
      paddingHorizontal: 20,
      borderBottomWidth: 1,
      borderBottomColor: tokens.borderColor,
      marginBottom: 8,
    },
    userIconCircle: {
      marginBottom: 12,
    },
    greetingText: {
      fontSize: 14,
      color: tokens.mutedTextColor,
      marginBottom: 4,
    },
    userNameText: {
      fontSize: 18,
      fontWeight: 'bold',
      color: colors.text,
    },
    menuContainer: {
      paddingVertical: 8,
    },
    menuItem: {
      flexDirection: 'row',
      alignItems: 'center',
      paddingVertical: 14,
      paddingHorizontal: 20,
    },
    menuItemActive: {
      backgroundColor: tokens.activeBackground,
      borderLeftWidth: 4,
      borderLeftColor: colors.primary,
    },
    menuIcon: {
      marginRight: 16,
    },
    menuText: {
      fontSize: 16,
      color: colors.text,
    },
    menuTextActive: {
      color: colors.primary,
      fontWeight: '600',
    },
    settingsButton: {
      flexDirection: 'row',
      alignItems: 'center',
      paddingVertical: 14,
      paddingHorizontal: 20,
      marginTop: 'auto',
      borderTopWidth: 1,
      borderTopColor: tokens.borderColor,
    },
    settingsText: {
      fontSize: 16,
      color: colors.primary,
      fontWeight: '600',
    },
    overlay: {
      flex: 1,
      backgroundColor: tokens.overlayColor,
    },
  });

export default CustomDrawer;

export default CustomDrawer;

