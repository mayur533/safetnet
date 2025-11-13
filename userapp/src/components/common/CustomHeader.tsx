import React from 'react';
import {View, Text, TouchableOpacity, StyleSheet, Platform, StatusBar} from 'react-native';
import {useSafeAreaInsets} from 'react-native-safe-area-context';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import LinearGradient from 'react-native-linear-gradient';
import {useAuthStore} from '../../stores/authStore';
import {useTheme} from '@react-navigation/native';

interface CustomHeaderProps {
  title: string;
  onMenuPress: () => void;
  onUpgradePress?: () => void;
  showPremiumCTA?: boolean;
}

const CustomHeader: React.FC<CustomHeaderProps> = ({
  title,
  onMenuPress,
  onUpgradePress,
  showPremiumCTA = true,
}) => {
  const insets = useSafeAreaInsets();
  const statusBarHeight = Platform.OS === 'android' ? StatusBar.currentHeight || 0 : insets.top;
  const user = useAuthStore((state) => state.user);
  const isFreeUser = showPremiumCTA && (user?.plan !== 'premium');
  const theme = useTheme();
  const colors = theme.colors;

  return (
    <View
      style={[styles.header, {paddingTop: statusBarHeight, backgroundColor: colors.card, borderBottomColor: colors.border}]}> 
      {/* Top row - Drawer, Title with icon, Settings */}
      <View style={styles.headerTopRow}>
        {/* Left side - Drawer icon */}
        <TouchableOpacity onPress={onMenuPress} style={styles.menuButton}>
          <MaterialIcons name="menu" size={24} color={colors.text} />
        </TouchableOpacity>
        
        {/* Left - Title aligned to left */}
        <View style={styles.titleContainer}>
          <Text style={[styles.title, {color: colors.text}]}>{title}</Text>
        </View>

        {/* Right side actions */}
        <View style={styles.rightActions}>
          {isFreeUser && (
            <TouchableOpacity
              activeOpacity={0.85}
              onPress={onUpgradePress}
              style={styles.premiumButtonWrapper}>
              <LinearGradient
                colors={['#F97316', '#FB923C']}
                start={{x: 0, y: 0}}
                end={{x: 1, y: 1}}
                style={styles.premiumButton}>
                <MaterialIcons name="bolt" size={16} color="#FFFFFF" />
                <Text style={styles.premiumButtonText}>Buy Premium</Text>
              </LinearGradient>
            </TouchableOpacity>
          )}
        </View>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  header: {
    borderBottomWidth: 1,
    paddingBottom: 8,
    minHeight: 48,
  },
  headerTopRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingTop: 8,
    paddingBottom: 8,
  },
  menuButton: {
    padding: 4,
    width: 40,
    alignItems: 'flex-start',
  },
  titleContainer: {
    flex: 1,
    alignItems: 'flex-start',
    justifyContent: 'center',
    marginLeft: 12,
  },
  title: {
    fontSize: 18,
    fontWeight: 'bold',
    textAlign: 'left',
  },
  rightActions: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'flex-end',
    gap: 8,
  },
  premiumButtonWrapper: {
    borderRadius: 999,
    overflow: 'hidden',
  },
  premiumButton: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 6,
    paddingHorizontal: 12,
    borderRadius: 999,
    shadowColor: '#F97316',
    shadowOffset: {width: 0, height: 2},
    shadowOpacity: 0.25,
    shadowRadius: 3.5,
    elevation: 4,
  },
  premiumButtonText: {
    color: '#FFFFFF',
    fontSize: 13,
    fontWeight: '600',
    marginLeft: 6,
    letterSpacing: 0.3,
  },
});

export default CustomHeader;

