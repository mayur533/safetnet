import React from 'react';
import {View, Text, TouchableOpacity, StyleSheet, Platform, StatusBar} from 'react-native';
import {useSafeAreaInsets} from 'react-native-safe-area-context';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';

interface CustomHeaderProps {
  title: string;
  onMenuPress: () => void;
  onSettingsPress?: () => void;
  showNotification?: boolean;
}

const CustomHeader: React.FC<CustomHeaderProps> = ({
  title,
  onMenuPress,
  onSettingsPress,
  showNotification = false,
}) => {
  const insets = useSafeAreaInsets();
  const statusBarHeight = Platform.OS === 'android' ? StatusBar.currentHeight || 0 : insets.top;

  return (
    <View style={[styles.header, {paddingTop: statusBarHeight}]}>
      <View style={styles.headerContent}>
        <TouchableOpacity onPress={onMenuPress} style={styles.menuButton}>
          <MaterialIcons name="menu" size={24} color="#374151" />
        </TouchableOpacity>
        
        <Text style={styles.title}>{title}</Text>
        
        <TouchableOpacity
          onPress={onSettingsPress}
          style={styles.settingsButton}>
          <View style={styles.settingsContainer}>
            <MaterialIcons name="settings" size={24} color="#374151" />
            {showNotification && <View style={styles.notificationDot} />}
          </View>
        </TouchableOpacity>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  header: {
    backgroundColor: '#F3F4F6',
    borderBottomWidth: 1,
    borderBottomColor: '#E5E7EB',
  },
  headerContent: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    height: 56,
    paddingHorizontal: 16,
  },
  menuButton: {
    padding: 8,
  },
  title: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#374151',
    flex: 1,
    textAlign: 'center',
  },
  settingsButton: {
    padding: 8,
  },
  settingsContainer: {
    position: 'relative',
  },
  notificationDot: {
    position: 'absolute',
    top: 0,
    right: 0,
    width: 10,
    height: 10,
    borderRadius: 5,
    backgroundColor: '#10B981',
    borderWidth: 2,
    borderColor: '#F3F4F6',
  },
});

export default CustomHeader;

