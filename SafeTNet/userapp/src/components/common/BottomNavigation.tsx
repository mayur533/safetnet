import React from 'react';
import {View, TouchableOpacity, StyleSheet} from 'react-native';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useNavigation} from '@react-navigation/native';

interface BottomNavigationProps {
  currentRoute?: string;
}

const BottomNavigation: React.FC<BottomNavigationProps> = ({currentRoute}) => {
  const navigation = useNavigation<any>();

  const menuItems = [
    {name: 'Home', icon: 'home', route: 'Home'},
    {name: 'Alert', icon: 'notifications', route: 'Alert'},
    {name: 'Community', icon: 'groups', route: 'Community'},
    {name: 'Profile', icon: 'person', route: 'Profile'},
  ];

  return (
    <View style={styles.container}>
      {menuItems.map((item, index) => {
        const isActive = currentRoute === item.route;
        return (
          <TouchableOpacity
            key={index}
            style={styles.tab}
            onPress={() => navigation.navigate(item.route)}
            activeOpacity={0.7}>
            <MaterialIcons
              name={item.icon}
              size={24}
              color={isActive ? '#2563EB' : '#9CA3AF'}
            />
          </TouchableOpacity>
        );
      })}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    height: 60,
    backgroundColor: '#FFFFFF',
    borderTopWidth: 1,
    borderTopColor: '#E5E7EB',
    paddingHorizontal: 8,
    paddingBottom: 8,
    paddingTop: 8,
  },
  tab: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
});

export default BottomNavigation;

