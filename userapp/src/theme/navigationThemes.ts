import {DefaultTheme, DarkTheme, Theme} from '@react-navigation/native';

const baseLightColors = {
  primary: '#2563EB',
  background: '#FFFFFF',
  card: '#F9FAFB',
  text: '#111827',
  border: '#E5E7EB',
  notification: '#6B7280',
};

const baseDarkColors = {
  primary: '#60A5FA',
  background: '#0F172A',
  card: '#1E293B',
  text: '#F8FAFC',
  border: '#334155',
  notification: '#CBD5F5',
};

export const LightAppTheme: Theme = {
  ...DefaultTheme,
  colors: {
    ...DefaultTheme.colors,
    ...baseLightColors,
  },
};

export const DarkAppTheme: Theme = {
  ...DarkTheme,
  colors: {
    ...DarkTheme.colors,
    ...baseDarkColors,
  },
};


