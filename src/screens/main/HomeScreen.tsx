import React, {useState, useEffect, useRef, useCallback, useMemo} from 'react';
import {useRoute, useTheme} from '@react-navigation/native';
import type {Theme} from '@react-navigation/native';
import {
  View,
  Text,
  TouchableOpacity,
  Linking,
  Platform,
  PermissionsAndroid,
  Alert,
} from 'react-native';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useAuthStore} from '../../stores/authStore';
import {useSettingsStore} from '../../stores/settingsStore';
import {CustomVibration} from '../../modules/VibrationModule';
import {shakeDetectionService} from '../../services/shakeDetectionService';
import {useTheme as useNavigationTheme} from '@react-navigation/native'; // Import useTheme
import {dispatchSOSAlert} from '../../services/sosDispatcher';
import {requestDirectCall} from '../../services/callService';
import {useTheme as navigationUseTheme} from '@react-navigation/native';
import {addSosTriggerListener} from '../../services/sosEventBus';
