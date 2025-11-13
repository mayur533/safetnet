import React, {useState} from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  KeyboardAvoidingView,
  Platform,
  ScrollView,
  Alert,
  StatusBar,
  StyleSheet,
} from 'react-native';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useAuthStore} from '../../stores/authStore';
import {useNavigation} from '@react-navigation/native';

const LoginScreen = () => {
  // Pre-fill with sample credentials
  const [email, setEmail] = useState('user@example.com');
  const [password, setPassword] = useState('password123');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<{message: string; type: 'validation' | 'critical'} | null>(null);
  const login = useAuthStore((state) => state.login);
  const navigation = useNavigation<any>();

  const handleLogin = async () => {
    setError(null);
    
    if (!email || !password) {
      setError({message: 'Please enter email and password', type: 'validation'});
      return;
    }

    setLoading(true);
    try {
      await login(email, password);
    } catch (error) {
      setError({message: 'Login failed. Please check your credentials and try again.', type: 'critical'});
    } finally {
      setLoading(false);
    }
  };

  const handleEmailChange = (text: string) => {
    setEmail(text);
    if (error) setError(null);
  };

  const handlePasswordChange = (text: string) => {
    setPassword(text);
    if (error) setError(null);
  };

  const handleSkip = () => {
    // Navigate to How It Works screen
    navigation.navigate('HowItWorks');
  };

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#2563eb" />
      {/* SKIP Button - Top Right */}
      <TouchableOpacity onPress={handleSkip} style={styles.skipButton}>
        <Text style={styles.skipText}>SKIP</Text>
      </TouchableOpacity>
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
        style={styles.keyboardView}>
        <ScrollView
          contentContainerStyle={styles.scrollContent}
          keyboardShouldPersistTaps="handled"
          showsVerticalScrollIndicator={false}>
          <View style={styles.contentWrapper}>

            {/* Logo Section */}
            <View style={styles.logoSection}>
              {/* Shield Icon */}
              <View style={styles.logoImageContainer}>
                <MaterialIcons name="security" size={100} color="#FFFFFF" />
              </View>

              {/* Welcome Text */}
              <Text style={styles.welcomeText}>
                Welcome To SafeTNet
              </Text>
            </View>

            {/* Form Section */}
            <View style={styles.formSection}>
              {/* Email Input */}
              <View style={styles.inputContainer}>
                <MaterialIcons name="person" size={20} color="#6B7280" style={styles.inputIcon} />
                <TextInput
                  style={styles.input}
                  placeholder="Email"
                  placeholderTextColor="#9CA3AF"
                  value={email}
                  onChangeText={handleEmailChange}
                  keyboardType="email-address"
                  autoCapitalize="none"
                  autoComplete="email"
                />
              </View>

              {/* Password Input */}
              <View style={styles.inputContainer}>
                <MaterialIcons name="lock" size={20} color="#6B7280" style={styles.inputIcon} />
                <TextInput
                  style={[styles.input, styles.passwordInput]}
                  placeholder="Password"
                  placeholderTextColor="#9CA3AF"
                  value={password}
                  onChangeText={handlePasswordChange}
                  secureTextEntry={!showPassword}
                  autoCapitalize="none"
                />
                <TouchableOpacity
                  onPress={() => setShowPassword(!showPassword)}
                  style={styles.eyeIcon}>
                  <MaterialIcons
                    name={showPassword ? "visibility" : "visibility-off"}
                    size={18}
                    color="#6B7280"
                  />
                </TouchableOpacity>
              </View>

              {/* Error Message */}
              {error ? (
                <View style={styles.errorContainer}>
                  <MaterialIcons 
                    name="error" 
                    size={16} 
                    color={error.type === 'critical' ? '#EF4444' : '#FCD34D'} 
                    style={styles.errorIcon} 
                  />
                  <Text style={[styles.errorText, {color: error.type === 'critical' ? '#EF4444' : '#FCD34D'}]}>
                    {error.message}
                  </Text>
                </View>
              ) : null}

              {/* Forgot Password Link */}
              <View style={styles.forgotPasswordContainer}>
                <TouchableOpacity
                  onPress={() => {
                    Alert.alert('Forgot Password', 'Password reset functionality coming soon');
                  }}>
                  <Text style={styles.linkText}>Forgot Password</Text>
                </TouchableOpacity>
              </View>

              {/* LOGIN Button */}
              <TouchableOpacity
                onPress={handleLogin}
                disabled={loading}
                style={[styles.loginButton, loading && styles.buttonDisabled]}>
                <Text style={styles.loginButtonText}>
                  {loading ? 'LOGGING IN...' : 'LOGIN'}
                </Text>
              </TouchableOpacity>

              {/* Create Account Link */}
              <View style={styles.createAccountContainer}>
                <Text style={styles.createAccountText}>Don't have an account? </Text>
                <TouchableOpacity onPress={() => navigation.navigate('Registration')}>
                  <Text style={styles.createAccountLinkText}>Create one</Text>
                </TouchableOpacity>
              </View>

              <TouchableOpacity
                style={styles.termsContainer}
                onPress={() => {
                  Alert.alert('Terms of Use', 'Terms and conditions coming soon');
                }}>
                <Text style={styles.linkText}>Terms of Use</Text>
              </TouchableOpacity>
            </View>
          </View>
        </ScrollView>
      </KeyboardAvoidingView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#2563eb',
  },
  keyboardView: {
    flex: 1,
  },
  scrollContent: {
    flexGrow: 1,
  },
  contentWrapper: {
    flex: 1,
    justifyContent: 'center',
    paddingHorizontal: 24,
    paddingVertical: 40,
  },
  skipButton: {
    position: 'absolute',
    top: Platform.OS === 'ios' ? 50 : 40,
    right: 20,
    zIndex: 1000,
    paddingVertical: 8,
    paddingHorizontal: 16,
  },
  skipText: {
    color: '#FFFFFF',
    fontSize: 14,
    fontWeight: '600',
  },
  logoSection: {
    alignItems: 'center',
    marginBottom: 32,
  },
  logoImageContainer: {
    width: 100,
    height: 100,
    marginBottom: 20,
    alignItems: 'center',
    justifyContent: 'center',
  },
  logoImage: {
    width: '100%',
    height: '100%',
  },
  welcomeText: {
    color: '#FFFFFF',
    fontSize: 22,
    fontWeight: 'bold',
    textAlign: 'center',
  },
  formSection: {
    width: '100%',
  },
  inputContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#E5E7EB',
    borderRadius: 10,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: '#D1D5DB',
    paddingHorizontal: 12,
    height: 48,
  },
  inputIcon: {
    marginRight: 10,
  },
  input: {
    flex: 1,
    fontSize: 15,
    color: '#111827',
    paddingVertical: 0,
  },
  passwordInput: {
    paddingRight: 36,
  },
  eyeIcon: {
    position: 'absolute',
    right: 12,
    padding: 4,
  },
  forgotPasswordContainer: {
    alignItems: 'flex-end',
    marginBottom: 12,
    marginTop: -4,
  },
  loginButton: {
    backgroundColor: '#FFFFFF',
    borderRadius: 10,
    paddingVertical: 12,
    paddingHorizontal: 16,
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 8,
    marginBottom: 12,
    width: '100%',
    shadowColor: '#000',
    shadowOffset: {width: 0, height: 2},
    shadowOpacity: 0.25,
    shadowRadius: 3.84,
    elevation: 5,
  },
  buttonDisabled: {
    opacity: 0.6,
  },
  loginButtonText: {
    color: '#2563eb',
    fontSize: 16,
    fontWeight: 'bold',
    letterSpacing: 0.5,
    textAlign: 'center',
  },
  createAccountContainer: {
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
    marginTop: 6,
    marginBottom: 12,
  },
  createAccountText: {
    color: '#FFFFFF',
    fontSize: 13,
    fontWeight: '500',
  },
  createAccountLinkText: {
    color: '#FFFFFF',
    fontSize: 13,
    fontWeight: 'bold',
    textDecorationLine: 'underline',
  },
  termsContainer: {
    alignItems: 'center',
    marginTop: 6,
  },
  linkText: {
    color: '#FFFFFF',
    fontSize: 13,
    fontWeight: '500',
  },
  errorContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 12,
  },
  errorIcon: {
    marginRight: 6,
  },
  errorText: {
    flex: 1,
    fontSize: 13,
    fontWeight: '500',
  },
});

export default LoginScreen;

