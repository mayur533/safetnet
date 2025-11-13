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
  Image,
} from 'react-native';
import MaterialIcons from 'react-native-vector-icons/MaterialIcons';
import {useAuthStore} from '../../stores/authStore';
import {useNavigation} from '@react-navigation/native';

const RegistrationScreen = () => {
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [phoneNo, setPhoneNo] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [agreeTerms, setAgreeTerms] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<{message: string; type: 'validation' | 'critical'} | null>(null);
  const login = useAuthStore((state) => state.login);
  const navigation = useNavigation<any>();

  const handleRegister = async () => {
    setError(null);
    
    if (!firstName || !lastName || !email || !phoneNo || !password) {
      setError({message: 'Please fill in all fields', type: 'validation'});
      return;
    }

    if (!agreeTerms) {
      setError({message: 'Please agree to the Terms of Use', type: 'validation'});
      return;
    }

    setLoading(true);
    try {
      // TODO: Implement actual registration logic
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1500));
      // Auto login after registration
      login(email, password);
    } catch (error) {
      setError({message: 'Registration failed. Please try again.', type: 'critical'});
    } finally {
      setLoading(false);
    }
  };

  const clearError = () => {
    if (error) setError(null);
  };

  const handleSkip = () => {
    // Skip to login with demo credentials
    login('demo@example.com', 'demo123');
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
              {/* App Logo Image */}
              <View style={styles.logoImageContainer}>
                <Image
                  source={require('../../assets/images/app_logo.png')}
                  style={styles.logoImage}
                  resizeMode="contain"
                />
              </View>

              {/* Welcome Text */}
              <Text style={styles.welcomeText}>
                Create Your Account
              </Text>
            </View>

            {/* Form Section */}
            <View style={styles.formSection}>
              {/* First Name Input */}
              <View style={styles.inputContainer}>
                <MaterialIcons name="person" size={20} color="#6B7280" style={styles.inputIcon} />
                <TextInput
                  style={styles.input}
                  placeholder="First Name"
                  placeholderTextColor="#9CA3AF"
                  value={firstName}
                  onChangeText={(text) => {
                    setFirstName(text);
                    clearError();
                  }}
                  autoCapitalize="words"
                />
              </View>

              {/* Last Name Input */}
              <View style={styles.inputContainer}>
                <MaterialIcons name="person" size={20} color="#6B7280" style={styles.inputIcon} />
                <TextInput
                  style={styles.input}
                  placeholder="Last Name"
                  placeholderTextColor="#9CA3AF"
                  value={lastName}
                  onChangeText={(text) => {
                    setLastName(text);
                    clearError();
                  }}
                  autoCapitalize="words"
                />
              </View>

              {/* Email Input */}
              <View style={styles.inputContainer}>
                <MaterialIcons name="email" size={20} color="#6B7280" style={styles.inputIcon} />
                <TextInput
                  style={styles.input}
                  placeholder="Email"
                  placeholderTextColor="#9CA3AF"
                  value={email}
                  onChangeText={(text) => {
                    setEmail(text);
                    clearError();
                  }}
                  keyboardType="email-address"
                  autoCapitalize="none"
                  autoComplete="email"
                />
              </View>

              {/* Phone Number Input */}
              <View style={styles.inputContainer}>
                <MaterialIcons name="phone" size={20} color="#6B7280" style={styles.inputIcon} />
                <TextInput
                  style={styles.input}
                  placeholder="Phone Number"
                  placeholderTextColor="#9CA3AF"
                  value={phoneNo}
                  onChangeText={(text) => {
                    setPhoneNo(text);
                    clearError();
                  }}
                  keyboardType="phone-pad"
                  autoComplete="tel"
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
                  onChangeText={(text) => {
                    setPassword(text);
                    clearError();
                  }}
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

              {/* Terms and Conditions Checkbox */}
              <View style={styles.checkboxContainer}>
                <TouchableOpacity
                  onPress={() => {
                    setAgreeTerms(!agreeTerms);
                    clearError();
                  }}
                  style={styles.checkbox}>
                  {agreeTerms ? (
                    <MaterialIcons name="check-box" size={24} color="#FFFFFF" />
                  ) : (
                    <MaterialIcons name="check-box-outline-blank" size={24} color="#FFFFFF" />
                  )}
                </TouchableOpacity>
                <TouchableOpacity
                  onPress={() => {
                    setAgreeTerms(!agreeTerms);
                    clearError();
                  }}
                  style={styles.checkboxLabel}>
                  <Text style={styles.checkboxText}>
                    I agree to the{' '}
                    <Text style={styles.linkText}>Terms of Use</Text>
                  </Text>
                </TouchableOpacity>
              </View>

              {/* REGISTER Button */}
              <TouchableOpacity
                onPress={handleRegister}
                disabled={loading || !agreeTerms}
                style={[
                  styles.registerButton,
                  (loading || !agreeTerms) && styles.buttonDisabled,
                ]}>
                <Text style={styles.registerButtonText}>
                  {loading ? 'REGISTERING...' : 'REGISTER'}
                </Text>
              </TouchableOpacity>

              {/* Login Link */}
              <View style={styles.loginContainer}>
                <Text style={styles.loginText}>Already have an account? </Text>
                <TouchableOpacity onPress={() => navigation.navigate('Login')}>
                  <Text style={styles.loginLinkText}>LOGIN</Text>
                </TouchableOpacity>
              </View>
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
  checkboxContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 16,
    marginTop: 4,
  },
  checkbox: {
    marginRight: 8,
  },
  checkboxLabel: {
    flex: 1,
  },
  checkboxText: {
    color: '#FFFFFF',
    fontSize: 13,
    fontWeight: '500',
  },
  linkText: {
    color: '#FFFFFF',
    fontSize: 13,
    fontWeight: '600',
    textDecorationLine: 'underline',
  },
  registerButton: {
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
  registerButtonText: {
    color: '#2563eb',
    fontSize: 16,
    fontWeight: 'bold',
    letterSpacing: 0.5,
    textAlign: 'center',
  },
  loginContainer: {
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
    marginTop: 6,
  },
  loginText: {
    color: '#FFFFFF',
    fontSize: 13,
    fontWeight: '500',
  },
  loginLinkText: {
    color: '#FFFFFF',
    fontSize: 13,
    fontWeight: 'bold',
    textDecorationLine: 'underline',
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

export default RegistrationScreen;

