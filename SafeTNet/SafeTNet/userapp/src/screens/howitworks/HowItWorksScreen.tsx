import React from 'react';
import {View, Text, ScrollView} from 'react-native';

const HowItWorksScreen = () => {
  const steps = [
    {
      id: '1',
      title: 'Create Your Profile',
      description: 'Set up your account with personal information and emergency contacts.',
      icon: '👤',
    },
    {
      id: '2',
      title: 'Set Geofence Areas',
      description: 'Define safe zones and areas you want to monitor for alerts.',
      icon: '📍',
    },
    {
      id: '3',
      title: 'Enable Location Tracking',
      description: 'Allow the app to track your location for safety and emergency purposes.',
      icon: '📡',
    },
    {
      id: '4',
      title: 'Use Panic Button',
      description: 'In case of emergency, press the panic button to alert all contacts instantly.',
      icon: '🚨',
    },
    {
      id: '5',
      title: 'Stay Connected',
      description: 'Communicate with your safety network through reports and chat features.',
      icon: '💬',
    },
  ];

  return (
    <ScrollView style={{flex: 1, backgroundColor: '#F9FAFB'}}>
      <View style={{paddingHorizontal: 24, paddingVertical: 16}}>
        <Text style={{fontSize: 24, fontWeight: 'bold', color: '#111827', marginBottom: 24}}>
          How It Works
        </Text>

        {steps.map((step, index) => (
          <View key={step.id} style={{marginBottom: 24}}>
            <View style={{flexDirection: 'row', alignItems: 'flex-start'}}>
              <View
                style={{
                  width: 60,
                  height: 60,
                  backgroundColor: '#2563EB',
                  borderRadius: 30,
                  alignItems: 'center',
                  justifyContent: 'center',
                  marginRight: 16,
                }}>
                <Text style={{fontSize: 28}}>{step.icon}</Text>
              </View>
              <View style={{flex: 1, paddingTop: 8}}>
                <Text style={{color: '#111827', fontSize: 18, fontWeight: '600', marginBottom: 4}}>
                  Step {index + 1}: {step.title}
                </Text>
                <Text style={{color: '#6B7280', fontSize: 14, lineHeight: 20}}>
                  {step.description}
                </Text>
              </View>
            </View>
            {index < steps.length - 1 && (
              <View
                style={{
                  width: 2,
                  height: 30,
                  backgroundColor: '#E5E7EB',
                  marginLeft: 30,
                  marginTop: 8,
                }}
              />
            )}
          </View>
        ))}
      </View>
    </ScrollView>
  );
};

export default HowItWorksScreen;


