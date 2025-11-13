import React from 'react';
import {View, Text, ScrollView} from 'react-native';

const SafetyTipsScreen = () => {
  const safetyTips = [
    {
      id: '1',
      title: 'Personal Safety',
      tips: [
        'Always inform someone about your location when traveling alone',
        'Keep emergency contacts easily accessible',
        'Stay aware of your surroundings',
        'Trust your instincts and avoid risky situations',
      ],
    },
    {
      id: '2',
      title: 'Home Security',
      tips: [
        'Install security systems and cameras',
        'Keep doors and windows locked',
        'Use geofencing to monitor your property',
        'Maintain good lighting around your home',
      ],
    },
    {
      id: '3',
      title: 'Emergency Preparedness',
      tips: [
        'Have an emergency kit ready',
        'Know your evacuation routes',
        'Keep important documents safe',
        'Practice emergency drills regularly',
      ],
    },
  ];

  return (
    <ScrollView style={{flex: 1, backgroundColor: '#F9FAFB'}}>
      <View style={{paddingHorizontal: 24, paddingVertical: 16}}>
        <Text style={{fontSize: 24, fontWeight: 'bold', color: '#111827', marginBottom: 16}}>
          Safety Tips
        </Text>

        {safetyTips.map((category) => (
          <View
            key={category.id}
            style={{
              backgroundColor: '#FFFFFF',
              borderRadius: 12,
              padding: 20,
              marginBottom: 16,
            }}>
            <Text style={{color: '#111827', fontSize: 20, fontWeight: '600', marginBottom: 12}}>
              {category.title}
            </Text>
            {category.tips.map((tip, index) => (
              <View key={index} style={{flexDirection: 'row', marginBottom: 8}}>
                <Text style={{color: '#2563EB', marginRight: 8}}>•</Text>
                <Text style={{color: '#6B7280', fontSize: 14, flex: 1}}>{tip}</Text>
              </View>
            ))}
          </View>
        ))}
      </View>
    </ScrollView>
  );
};

export default SafetyTipsScreen;


