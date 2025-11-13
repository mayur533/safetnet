import {Alert} from 'react-native';
import {useCallback} from 'react';
import {useAuthStore} from '../../stores/authStore';

export type SubscriptionPlan = 'free' | 'premium';

export const FREE_CONTACT_LIMIT = 5;
export const FREE_TRUSTED_CIRCLE_LIMIT = 2;

export const useSubscription = () => {
  const plan = useAuthStore((state) => state.user?.plan as SubscriptionPlan | undefined);
  const normalizedPlan: SubscriptionPlan = plan ?? 'free';
  const isPremium = normalizedPlan === 'premium';

  const promptUpgrade = useCallback((message?: string) => {
    Alert.alert(
      'Upgrade to Premium',
      message ??
        'This feature is available for Premium members. Upgrade to unlock advanced safety tools.',
      [
        {text: 'Later', style: 'cancel'},
        {text: 'Upgrade', onPress: () => {}},
      ],
    );
  }, []);

  const requirePremium = useCallback(
    (message?: string) => {
      if (!isPremium) {
        promptUpgrade(message);
        return false;
      }
      return true;
    },
    [isPremium, promptUpgrade],
  );

  return {
    plan: normalizedPlan,
    isPremium,
    requirePremium,
    promptUpgrade,
  };
};


