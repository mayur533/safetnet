package com.userapp;

import android.os.VibrationEffect;
import android.os.Vibrator;
import android.os.VibratorManager;
import android.os.Build;
import android.content.Context;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;

public class VibrationModule extends ReactContextBaseJavaModule {
    private static final String MODULE_NAME = "VibrationModule";
    private final ReactApplicationContext reactContext;

    public VibrationModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @NonNull
    @Override
    public String getName() {
        return MODULE_NAME;
    }

    @ReactMethod
    public void vibrate(double duration) {
        try {
            long durationMs = (long) duration;
            Context context = reactContext.getApplicationContext();
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                // Android 12+ (API 31+)
                VibratorManager vibratorManager = (VibratorManager) context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE);
                if (vibratorManager != null) {
                    Vibrator vibrator = vibratorManager.getDefaultVibrator();
                    if (vibrator != null && vibrator.hasVibrator()) {
                        // Use VibrationEffect with NOTIFICATION usage instead of TOUCH
                        VibrationEffect effect = VibrationEffect.createOneShot(durationMs, VibrationEffect.DEFAULT_AMPLITUDE);
                        android.os.VibrationAttributes attrs = new android.os.VibrationAttributes.Builder()
                            .setUsage(android.os.VibrationAttributes.USAGE_NOTIFICATION)
                            .build();
                        vibrator.vibrate(effect, attrs);
                    }
                }
            } else {
                // Android 11 and below
                Vibrator vibrator = (Vibrator) context.getSystemService(Context.VIBRATOR_SERVICE);
                if (vibrator != null && vibrator.hasVibrator()) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        VibrationEffect effect = VibrationEffect.createOneShot(durationMs, VibrationEffect.DEFAULT_AMPLITUDE);
                        vibrator.vibrate(effect);
                    } else {
                        vibrator.vibrate(durationMs);
                    }
                }
            }
        } catch (Exception e) {
            // Silently fail if vibration is not available
        }
    }

    @ReactMethod
    public void vibratePattern(ReadableArray pattern, int repeat) {
        try {
            // Convert ReadableArray to long[]
            long[] patternArray = new long[pattern.size()];
            for (int i = 0; i < pattern.size(); i++) {
                patternArray[i] = (long) pattern.getDouble(i);
            }
            
            Context context = reactContext.getApplicationContext();
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                // Android 12+ (API 31+)
                VibratorManager vibratorManager = (VibratorManager) context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE);
                if (vibratorManager != null) {
                    Vibrator vibrator = vibratorManager.getDefaultVibrator();
                    if (vibrator != null && vibrator.hasVibrator()) {
                        // Use VibrationEffect with NOTIFICATION usage
                        VibrationEffect effect = VibrationEffect.createWaveform(patternArray, repeat);
                        android.os.VibrationAttributes attrs = new android.os.VibrationAttributes.Builder()
                            .setUsage(android.os.VibrationAttributes.USAGE_NOTIFICATION)
                            .build();
                        vibrator.vibrate(effect, attrs);
                    }
                }
            } else {
                // Android 11 and below
                Vibrator vibrator = (Vibrator) context.getSystemService(Context.VIBRATOR_SERVICE);
                if (vibrator != null && vibrator.hasVibrator()) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        VibrationEffect effect = VibrationEffect.createWaveform(patternArray, repeat);
                        vibrator.vibrate(effect);
                    } else {
                        vibrator.vibrate(patternArray, repeat);
                    }
                }
            }
        } catch (Exception e) {
            // Silently fail if vibration is not available
        }
    }
}

