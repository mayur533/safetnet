package com.userapp

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod

class ShakeDetectionServiceModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String {
        return "ShakeDetectionServiceModule"
    }

    @ReactMethod
    fun startService() {
        val context = reactApplicationContext
        ShakeDetectionService.startService(context)
    }

    @ReactMethod
    fun stopService() {
        val context = reactApplicationContext
        ShakeDetectionService.stopService(context)
    }
    
    @ReactMethod
    fun setShakeEnabled(enabled: Boolean) {
        val context = reactApplicationContext
        ShakeDetectionService.setShakeEnabled(context, enabled)
    }
}

