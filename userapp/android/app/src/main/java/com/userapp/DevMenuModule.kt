package com.userapp

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.Promise
import com.facebook.react.modules.core.DeviceEventManagerModule

class DevMenuModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {
    
    companion object {
        @Volatile
        private var isShakeDetectionActive: Boolean = false
        
        fun setShakeDetectionActive(active: Boolean) {
            isShakeDetectionActive = active
        }
        
        fun isShakeDetectionActive(): Boolean {
            return isShakeDetectionActive
        }
    }

    override fun getName(): String {
        return "DevMenuModule"
    }

    @ReactMethod
    fun setShakeDetectionActive(active: Boolean) {
        isShakeDetectionActive = active
    }

    @ReactMethod
    fun isShakeDetectionActive(promise: Promise) {
        promise.resolve(isShakeDetectionActive)
    }
}




