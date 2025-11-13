package com.userapp

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            // Check if shake detection is enabled
            if (ShakeDetectionService.isShakeEnabled(context)) {
                // Start the service on boot
                ShakeDetectionService.startService(context)
            }
        }
    }
}




