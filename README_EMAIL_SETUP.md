# Email Configuration Guide

This guide explains how to configure email sending for the SafeTNet Admin Panel.

## Overview

The email functionality is used to send discount codes to users. The system uses Django's email framework with SMTP configuration.

## Configuration

Email settings are configured in `.env` file using the following variables:

```env
# Email Backend (use 'django.core.mail.backends.console.EmailBackend' for development)
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend

# SMTP Server Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_USE_SSL=False

# Email Credentials
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# Sender Information
DEFAULT_FROM_EMAIL=SafeTNet Admin <noreply@safetnet.com>
SERVER_EMAIL=SafeTNet Admin <noreply@safetnet.com>
```

## Gmail Setup (Recommended)

### Step 1: Enable 2-Factor Authentication
1. Go to your Google Account settings
2. Security → 2-Step Verification
3. Enable 2-Step Verification

### Step 2: Generate App Password
1. Go to Security → App passwords (or visit: https://myaccount.google.com/apppasswords)
2. Select "Mail" as the app
3. Select "Other" as the device and name it "SafeTNet"
4. Click "Generate"
5. Copy the 16-character password (use this as `EMAIL_HOST_PASSWORD`)

### Step 3: Update .env File
```env
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=xxxx xxxx xxxx xxxx  # The app password from step 2
```

## Other Email Providers

### Outlook/Office 365
```env
EMAIL_HOST=smtp.office365.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_USE_SSL=False
```

### SendGrid
```env
EMAIL_HOST=smtp.sendgrid.net
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=apikey
EMAIL_HOST_PASSWORD=your-sendgrid-api-key
```

### AWS SES
```env
EMAIL_HOST=email-smtp.us-east-1.amazonaws.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-access-key-id
EMAIL_HOST_PASSWORD=your-secret-access-key
```

## Development/Testing

For local development without sending actual emails, use the console backend:

```env
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
```

This will print emails to the console instead of sending them.

## Usage

### Sending Discount Emails

When you create a discount email through the admin panel:

1. **Automatic sending**: Emails are automatically sent when a new discount email is created
2. **Resend option**: Use the "Resend" action if an email fails to send
3. **Status tracking**: Email status is tracked (PENDING/SENT)

### API Endpoints

#### Create Discount Email (auto-sends)
```
POST /api/auth/admin/discount-emails/
```

#### Mark as Sent (manual)
```
POST /api/auth/admin/discount-emails/{id}/mark_sent/
```

#### Resend Email
```
POST /api/auth/admin/discount-emails/{id}/resend/
```

## Troubleshooting

### Emails not sending

1. **Check email configuration**:
   - Verify `.env` file has correct email settings
   - Ensure credentials are correct

2. **Check logs**:
   - Django logs will show email sending errors
   - Look for `Failed to send discount email` messages

3. **Common issues**:
   - **Gmail**: Make sure 2FA is enabled and you're using an app password, not your regular password
   - **Port 587 blocked**: Try port 465 with SSL instead
   - **Firewall**: Ensure port 587/465 is not blocked

### Testing Email Configuration

Run this Python command to test:

```python
from django.core.mail import send_mail
from django.conf import settings

send_mail(
    'Test Email',
    'This is a test email from SafeTNet.',
    settings.DEFAULT_FROM_EMAIL,
    ['your-test-email@example.com'],
    fail_silently=False,
)
```

## Security Notes

1. **Never commit `.env` file** to version control
2. **Use app-specific passwords** instead of main account passwords
3. **Rotate credentials** periodically
4. **Use environment variables** in production

## Production Deployment

For production (e.g., Render.com):

1. Set environment variables in your hosting platform
2. Use a reliable email service (SendGrid, AWS SES, etc.)
3. Enable proper logging and monitoring
4. Set up email delivery tracking

## Support

For issues or questions, check:
- Django email documentation: https://docs.djangoproject.com/en/5.1/topics/email/
- Your email provider's SMTP documentation

