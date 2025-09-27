import twilio from 'twilio'

// Initialize Twilio client for voice calls
const getTwilioVoiceClient = () => {
  const accountSid = process.env.TWILIO_ACCOUNT_SID
  const authToken = process.env.TWILIO_AUTH_TOKEN
  
  if (!accountSid || !authToken) {
    throw new Error('Twilio credentials not configured for voice calls')
  }
  
  return twilio(accountSid, authToken)
}

// Generate OTP for voice call
export const generateVoiceOTP = (): string => {
  return Math.floor(100000 + Math.random() * 900000).toString() // 6-digit OTP
}

// Create TwiML for voice OTP
const createVoiceOTPTwiML = (otp: string): string => {
  const digits = otp.split('').join(', ')
  
  return `
    <?xml version="1.0" encoding="UTF-8"?>
    <Response>
      <Say voice="alice" language="en-US">
        Hello! Your CyberShield verification code is: ${digits}. 
        I repeat, your code is: ${digits}. 
        This code will expire in 5 minutes.
      </Say>
      <Pause length="1"/>
      <Say voice="alice" language="en-US">
        Thank you for using CyberShield security platform.
      </Say>
    </Response>
  `.trim()
}

// Send voice OTP call
export const sendVoiceOTP = async (phoneNumber: string, otp: string): Promise<{ success: boolean; callSid?: string; message?: string }> => {
  try {
    console.log(`📞 Attempting voice OTP call to: ${phoneNumber}`)
    
    const client = getTwilioVoiceClient()
    const fromNumber = process.env.TWILIO_PHONE_NUMBER
    
    if (!fromNumber) {
      throw new Error('Twilio phone number not configured')
    }
    
    // Format phone number
    const formattedPhone = phoneNumber.startsWith('+') ? phoneNumber : `+91${phoneNumber}`
    
    // Create TwiML for the call
    const twiml = createVoiceOTPTwiML(otp)
    
    const call = await client.calls.create({
      from: fromNumber,
      to: formattedPhone,
      twiml: twiml,
      timeout: 30, // Ring for 30 seconds
      record: false // Don't record the call
    })
    
    console.log(`✅ Voice OTP call initiated: ${call.sid}`)
    console.log(`📞 Called number: ${formattedPhone}`)
    
    return {
      success: true,
      callSid: call.sid,
      message: `Voice call initiated to ${formattedPhone}`
    }
    
  } catch (error: any) {
    console.error('❌ Voice OTP call failed:', error)
    console.error('Error details:', {
      message: error.message,
      code: error.code,
      moreInfo: error.moreInfo,
      status: error.status
    })
    
    return {
      success: false,
      message: error.message || 'Failed to initiate voice call'
    }
  }
}

// Alternative: Use Twilio's built-in voice verification
export const sendVoiceOTPVerify = async (phoneNumber: string): Promise<{ success: boolean; sid?: string; message?: string }> => {
  try {
    console.log(`📞 Attempting Twilio Verify voice call to: ${phoneNumber}`)
    
    const client = getTwilioVoiceClient()
    const verifySid = process.env.TWILIO_VERIFY_SERVICE_SID
    
    if (!verifySid) {
      throw new Error('Twilio Verify Service SID not configured')
    }
    
    // Format phone number
    const formattedPhone = phoneNumber.startsWith('+') ? phoneNumber : `+91${phoneNumber}`
    
    const verification = await client.verify.v2
      .services(verifySid)
      .verifications
      .create({
        to: formattedPhone,
        channel: 'call' // Use voice call instead of SMS
      })
    
    console.log(`✅ Voice OTP verification initiated: ${verification.sid}`)
    console.log(`📞 Call status: ${verification.status}`)
    
    return {
      success: true,
      sid: verification.sid,
      message: `Voice verification call sent to ${formattedPhone}`
    }
    
  } catch (error: any) {
    console.error('❌ Voice OTP Verify failed:', error)
    console.error('Error details:', {
      message: error.message,
      code: error.code,
      moreInfo: error.moreInfo,
      status: error.status
    })
    
    return {
      success: false,
      message: error.message || 'Failed to send voice verification'
    }
  }
}

// Test voice call configuration
export const testVoiceConfig = async (): Promise<boolean> => {
  try {
    const client = getTwilioVoiceClient()
    const account = await client.api.accounts.list({ limit: 1 })
    
    console.log('✅ Twilio voice configuration verified')
    console.log('📞 Account SID:', account[0]?.sid?.slice(0, 10) + '...')
    
    return true
  } catch (error: any) {
    console.error('❌ Twilio voice configuration failed:', error.message)
    return false
  }
}
