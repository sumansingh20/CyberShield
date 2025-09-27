import twilio from 'twilio'

// Initialize Twilio client
const getTwilioClient = () => {
  const accountSid = process.env.TWILIO_ACCOUNT_SID
  const authToken = process.env.TWILIO_AUTH_TOKEN
  
  if (!accountSid || !authToken) {
    throw new Error('Twilio credentials not configured')
  }
  
  return twilio(accountSid, authToken)
}

// Send SMS OTP using Twilio Verify
export async function sendSMSOTPVerify(phoneNumber: string): Promise<{
  success: boolean
  message?: string
  sid?: string
}> {
  try {
    const client = getTwilioClient()
    const verifySid = process.env.TWILIO_VERIFY_SERVICE_SID

    if (!verifySid) {
      throw new Error('Twilio Verify Service SID not configured')
    }

    const formattedPhone = phoneNumber.startsWith('+') ? phoneNumber : `+91${phoneNumber}`

    const verification = await client.verify.v2
      .services(verifySid)
      .verifications
      .create({ 
        to: formattedPhone, 
        channel: 'sms'
      })

    console.log(`✅ SMS OTP sent via Verify service: ${verification.sid}`)
    console.log(`📱 Sent to phone: ${formattedPhone}`)

    return {
      success: true,
      message: 'SMS OTP sent successfully',
      sid: verification.sid
    }
  } catch (error: any) {
    console.error('❌ Twilio Verify SMS failed:', error)
    console.error('Error details:', {
      message: error.message,
      code: error.code,
      moreInfo: error.moreInfo,
      status: error.status
    })

    return {
      success: false,
      message: error.message || 'Failed to send SMS OTP'
    }
  }
}

// Verify SMS OTP using Twilio Verify Service
export const verifySMSOTP = async (phoneNumber: string, otp: string): Promise<{
  success: boolean
  message?: string
  status?: string
}> => {
  try {
    const client = getTwilioClient()
    const verifySid = process.env.TWILIO_VERIFY_SERVICE_SID
    
    if (!verifySid) {
      throw new Error('Twilio Verify Service SID not configured')
    }
    
    // Format phone number
    const formattedPhone = phoneNumber.startsWith('+') ? phoneNumber : `+91${phoneNumber}`
    
    const verification = await client.verify.v2
      .services(verifySid)
      .verificationChecks
      .create({
        to: formattedPhone,
        code: otp
      })
    
    console.log('📱 SMS OTP verification result:', verification.status)
    
    return {
      success: verification.status === 'approved',
      message: verification.status === 'approved' 
        ? 'OTP verified successfully' 
        : 'Invalid or expired OTP',
      status: verification.status
    }
    
  } catch (error: any) {
    console.error('❌ SMS OTP verification failed:', error)
    console.error('Error details:', error.message)
    
    return {
      success: false,
      message: error.message || 'Failed to verify SMS OTP'
    }
  }
}
