/**
 * Server-side reCAPTCHA verification utility
 */

interface RecaptchaResponse {
  success: boolean
  score?: number
  action?: string
  challenge_ts?: string
  hostname?: string
  'error-codes'?: string[]
}

export async function verifyRecaptcha(token: string, remoteIp?: string): Promise<{
  success: boolean
  score?: number
  error?: string
}> {
  // Allow bypass in local development only
  if (process.env.NODE_ENV === 'development' && process.env.BYPASS_RECAPTCHA === 'true') {
    console.log('🔧 Development Mode: Bypassing reCAPTCHA verification (BYPASS_RECAPTCHA=true)')
    return { success: true, score: 0.9 }
  }

  if (!process.env.RECAPTCHA_SECRET_KEY) {
    console.error('❌ RECAPTCHA_SECRET_KEY not configured')
    return { success: false, error: 'reCAPTCHA not properly configured' }
  }

  if (!token) {
    return { success: false, error: 'No reCAPTCHA token provided' }
  }

  try {
    console.log('🔍 Verifying reCAPTCHA token with Google...')
    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        secret: process.env.RECAPTCHA_SECRET_KEY,
        response: token,
        ...(remoteIp && { remoteip: remoteIp })
      })
    })

    const data: RecaptchaResponse = await response.json()
    console.log('📊 reCAPTCHA response:', { success: data.success, score: data.score, errors: data['error-codes'] })

    if (!data.success) {
      console.warn('❌ reCAPTCHA verification failed:', data['error-codes'])
      return { 
        success: false, 
        error: `reCAPTCHA verification failed: ${data['error-codes']?.join(', ') || 'Unknown error'}` 
      }
    }

    // For reCAPTCHA v3, check score (v2 doesn't have score)
    if (data.score !== undefined && data.score < 0.5) {
      console.warn('❌ reCAPTCHA score too low:', data.score)
      return { 
        success: false, 
        error: 'Security check failed. Please try again.',
        score: data.score 
      }
    }

    console.log('✅ reCAPTCHA verification successful', data.score ? `(score: ${data.score})` : '')
    return { 
      success: true, 
      score: data.score 
    }

  } catch (error) {
    console.error('❌ reCAPTCHA verification error:', error)
    return { 
      success: false, 
      error: 'reCAPTCHA verification service unavailable' 
    }
  }
}

/**
 * Middleware to verify reCAPTCHA token from request
 */
export async function requireRecaptcha(
  request: Request, 
  options: { 
    tokenField?: string
    minScore?: number 
  } = {}
): Promise<{
  success: boolean
  error?: string
  score?: number
}> {
  const { tokenField = 'recaptchaToken', minScore = 0.5 } = options

  try {
    const body = await request.clone().json()
    const token = body[tokenField]
    
    if (!token) {
      return { success: false, error: 'reCAPTCHA token is required' }
    }

    const clientIp = request.headers.get('x-forwarded-for') || 
                     request.headers.get('x-real-ip') || 
                     undefined

    const result = await verifyRecaptcha(token, clientIp)

    if (!result.success) {
      return result
    }

    // Check score for v3 (if available)
    if (result.score !== undefined && result.score < minScore) {
      return { 
        success: false, 
        error: `reCAPTCHA score too low: ${result.score}`, 
        score: result.score 
      }
    }

    return result

  } catch (error) {
    console.error('❌ reCAPTCHA middleware error:', error)
    return { success: false, error: 'Failed to process reCAPTCHA verification' }
  }
}
