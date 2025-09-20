interface RecaptchaEnterpriseAssessment {
  event: {
    token: string
    expectedAction: string
    siteKey: string
  }
}

interface RecaptchaEnterpriseResponse {
  name: string
  event: {
    token: string
    siteKey: string
    userAgent: string
    userIpAddress: string
    expectedAction: string
  }
  riskAnalysis: {
    score: number
    reasons: string[]
  }
  tokenProperties: {
    valid: boolean
    invalidReason?: string
    hostname: string
    action: string
    createTime: string
  }
}

export async function verifyRecaptchaEnterprise(
  token: string,
  expectedAction: string,
  userIpAddress?: string
): Promise<{ success: boolean; score?: number; error?: string }> {
  try {
    // Check if we're in development mode or localhost
    if (process.env.NODE_ENV === 'development' || 
        process.env.NEXT_PUBLIC_APP_URL?.includes('localhost')) {
      console.log('🔧 Development Mode: Skipping reCAPTCHA Enterprise verification')
      return { success: true, score: 1.0 }
    }

    // Check if Enterprise API is configured
    if (!process.env.GOOGLE_CLOUD_PROJECT_ID || !process.env.RECAPTCHA_API_KEY) {
      console.log('reCAPTCHA Enterprise not fully configured, allowing through')
      return { success: true } // Allow through if not configured
    }

    const projectId = process.env.GOOGLE_CLOUD_PROJECT_ID
    const apiKey = process.env.RECAPTCHA_API_KEY
    const siteKey = process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY

    if (!siteKey) {
      console.error('Site key not configured')
      return { success: false, error: 'Site key not configured' }
    }

    // Prepare the assessment payload
    const assessmentPayload: RecaptchaEnterpriseAssessment = {
      event: {
        token,
        expectedAction,
        siteKey,
      }
    }

    // Call the reCAPTCHA Enterprise API
    const response = await fetch(
      `https://recaptchaenterprise.googleapis.com/v1/projects/${projectId}/assessments?key=${apiKey}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(assessmentPayload),
      }
    )

    if (!response.ok) {
      const errorText = await response.text()
      console.error('reCAPTCHA Enterprise API error:', response.status, errorText)
      return { success: false, error: `API error: ${response.status}` }
    }

    const result: RecaptchaEnterpriseResponse = await response.json()

    // Check token validity
    if (!result.tokenProperties?.valid) {
      console.warn('Invalid reCAPTCHA token:', result.tokenProperties?.invalidReason)
      return { 
        success: false, 
        error: `Invalid token: ${result.tokenProperties?.invalidReason || 'Unknown reason'}` 
      }
    }

    // Check if the action matches
    if (result.tokenProperties.action !== expectedAction) {
      console.warn(`Action mismatch: expected ${expectedAction}, got ${result.tokenProperties.action}`)
      return { 
        success: false, 
        error: 'Action mismatch' 
      }
    }

    // Get the risk score (0.0 to 1.0, where 1.0 is very likely human)
    const score = result.riskAnalysis?.score || 0
    
    // Consider score above 0.5 as legitimate (you can adjust this threshold)
    const isLegitimate = score >= 0.5

    console.log(`reCAPTCHA Enterprise verification - Score: ${score}, Legitimate: ${isLegitimate}`)

    if (!isLegitimate) {
      console.warn('Low reCAPTCHA score:', score, 'Reasons:', result.riskAnalysis?.reasons)
    }

    return {
      success: isLegitimate,
      score,
      error: isLegitimate ? undefined : `Low trust score: ${score}`
    }

  } catch (error) {
    console.error('reCAPTCHA Enterprise verification error:', error)
    return { 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }
  }
}