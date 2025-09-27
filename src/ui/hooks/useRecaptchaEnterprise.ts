import { useCallback } from 'react'

declare global {
  interface Window {
    grecaptcha: {
      enterprise: {
        ready: (callback: () => void) => void
        execute: (siteKey: string, options: { action: string }) => Promise<string>
      }
    }
  }
}

export const useRecaptchaEnterprise = () => {
  const executeRecaptcha = useCallback(async (action: string): Promise<string | null> => {
    // Check if we're in development mode or localhost
    if (process.env.NODE_ENV === 'development' || 
        typeof window !== 'undefined' && window.location.hostname === 'localhost') {
      console.log('🔧 Development Mode: Returning mock reCAPTCHA token')
      return `mock-token-${action}-${Date.now()}`
    }

    if (!process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY) {
      console.log('🔧 reCAPTCHA not configured, returning null')
      return null
    }

    try {
      return new Promise((resolve, reject) => {
        if (typeof window !== 'undefined' && window.grecaptcha?.enterprise) {
          window.grecaptcha.enterprise.ready(async () => {
            try {
              const token = await window.grecaptcha.enterprise.execute(
                process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY!,
                { action }
              )
              resolve(token)
            } catch (error) {
              console.error('reCAPTCHA Enterprise execution failed:', error)
              reject(error)
            }
          })
        } else {
          console.warn('reCAPTCHA Enterprise not loaded')
          resolve(null)
        }
      })
    } catch (error) {
      console.error('reCAPTCHA Enterprise error:', error)
      return null
    }
  }, [])

  return { executeRecaptcha }
}
