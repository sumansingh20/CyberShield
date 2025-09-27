"use client"

import React, { useRef, forwardRef, useImperativeHandle } from 'react'
import ReCAPTCHA from 'react-google-recaptcha'

interface ReCaptchaProps {
  onVerify?: (token: string | null) => void
  theme?: 'light' | 'dark'
  size?: 'compact' | 'normal' | 'invisible'
}

export interface ReCaptchaRef {
  getValue: () => string | null
  reset: () => void
  execute: () => void
}

const ReCaptcha = forwardRef<ReCaptchaRef, ReCaptchaProps>(
  ({ onVerify, theme = 'dark', size = 'normal' }, ref) => {
    const recaptchaRef = useRef<ReCAPTCHA>(null)

    useImperativeHandle(ref, () => ({
      getValue: () => {
        return recaptchaRef.current?.getValue() || null
      },
      reset: () => {
        recaptchaRef.current?.reset()
      },
      execute: () => {
        recaptchaRef.current?.execute()
      }
    }))

    const handleChange = (token: string | null) => {
      if (onVerify) {
        onVerify(token)
      }
    }

    // Only show development mode if site key is not configured
    if (!process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY) {
      return (
        <div className="flex items-center gap-2 p-3 bg-muted/20 rounded-md border border-dashed">
          <div className="w-4 h-4 bg-green-500 rounded-full flex items-center justify-center">
            <div className="w-2 h-2 bg-white rounded-full"></div>
          </div>
          <span className="text-sm text-muted-foreground">
            reCAPTCHA (Development Mode)
          </span>
        </div>
      )
    }

    return (
      <div className="flex justify-center">
        <ReCAPTCHA
          ref={recaptchaRef}
          sitekey={process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY}
          onChange={handleChange}
          theme={theme}
          size={size}
        />
      </div>
    )
  }
)

ReCaptcha.displayName = 'ReCaptcha'

export default ReCaptcha
