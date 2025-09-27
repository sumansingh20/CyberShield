import { NextRequest, NextResponse } from "next/server"

interface SERequest {
  template_type: string
  category: string
  target_company?: string
  target_name?: string
  target_email?: string
  custom_subject?: string
  custom_message?: string
}

interface SETemplate {
  id: string
  type: string
  category: string
  name: string
  description: string
  subject?: string
  content: string
  target_info: string[]
  effectiveness_score: number
  difficulty: string
  detection_risk: string
  customizable_fields: string[]
  preview_html?: string
}

// Template database
const SE_TEMPLATES: Record<string, Record<string, SETemplate[]>> = {
  phishing_email: {
    credential_harvesting: [
      {
        id: "pe_ch_001",
        type: "phishing_email",
        category: "credential_harvesting",
        name: "Urgent Account Security Alert",
        description: "Classic security alert phishing email requesting immediate action",
        subject: "URGENT: Suspicious Activity Detected on Your Account",
        content: `Dear {target_name},

We have detected unusual activity on your {company} account from an unrecognized device. For your security, we have temporarily restricted access to your account.

**Suspicious Activity Details:**
- Location: Unknown (IP: 192.168.1.1)
- Device: Unrecognized Browser
- Time: Today at 3:47 AM

To restore full access to your account, please verify your identity immediately by clicking the link below:

🔒 VERIFY YOUR ACCOUNT NOW: https://secure-{company_domain}/verify

If you do not verify within 24 hours, your account will be permanently suspended.

This is an automated security message. Please do not reply to this email.

Best regards,
{Company} Security Team`,
        target_info: ["Name", "Company", "Email Domain"],
        effectiveness_score: 8.5,
        difficulty: "Easy",
        detection_risk: "Medium",
        customizable_fields: ["target_name", "company", "company_domain"],
        preview_html: `<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd;">
          <div style="background: #f44336; color: white; padding: 10px; text-align: center; font-weight: bold;">
            🚨 SECURITY ALERT 🚨
          </div>
          <div style="padding: 20px;">
            <h2>Suspicious Activity Detected</h2>
            <p>We have detected unusual activity on your account...</p>
            <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0;">
              <strong>Action Required:</strong> Verify your account immediately
            </div>
            <a href="#" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
              🔒 VERIFY ACCOUNT NOW
            </a>
          </div>
        </div>`
      },
      {
        id: "pe_ch_002",
        type: "phishing_email",
        category: "credential_harvesting",
        name: "IT Department Password Reset",
        description: "Impersonates IT department requesting password reset",
        subject: "IT Notice: Mandatory Password Reset Required",
        content: `Hello {target_name},

This is an automated message from the {company} IT Security Department.

As part of our ongoing security improvements, all employees are required to reset their passwords by the end of this week. This is a mandatory security update following recent cyber threats in our industry.

**New Password Requirements:**
- Minimum 12 characters
- Include uppercase, lowercase, numbers, and symbols
- Cannot contain personal information

Please reset your password using our secure portal:
👤 UPDATE PASSWORD: https://it-portal-{company_domain}/reset

Your current password will expire in 48 hours. Failure to update will result in account lockout.

If you have any questions, please contact the IT Help Desk at it-support@{company_domain}

Thank you for helping us maintain security,
{Company} IT Security Team`,
        target_info: ["Name", "Company", "Email Domain"],
        effectiveness_score: 7.8,
        difficulty: "Easy",
        detection_risk: "Low",
        customizable_fields: ["target_name", "company", "company_domain"]
      }
    ],
    business_email_compromise: [
      {
        id: "pe_bec_001",
        type: "phishing_email",
        category: "business_email_compromise",
        name: "CEO Urgent Wire Transfer",
        description: "Executive impersonation requesting urgent financial transaction",
        subject: "Urgent Wire Transfer - Confidential",
        content: `{target_name},

I need you to process an urgent wire transfer today. We have a confidential acquisition opportunity that requires immediate funding.

**Transfer Details:**
Amount: $45,000 USD
Recipient: SecureTech Holdings LLC
Account: [Will provide separately]
Deadline: Before 5 PM today

This is highly confidential - please do not discuss with anyone else on the team. I'm in meetings all day but you can reach me on my mobile if needed.

Please confirm when the transfer is initiated.

Best regards,
[CEO Name]
Sent from my iPhone`,
        target_info: ["Name", "CEO Name", "Company Financial Info"],
        effectiveness_score: 9.2,
        difficulty: "Intermediate",
        detection_risk: "High",
        customizable_fields: ["target_name", "ceo_name", "amount"]
      }
    ]
  },
  sms_phishing: {
    credential_harvesting: [
      {
        id: "sms_ch_001",
        type: "sms_phishing",
        category: "credential_harvesting",
        name: "Bank Security Alert SMS",
        description: "SMS alert claiming suspicious bank account activity",
        content: `SECURITY ALERT: Suspicious activity detected on your account ending in ****2341. 
$847.99 charge from AMAZON PRIME blocked. 
If this wasn't you, verify immediately: bit.ly/bank-verify-{random}
Reply STOP to opt out.`,
        target_info: ["Phone Number", "Bank Name"],
        effectiveness_score: 7.5,
        difficulty: "Easy",
        detection_risk: "Medium",
        customizable_fields: ["amount", "merchant", "account_digits"]
      }
    ]
  },
  voice_phishing: {
    tech_support_scam: [
      {
        id: "vp_ts_001",
        type: "voice_phishing",
        category: "tech_support_scam",
        name: "Microsoft Tech Support Call",
        description: "Cold call script impersonating Microsoft technical support",
        content: `**Opening Script:**
"Hello, this is [Name] calling from Microsoft Technical Support Department. We've detected some suspicious activity on your computer that's connected to your Windows license key [License Key]. 

We've identified several security threats including:
- Trojan horses accessing your personal files
- Hackers attempting to steal your banking information  
- Malware that could damage your system permanently

**If they express doubt:**
"Sir/Ma'am, I can see from our security center that your computer is currently compromised. We need to fix this immediately before your personal information is stolen."

**Next Steps:**
1. Ask them to turn on their computer
2. Guide them to Event Viewer to show "errors" 
3. Request remote access via TeamViewer/AnyDesk
4. Claim to need payment for "security software"

**Objection Handling:**
- "This is a free service from Microsoft"
- "We're only trying to help protect you"
- "The threats are very serious and time-sensitive"`,
        target_info: ["Phone Number", "Computer Knowledge Level"],
        effectiveness_score: 6.8,
        difficulty: "Advanced",
        detection_risk: "High",
        customizable_fields: ["caller_name", "license_key", "threats"]
      }
    ]
  }
}

function generateSETemplates(request: SERequest): SETemplate[] {
  const templates: SETemplate[] = []
  
  // Get templates for the specified type and category
  const typeTemplates = SE_TEMPLATES[request.template_type]
  if (!typeTemplates) return templates
  
  const categoryTemplates = typeTemplates[request.category]
  if (!categoryTemplates) return templates
  
  // Customize templates with provided information
  categoryTemplates.forEach(template => {
    let customizedTemplate = { ...template }
    
    // Replace placeholders with actual values
    if (request.target_name) {
      customizedTemplate.content = customizedTemplate.content.replace(/{target_name}/g, request.target_name)
      if (customizedTemplate.subject) {
        customizedTemplate.subject = customizedTemplate.subject.replace(/{target_name}/g, request.target_name)
      }
    }
    
    if (request.target_company) {
      customizedTemplate.content = customizedTemplate.content.replace(/{company}/g, request.target_company)
      customizedTemplate.content = customizedTemplate.content.replace(/{Company}/g, request.target_company)
      if (customizedTemplate.subject) {
        customizedTemplate.subject = customizedTemplate.subject.replace(/{company}/g, request.target_company)
      }
    }
    
    if (request.target_email) {
      const domain = request.target_email.split('@')[1]
      customizedTemplate.content = customizedTemplate.content.replace(/{company_domain}/g, domain)
    }
    
    if (request.custom_subject && customizedTemplate.subject) {
      customizedTemplate.subject = request.custom_subject
    }
    
    // Add random elements to make templates unique
    customizedTemplate.content = customizedTemplate.content.replace(/{random}/g, Math.random().toString(36).substring(7))
    
    templates.push(customizedTemplate)
  })
  
  return templates
}

function generateCampaignRiskAssessment(templates: SETemplate[], request: SERequest) {
  const hasHighRiskTemplate = templates.some(t => t.detection_risk === "High")
  const avgEffectiveness = templates.reduce((sum, t) => sum + t.effectiveness_score, 0) / templates.length
  
  return {
    template: templates[0],
    customizations: {
      target_name: request.target_name || "Not specified",
      target_company: request.target_company || "Not specified",
      target_email: request.target_email || "Not specified"
    },
    target_count: 1,
    estimated_success_rate: Math.round(avgEffectiveness * 10),
    risk_assessment: {
      legal_risk: hasHighRiskTemplate ? "High" : "Medium",
      detection_risk: hasHighRiskTemplate ? "High" : "Medium",
      ethical_concerns: [
        "Potential psychological harm to targets",
        "Risk of actual credential theft if misused",
        "May violate computer fraud and abuse laws",
        "Could damage organizational trust if discovered",
        "May trigger legitimate security incident response"
      ]
    },
    generated_content: templates[0]?.content || "",
    delivery_methods: getDeliveryMethods(request.template_type),
    tracking_options: getTrackingOptions(request.template_type)
  }
}

function getDeliveryMethods(templateType: string): string[] {
  switch (templateType) {
    case "phishing_email":
      return ["SMTP Server", "Email Marketing Platform", "Spoofed Domain", "Compromised Account"]
    case "sms_phishing":
      return ["SMS Gateway", "Spoofed Sender ID", "Premium SMS", "Messaging Apps"]
    case "voice_phishing":
      return ["VoIP Service", "Caller ID Spoofing", "Robocall Platform", "Social Media Voice"]
    case "social_media":
      return ["Fake Profiles", "Compromised Accounts", "Sponsored Posts", "Direct Messages"]
    default:
      return ["Manual Delivery", "Automated Systems"]
  }
}

function getTrackingOptions(templateType: string): string[] {
  const baseOptions = ["Click Tracking", "Open Rates", "Response Tracking", "Time Analytics"]
  
  switch (templateType) {
    case "phishing_email":
      return [...baseOptions, "Email Client Detection", "Geolocation", "Credential Capture"]
    case "sms_phishing":
      return [...baseOptions, "SMS Delivery Status", "Device Type", "Carrier Information"]
    case "voice_phishing":
      return ["Call Duration", "Response Recording", "Callback Tracking", "Success Rate"]
    default:
      return baseOptions
  }
}

export async function POST(request: NextRequest) {
  try {
    const body: SERequest = await request.json()
    
    // Validate required fields
    if (!body.template_type || !body.category) {
      return NextResponse.json(
        { error: "Template type and category are required" },
        { status: 400 }
      )
    }
    
    // Check if template type is supported
    if (!SE_TEMPLATES[body.template_type]) {
      return NextResponse.json(
        { error: "Unsupported template type" },
        { status: 400 }
      )
    }
    
    // Track generation time
    const generateStart = Date.now()
    const templates = generateSETemplates(body)
    const generationTime = Date.now() - generateStart
    
    if (templates.length === 0) {
      return NextResponse.json(
        { error: "No templates available for the specified type and category" },
        { status: 404 }
      )
    }
    
    const campaign = generateCampaignRiskAssessment(templates, body)
    
    const result = {
      campaign,
      templates,
      total_templates: templates.length,
      generation_time: generationTime,
      timestamp: new Date().toISOString()
    }
    
    return NextResponse.json(result)
    
  } catch (error) {
    console.error("Social engineering template generation error:", error)
    return NextResponse.json(
      { error: "Failed to generate social engineering templates" },
      { status: 500 }
    )
  }
}
