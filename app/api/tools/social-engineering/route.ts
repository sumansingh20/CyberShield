import { NextRequest, NextResponse } from 'next/server'

interface SocialEngineeringRequest {
  campaignType: string
  targetType: string
  industry: string
  targetName: string
  targetEmail: string
  targetCompany: string
  attackGoal: string
  complexity: string
  includePersonalization: boolean
  includePsychology: boolean
  includeDefenses: boolean
}

interface SocialEngineeringResult {
  campaignType: string
  targetAnalysis: {
    profile: {
      name: string
      role: string
      company: string
      email: string
      socialMedia: string[]
      vulnerabilities: string[]
      riskLevel: 'Low' | 'Medium' | 'High' | 'Critical'
    }
    digitalFootprint: {
      socialPlatforms: string[]
      publicInfo: string[]
      connections: string[]
      interests: string[]
    }
    attackVectors: Array<{
      vector: string
      method: string
      success_rate: number
      difficulty: 'Easy' | 'Medium' | 'Hard'
      description: string
    }>
  }
  templates: {
    emails: Array<{
      subject: string
      body: string
      type: string
      effectiveness: number
      red_flags: string[]
    }>
    messages: Array<{
      platform: string
      message: string
      context: string
      approach: string
    }>
    calls: Array<{
      script: string
      scenario: string
      duration: string
      key_points: string[]
    }>
  }
  psychologyProfiles: Array<{
    personalityType: string
    triggers: string[]
    approaches: string[]
    avoidance: string[]
    successRate: number
  }>
  defensiveMeasures: string[]
  awarenessTips: string[]
  summary: string
}

// Industry-specific data and attack vectors
const INDUSTRY_DATA = {
  technology: {
    commonRoles: ['Software Engineer', 'DevOps Engineer', 'Product Manager', 'CTO', 'Security Analyst'],
    interests: ['Programming', 'Open Source', 'Cloud Computing', 'AI/ML', 'Cybersecurity'],
    vulnerabilities: ['GitHub profiles reveal tech stack', 'Conference attendance patterns', 'Technical blog posts', 'Stack Overflow activity'],
    platforms: ['LinkedIn', 'GitHub', 'Twitter', 'Stack Overflow', 'Reddit']
  },
  healthcare: {
    commonRoles: ['Doctor', 'Nurse', 'Administrator', 'IT Support', 'Researcher'],
    interests: ['Medical Research', 'Patient Care', 'Healthcare Technology', 'Medical Conferences'],
    vulnerabilities: ['Medical licensing boards public data', 'Research publication authorship', 'Hospital directory listings'],
    platforms: ['LinkedIn', 'ResearchGate', 'Doximity', 'Facebook']
  },
  finance: {
    commonRoles: ['Financial Advisor', 'Analyst', 'Trader', 'Compliance Officer', 'Risk Manager'],
    interests: ['Investment Strategies', 'Market Analysis', 'Financial Regulations', 'Fintech'],
    vulnerabilities: ['FINRA BrokerCheck data', 'Investment firm websites', 'Financial news quotes'],
    platforms: ['LinkedIn', 'Bloomberg Terminal', 'Twitter', 'Financial Forums']
  }
}

// Attack vector templates
const ATTACK_VECTORS = {
  phishing: [
    {
      vector: 'CEO Fraud',
      method: 'Executive impersonation email',
      success_rate: 85,
      difficulty: 'Easy' as const,
      description: 'Impersonate C-level executive requesting urgent financial transfer or sensitive information'
    },
    {
      vector: 'IT Support Scam',
      method: 'Technical support impersonation',
      success_rate: 70,
      difficulty: 'Medium' as const,
      description: 'Pose as internal IT support requesting credentials for system maintenance'
    },
    {
      vector: 'Vendor Invoice Fraud',
      method: 'Supplier impersonation',
      success_rate: 60,
      difficulty: 'Medium' as const,
      description: 'Impersonate trusted vendor requesting payment to new bank account'
    }
  ],
  spear_phishing: [
    {
      vector: 'Personalized Business Email',
      method: 'Highly targeted personalization',
      success_rate: 90,
      difficulty: 'Hard' as const,
      description: 'Craft highly personalized email using target-specific information and context'
    },
    {
      vector: 'Industry Conference Lure',
      method: 'Event-based targeting',
      success_rate: 75,
      difficulty: 'Medium' as const,
      description: 'Reference specific industry events or conferences the target attended'
    }
  ],
  vishing: [
    {
      vector: 'Authority Impersonation',
      method: 'Government agency impersonation',
      success_rate: 65,
      difficulty: 'Medium' as const,
      description: 'Call impersonating IRS, law enforcement, or regulatory agency'
    },
    {
      vector: 'Tech Support Call',
      method: 'Technical support scam call',
      success_rate: 55,
      difficulty: 'Easy' as const,
      description: 'Cold call claiming computer infection requiring remote access'
    }
  ]
}

// Email templates
const EMAIL_TEMPLATES = {
  phishing: {
    subject: 'Urgent: Account Security Verification Required',
    body: `Dear {name},

We've detected unusual activity on your {company} account. To protect your account, we need you to verify your identity immediately.

Click here to verify your account: [Malicious Link]

If you don't verify within 24 hours, your account will be temporarily suspended.

Best regards,
Security Team
{company}`,
    type: 'Security Alert',
    effectiveness: 75,
    red_flags: ['Urgent language', 'Threatening consequences', 'Suspicious link', 'Generic greeting']
  },
  spear_phishing: {
    subject: 'Follow-up from {conference} - Partnership Opportunity',
    body: `Hi {name},

Great meeting you at {conference} last week! I was impressed by your presentation on {topic}.

I'd love to discuss the partnership opportunity we briefly mentioned. I've attached a proposal document for your review.

[Malicious Attachment: Partnership_Proposal.pdf]

Looking forward to hearing your thoughts.

Best,
{sender_name}
{sender_company}`,
    type: 'Business Opportunity',
    effectiveness: 90,
    red_flags: ['Attachment from unknown sender', 'References to recent events', 'Too good to be true opportunity']
  }
}

// Psychology profiles
const PSYCHOLOGY_PROFILES = [
  {
    personalityType: 'Authority-Responsive',
    triggers: ['Fear of consequences', 'Respect for hierarchy', 'Compliance mindset'],
    approaches: ['Use official language', 'Reference company policies', 'Invoke urgency'],
    avoidance: ['Casual tone', 'Peer-level requests', 'Optional language'],
    successRate: 80
  },
  {
    personalityType: 'Helpful/Cooperative',
    triggers: ['Desire to assist', 'Team player mentality', 'Reciprocity'],
    approaches: ['Request help', 'Mention mutual connections', 'Offer assistance in return'],
    avoidance: ['Demanding tone', 'Selfish requests', 'Threatening language'],
    successRate: 75
  },
  {
    personalityType: 'Curious/Inquisitive',
    triggers: ['Interesting information', 'Exclusive opportunities', 'Learning opportunities'],
    approaches: ['Offer insider knowledge', 'Reference industry trends', 'Promise valuable insights'],
    avoidance: ['Boring content', 'Generic information', 'Obvious sales pitches'],
    successRate: 70
  }
]

async function analyzeSocialEngineeringVectors(request: SocialEngineeringRequest): Promise<SocialEngineeringResult> {
  const { campaignType, targetType, industry, targetName, targetEmail, targetCompany, attackGoal, complexity, includePersonalization, includePsychology, includeDefenses } = request
  
  // Generate target profile
  const industryData = INDUSTRY_DATA[industry as keyof typeof INDUSTRY_DATA] || INDUSTRY_DATA.technology
  const role = industryData.commonRoles[Math.floor(Math.random() * industryData.commonRoles.length)]
  
  const targetAnalysis = {
    profile: {
      name: targetName || 'John Doe',
      role: role,
      company: targetCompany || 'Example Corp',
      email: targetEmail || 'john.doe@example.com',
      socialMedia: industryData.platforms,
      vulnerabilities: industryData.vulnerabilities,
      riskLevel: calculateRiskLevel(targetType, industry) as any
    },
    digitalFootprint: {
      socialPlatforms: industryData.platforms,
      publicInfo: [
        'LinkedIn profile with work history',
        'Company website employee directory',
        'Conference speaker listings',
        'Professional association memberships',
        'Social media posts about work projects'
      ],
      connections: generateConnections(targetCompany),
      interests: industryData.interests
    },
    attackVectors: ATTACK_VECTORS[campaignType as keyof typeof ATTACK_VECTORS] || ATTACK_VECTORS.phishing
  }
  
  // Generate templates
  const templates = {
    emails: generateEmailTemplates(campaignType, targetAnalysis.profile, includePersonalization),
    messages: generateMessageTemplates(targetAnalysis.profile),
    calls: generateCallScripts(campaignType, targetAnalysis.profile)
  }
  
  // Psychology profiles
  const psychologyProfiles = includePsychology ? PSYCHOLOGY_PROFILES : []
  
  // Defensive measures
  const defensiveMeasures = includeDefenses ? generateDefensiveMeasures(campaignType, attackGoal) : []
  
  // Awareness tips
  const awarenessTips = generateAwarenessTips(campaignType)
  
  // Summary
  const summary = `Analyzed ${campaignType} campaign targeting ${targetType} in ${industry} industry. Identified ${targetAnalysis.attackVectors.length} attack vectors with ${targetAnalysis.profile.riskLevel.toLowerCase()} risk level. Generated ${templates.emails.length} email templates and comprehensive defensive strategies.`
  
  return {
    campaignType,
    targetAnalysis,
    templates,
    psychologyProfiles,
    defensiveMeasures,
    awarenessTips,
    summary
  }
}

function calculateRiskLevel(targetType: string, industry: string): string {
  let riskScore = 0
  
  // Target type scoring
  switch (targetType) {
    case 'executive': riskScore += 4; break
    case 'employee': riskScore += 2; break
    case 'contractor': riskScore += 3; break
    case 'customer': riskScore += 1; break
    default: riskScore += 2
  }
  
  // Industry scoring
  switch (industry) {
    case 'finance': riskScore += 3; break
    case 'healthcare': riskScore += 3; break
    case 'government': riskScore += 4; break
    case 'technology': riskScore += 2; break
    default: riskScore += 2
  }
  
  if (riskScore >= 6) return 'Critical'
  if (riskScore >= 4) return 'High'
  if (riskScore >= 2) return 'Medium'
  return 'Low'
}

function generateConnections(company: string): string[] {
  return [
    `CEO of ${company}`,
    `CTO of ${company}`,
    `HR Director at ${company}`,
    'Industry colleagues',
    'Former coworkers',
    'University alumni',
    'Conference connections',
    'Professional associations'
  ]
}

function generateEmailTemplates(campaignType: string, profile: any, personalize: boolean) {
  const template = EMAIL_TEMPLATES[campaignType as keyof typeof EMAIL_TEMPLATES] || EMAIL_TEMPLATES.phishing
  
  let subject = template.subject
  let body = template.body
  
  if (personalize) {
    subject = subject.replace('{name}', profile.name)
    subject = subject.replace('{company}', profile.company)
    body = body.replace(/{name}/g, profile.name)
    body = body.replace(/{company}/g, profile.company)
  }
  
  return [{
    subject,
    body,
    type: template.type,
    effectiveness: template.effectiveness,
    red_flags: template.red_flags
  }]
}

function generateMessageTemplates(profile: any) {
  return [
    {
      platform: 'LinkedIn',
      message: `Hi ${profile.name}, I came across your profile and was impressed by your experience at ${profile.company}. I have an interesting opportunity that might be relevant to your background. Would you be open to a brief conversation?`,
      context: 'Professional networking',
      approach: 'Authority and opportunity'
    },
    {
      platform: 'Twitter',
      message: `@${profile.name.toLowerCase().replace(' ', '')} Loved your recent insights on the industry! DMing you about a collaboration opportunity.`,
      context: 'Social media engagement',
      approach: 'Flattery and exclusivity'
    }
  ]
}

function generateCallScripts(campaignType: string, profile: any) {
  return [
    {
      script: `Hello, this is Sarah from the IT Security department at ${profile.company}. We've detected some unusual activity on your account and need to verify your identity. Can you please confirm your username and current password so we can secure your account?`,
      scenario: 'IT Security Impersonation',
      duration: '3-5 minutes',
      key_points: [
        'Establish authority and urgency',
        'Reference company name for credibility',
        'Request credentials under security pretext',
        'Create time pressure for quick decision'
      ]
    }
  ]
}

function generateDefensiveMeasures(campaignType: string, attackGoal: string): string[] {
  const baseMeasures = [
    'Implement multi-factor authentication on all accounts',
    'Conduct regular security awareness training',
    'Establish verification procedures for sensitive requests',
    'Deploy email security solutions with phishing detection',
    'Create incident response procedures for social engineering attempts'
  ]
  
  const specificMeasures = {
    credential_theft: [
      'Never share passwords over phone or email',
      'Use password managers for unique, complex passwords',
      'Enable account monitoring and alerts'
    ],
    financial_fraud: [
      'Implement dual approval for financial transactions',
      'Verify payment changes through multiple channels',
      'Train finance staff on common fraud techniques'
    ],
    data_extraction: [
      'Classify and protect sensitive data appropriately',
      'Implement data loss prevention (DLP) solutions',
      'Monitor and log data access activities'
    ]
  }
  
  return [...baseMeasures, ...(specificMeasures[attackGoal as keyof typeof specificMeasures] || [])]
}

function generateAwarenessTips(campaignType: string): string[] {
  const baseTips = [
    'Be suspicious of unsolicited contact requesting sensitive information',
    'Verify the identity of unknown contacts through official channels',
    'Never provide passwords, PINs, or sensitive data over phone or email',
    'Take time to think before responding to urgent requests',
    'Report suspicious communications to your security team'
  ]
  
  const campaignSpecific = {
    phishing: [
      'Check sender email addresses carefully for spoofing',
      'Hover over links to see actual destinations before clicking',
      'Be wary of urgent language and threatening consequences'
    ],
    vishing: [
      'Legitimate organizations rarely call requesting sensitive information',
      'Ask for callback numbers and verify independently',
      'Be suspicious of callers who pressure for immediate action'
    ],
    smishing: [
      'Be cautious of text messages with links or requesting personal info',
      'Verify SMS senders through official channels',
      'Never reply to suspicious text messages'
    ]
  }
  
  return [...baseTips, ...(campaignSpecific[campaignType as keyof typeof campaignSpecific] || [])]
}

export async function POST(request: NextRequest) {
  try {
    const body: SocialEngineeringRequest = await request.json()
    
    // Validate required fields
    if (!body.campaignType || !body.targetType || !body.industry) {
      return NextResponse.json(
        { error: 'Campaign type, target type, and industry are required' },
        { status: 400 }
      )
    }
    
    // Simulate processing time for realism
    await new Promise(resolve => setTimeout(resolve, 900))
    
    const results = await analyzeSocialEngineeringVectors(body)
    
    return NextResponse.json({
      success: true,
      data: results
    })
    
  } catch (error) {
    console.error('Social Engineering API Error:', error)
    
    return NextResponse.json(
      { error: 'Failed to analyze social engineering vectors' },
      { status: 500 }
    )
  }
}