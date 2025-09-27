import { NextRequest, NextResponse } from 'next/server';

interface DirectoryBruteRequest {
  targetUrl: string;
  wordlistType: 'common' | 'comprehensive' | 'admin' | 'backup' | 'config' | 'custom';
  customWordlist?: string;
  extensions?: string;
  threads: number;
}

interface DirectoryBruteResult {
  foundDirectories: string[];
  foundFiles: string[];
  totalRequests: number;
  successfulRequests: number;
  statusCodes: { [key: string]: number };
  interestingFindings: string[];
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  recommendations: string[];
  detailedResults: {
    path: string;
    statusCode: number;
    size: number;
    contentType: string;
    interesting: boolean;
  }[];
}

export async function POST(request: NextRequest) {
  try {
    const body: DirectoryBruteRequest = await request.json();
    const { targetUrl, wordlistType, customWordlist, extensions, threads } = body;

    if (!targetUrl) {
      return NextResponse.json(
        { error: 'Target URL is required' },
        { status: 400 }
      );
    }

    // Generate directory brute force results
    const results: DirectoryBruteResult = await performDirectoryBruteForce(
      targetUrl,
      wordlistType,
      customWordlist,
      extensions,
      threads
    );

    return NextResponse.json(results);
  } catch (error) {
    console.error('Directory brute force error:', error);
    return NextResponse.json(
      { error: 'Failed to perform directory brute force' },
      { status: 500 }
    );
  }
}

async function performDirectoryBruteForce(
  targetUrl: string,
  wordlistType: string,
  customWordlist?: string,
  extensions?: string,
  threads?: number
): Promise<DirectoryBruteResult> {
  // Predefined wordlists
  const wordlists = {
    common: [
      'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
      'config', 'includes', 'uploads', 'images', 'css', 'js',
      'api', 'v1', 'v2', 'backup', 'test', 'dev', 'tmp'
    ],
    comprehensive: [
      'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin', 'cpanel',
      'config', 'configuration', 'settings', 'includes', 'inc', 'lib',
      'uploads', 'files', 'download', 'downloads', 'images', 'img',
      'css', 'js', 'javascript', 'assets', 'static', 'public',
      'api', 'rest', 'graphql', 'v1', 'v2', 'v3', 'api/v1', 'api/v2',
      'backup', 'backups', 'bak', 'old', 'archive', 'archives',
      'test', 'testing', 'dev', 'development', 'staging', 'demo',
      'tmp', 'temp', 'cache', 'logs', 'log', 'data', 'db',
      'install', 'setup', 'installer', 'wizard', 'readme',
      'docs', 'documentation', 'help', 'support', 'contact'
    ],
    admin: [
      'admin', 'administrator', 'adminpanel', 'admin-panel', 'control-panel',
      'cpanel', 'wp-admin', 'wp-login', 'login', 'signin', 'auth',
      'dashboard', 'panel', 'manage', 'manager', 'console',
      'moderator', 'webadmin', 'sysadmin', 'root', 'superuser'
    ],
    backup: [
      'backup', 'backups', 'bak', 'backup.zip', 'backup.tar',
      'site-backup', 'database-backup', 'db-backup', 'sql-backup',
      'backup.sql', 'dump.sql', 'backup.tar.gz', 'old', 'archive',
      'backup.rar', 'site.zip', 'www.zip', 'public_html.zip'
    ],
    config: [
      'config', 'configuration', 'settings', 'conf', 'cfg',
      'config.php', 'config.xml', 'config.json', 'settings.php',
      'web.config', 'app.config', '.env', 'environment', 'config.ini'
    ]
  };

  let wordlist: string[] = [];
  
  if (wordlistType === 'custom' && customWordlist) {
    wordlist = customWordlist.split('\n').map(w => w.trim()).filter(w => w);
  } else if (wordlists[wordlistType as keyof typeof wordlists]) {
    wordlist = wordlists[wordlistType as keyof typeof wordlists];
  } else {
    wordlist = wordlists.common;
  }

  // Add extensions if specified
  const extensionList = extensions ? extensions.split(',').map(e => e.trim()) : [];
  const finalWordlist: string[] = [...wordlist];
  
  if (extensionList.length > 0) {
    wordlist.forEach(word => {
      extensionList.forEach(ext => {
        finalWordlist.push(`${word}.${ext}`);
      });
    });
  }

  // Perform real directory brute force
  const detailedResults = await performRealDirectoryBruteforce(targetUrl, finalWordlist, threads || 5);

  const successfulResults = detailedResults.filter((result: any) => 
    result.statusCode >= 200 && result.statusCode < 400
  );

  const foundDirectories = successfulResults
    .filter((result: any) => !result.path.includes('.'))
    .map((result: any) => result.path);

  const foundFiles = successfulResults
    .filter((result: any) => result.path.includes('.'))
    .map((result: any) => result.path);

  const statusCodes = detailedResults.reduce((acc: any, result: any) => {
    acc[result.statusCode.toString()] = (acc[result.statusCode.toString()] || 0) + 1;
    return acc;
  }, {} as { [key: string]: number });

  const interestingFindings = successfulResults
    .filter((result: any) => result.interesting)
    .map((result: any) => `Found potentially sensitive path: ${result.path}`);

  const riskLevel = calculateRiskLevel(interestingFindings.length, foundFiles.length + foundDirectories.length);
  const recommendations = generateRecommendations(successfulResults.length > 0, interestingFindings.length);

  return {
    foundDirectories,
    foundFiles,
    totalRequests: finalWordlist.length,
    successfulRequests: successfulResults.length,
    statusCodes,
    interestingFindings,
    riskLevel,
    recommendations,
    detailedResults: detailedResults.slice(0, 100), // Limit results for performance
  };
}

async function performRealDirectoryBruteforce(
  targetUrl: string,
  wordlist: string[],
  maxConcurrency: number
): Promise<Array<{
  path: string;
  statusCode: number;
  size: number;
  contentType: string;
  interesting: boolean;
}>> {
  const results: Array<{
    path: string;
    statusCode: number;
    size: number;
    contentType: string;
    interesting: boolean;
  }> = [];

  // Ensure target URL ends with /
  const baseUrl = targetUrl.endsWith('/') ? targetUrl : targetUrl + '/';

  // Process wordlist in chunks to control concurrency
  for (let i = 0; i < wordlist.length; i += maxConcurrency) {
    const chunk = wordlist.slice(i, i + maxConcurrency);
    const chunkPromises = chunk.map(async (path) => {
      try {
        const fullUrl = `${baseUrl}${path}`;
        const startTime = Date.now();
        
        const response = await fetch(fullUrl, {
          method: 'HEAD', // Use HEAD to reduce bandwidth
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
          },
          signal: AbortSignal.timeout(5000), // 5 second timeout
        });

        const responseTime = Date.now() - startTime;
        const contentLength = parseInt(response.headers.get('content-length') || '0');
        const contentType = response.headers.get('content-type') || 'unknown';
        const interesting = isInterestingPath(path, response.status);

        return {
          path: `/${path}`,
          statusCode: response.status,
          size: contentLength,
          contentType,
          interesting,
        };
      } catch (error) {
        // If HEAD fails, try GET with range to minimize data transfer
        try {
          const fullUrl = `${baseUrl}${path}`;
          const response = await fetch(fullUrl, {
            method: 'GET',
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
              'Accept': '*/*',
              'Range': 'bytes=0-1023', // Only get first 1KB
            },
            signal: AbortSignal.timeout(5000),
          });

          const contentType = response.headers.get('content-type') || 'unknown';
          const interesting = isInterestingPath(path, response.status);

          return {
            path: `/${path}`,
            statusCode: response.status,
            size: 1024,
            contentType,
            interesting,
          };
        } catch (secondError) {
          return {
            path: `/${path}`,
            statusCode: 0,
            size: 0,
            contentType: 'error',
            interesting: false,
          };
        }
      }
    });

    const chunkResults = await Promise.all(chunkPromises);
    results.push(...chunkResults);

    // Add a small delay between chunks to be respectful
    if (i + maxConcurrency < wordlist.length) {
      await new Promise(resolve => setTimeout(resolve, 200));
    }
  }

  return results;
}

function generateStatusCode(): number {
  const codes = [200, 301, 302, 403, 404, 500];
  const weights = [0.15, 0.05, 0.05, 0.10, 0.60, 0.05]; // 404 is most common
  
  const random = Math.random();
  let weightSum = 0;
  
  for (let i = 0; i < codes.length; i++) {
    weightSum += weights[i];
    if (random <= weightSum) {
      return codes[i];
    }
  }
  
  return 404;
}

function determineContentType(path: string): string {
  const extension = path.split('.').pop()?.toLowerCase();
  
  const mimeTypes: { [key: string]: string } = {
    'html': 'text/html',
    'php': 'text/html',
    'asp': 'text/html',
    'jsp': 'text/html',
    'js': 'application/javascript',
    'css': 'text/css',
    'json': 'application/json',
    'xml': 'application/xml',
    'txt': 'text/plain',
    'zip': 'application/zip',
    'tar': 'application/x-tar',
    'sql': 'application/sql',
    'bak': 'application/octet-stream',
  };
  
  return extension ? (mimeTypes[extension] || 'application/octet-stream') : 'text/html';
}

function isInterestingPath(path: string, statusCode: number): boolean {
  if (statusCode >= 400) return false;
  
  const interestingKeywords = [
    'admin', 'config', 'backup', 'test', 'dev', 'api',
    '.env', '.git', 'phpmyadmin', 'cpanel', 'install',
    'setup', 'database', 'sql', 'dump', 'secret'
  ];
  
  return interestingKeywords.some(keyword => 
    path.toLowerCase().includes(keyword.toLowerCase())
  );
}

function calculateRiskLevel(
  interestingFindings: number,
  totalFindings: number
): 'Low' | 'Medium' | 'High' | 'Critical' {
  if (interestingFindings >= 5) return 'Critical';
  if (interestingFindings >= 3) return 'High';
  if (interestingFindings >= 1) return 'Medium';
  if (totalFindings >= 10) return 'Medium';
  return 'Low';
}

function generateRecommendations(
  pathsFound: boolean,
  interestingCount: number
): string[] {
  const baseRecommendations = [
    "🔒 Implement proper access controls for all directories",
    "🛡️ Use .htaccess or web server rules to restrict access",
    "🔍 Regular security audits to identify exposed files",
    "📊 Monitor web server logs for suspicious scanning activity",
    "⚡ Implement rate limiting to prevent brute force attacks",
  ];

  if (!pathsFound) {
    return [
      "✅ No accessible directories or files found during scan",
      "🔄 Continue regular security assessments",
      ...baseRecommendations,
    ];
  }

  const criticalRecommendations = [
    "🚨 Critical: Exposed directories and files detected",
    "🔧 Immediately review and restrict access to sensitive paths",
    "📋 Remove unnecessary files and directories from web root",
    "🎯 Implement directory listing restrictions",
  ];

  if (interestingCount > 0) {
    criticalRecommendations.unshift(
      "⚠️ HIGH PRIORITY: Sensitive files/directories exposed to public access"
    );
  }

  return [
    ...criticalRecommendations,
    ...baseRecommendations,
    "🔐 Consider implementing authentication for admin areas",
    "📱 Deploy Web Application Firewall (WAF) protection",
    "🗄️ Backup files should never be accessible via web",
  ];
}
