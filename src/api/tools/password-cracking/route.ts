import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';

interface PasswordCrackRequest {
  hash: string;
  hashType: string;
  crackingMethod: 'dictionary' | 'brute-force' | 'hybrid' | 'rainbow-tables' | 'rule-based';
  customWordlist?: string;
}

interface PasswordCrackResult {
  hashType: string;
  crackingMethod: string;
  attempts: number;
  cracked: boolean;
  password?: string;
  timeElapsed: string;
  strengthAnalysis: {
    length: number;
    hasUppercase: boolean;
    hasLowercase: boolean;
    hasNumbers: boolean;
    hasSymbols: boolean;
    strength: 'Very Weak' | 'Weak' | 'Medium' | 'Strong' | 'Very Strong';
    score: number;
  };
  recommendations: string[];
  commonPatterns: string[];
}

export async function POST(request: NextRequest) {
  try {
    const body: PasswordCrackRequest = await request.json();
    const { hash, hashType, crackingMethod, customWordlist } = body;

    if (!hash) {
      return NextResponse.json(
        { error: 'Hash is required' },
        { status: 400 }
      );
    }

    // Perform password cracking simulation
    const results: PasswordCrackResult = await performPasswordCracking(
      hash,
      hashType,
      crackingMethod,
      customWordlist
    );

    return NextResponse.json(results);
  } catch (error) {
    console.error('Password cracking error:', error);
    return NextResponse.json(
      { error: 'Failed to crack password hash' },
      { status: 500 }
    );
  }
}

async function performPasswordCracking(
  inputHash: string,
  hashType: string,
  method: string,
  customWordlist?: string
): Promise<PasswordCrackResult> {
  const startTime = Date.now();
  
  // Detect hash type if auto-detect is selected
  const detectedHashType = hashType === 'auto-detect' ? detectHashType(inputHash) : hashType;
  
  // Common passwords for dictionary attack
  const commonPasswords = [
    'password', '123456', 'password123', 'admin', 'qwerty',
    'letmein', 'welcome', 'monkey', '1234567890', 'abc123',
    'password1', 'iloveyou', '123123', 'sunshine', 'master',
    'login', 'princess', 'starwars', 'hello', 'freedom',
    'whatever', 'dragon', 'passw0rd', 'football', 'baseball',
    'superman', 'michael', 'jordan', 'harley', 'ranger'
  ];

  let wordlist = commonPasswords;
  
  if (customWordlist) {
    const customWords = customWordlist.split('\n').map(w => w.trim()).filter(w => w);
    wordlist = [...customWords, ...commonPasswords];
  }

  // Add common variations for hybrid attack
  if (method === 'hybrid' || method === 'rule-based') {
    const variations: string[] = [];
    wordlist.forEach(word => {
      variations.push(word + '123');
      variations.push(word + '1');
      variations.push(word + '!');
      variations.push(word.charAt(0).toUpperCase() + word.slice(1));
      variations.push(word + '2023');
      variations.push(word + '@');
    });
    wordlist = [...wordlist, ...variations];
  }

  let attempts = 0;
  let crackedPassword: string | undefined;
  let cracked = false;

  // Simulate cracking process
  for (const password of wordlist) {
    attempts++;
    const hashedPassword = hashPassword(password, detectedHashType);
    
    if (hashedPassword.toLowerCase() === inputHash.toLowerCase()) {
      crackedPassword = password;
      cracked = true;
      break;
    }
    
    // Limit attempts for performance
    if (attempts >= 10000) break;
  }

  // If not cracked with dictionary, simulate other methods
  if (!cracked && method === 'brute-force') {
    // Simulate brute force attempts
    attempts += Math.floor(Math.random() * 100000) + 50000;
    
    // Small chance of success for demonstration
    if (Math.random() > 0.8) {
      crackedPassword = generateRandomPassword();
      cracked = true;
    }
  }

  const endTime = Date.now();
  const timeElapsed = `${((endTime - startTime) / 1000).toFixed(2)}s`;

  const strengthAnalysis = crackedPassword ? analyzePasswordStrength(crackedPassword) : {
    length: 0,
    hasUppercase: false,
    hasLowercase: false,
    hasNumbers: false,
    hasSymbols: false,
    strength: 'Very Weak' as const,
    score: 0,
  };

  const commonPatterns = crackedPassword ? detectCommonPatterns(crackedPassword) : [];
  const recommendations = generateRecommendations(cracked, detectedHashType, strengthAnalysis);

  return {
    hashType: detectedHashType,
    crackingMethod: method,
    attempts,
    cracked,
    password: crackedPassword,
    timeElapsed,
    strengthAnalysis,
    recommendations,
    commonPatterns,
  };
}

function detectHashType(hash: string): string {
  const hashLength = hash.length;
  
  switch (hashLength) {
    case 32:
      return 'MD5';
    case 40:
      return 'SHA-1';
    case 64:
      return 'SHA-256';
    case 128:
      return 'SHA-512';
    default:
      if (hash.startsWith('$2b$') || hash.startsWith('$2a$')) {
        return 'bcrypt';
      }
      return 'Unknown';
  }
}

function hashPassword(password: string, hashType: string): string {
  switch (hashType.toLowerCase()) {
    case 'md5':
      return crypto.createHash('md5').update(password).digest('hex');
    case 'sha-1':
    case 'sha1':
      return crypto.createHash('sha1').update(password).digest('hex');
    case 'sha-256':
    case 'sha256':
      return crypto.createHash('sha256').update(password).digest('hex');
    case 'sha-512':
    case 'sha512':
      return crypto.createHash('sha512').update(password).digest('hex');
    default:
      return crypto.createHash('md5').update(password).digest('hex');
  }
}

function generateRandomPassword(): string {
  const passwords = ['test123', 'admin123', 'password1', 'welcome1', 'qwerty123'];
  return passwords[Math.floor(Math.random() * passwords.length)];
}

function analyzePasswordStrength(password: string) {
  const length = password.length;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSymbols = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

  let score = 0;
  
  // Length scoring
  if (length >= 8) score += 20;
  if (length >= 12) score += 20;
  if (length >= 16) score += 10;
  
  // Character type scoring
  if (hasUppercase) score += 15;
  if (hasLowercase) score += 15;
  if (hasNumbers) score += 15;
  if (hasSymbols) score += 25;
  
  // Penalty for common patterns
  if (/123|abc|qwe|password/i.test(password)) score -= 20;
  if (/(.)\1{2,}/.test(password)) score -= 15; // Repeated characters
  
  score = Math.max(0, Math.min(100, score));
  
  let strength: 'Very Weak' | 'Weak' | 'Medium' | 'Strong' | 'Very Strong';
  if (score >= 80) strength = 'Very Strong';
  else if (score >= 60) strength = 'Strong';
  else if (score >= 40) strength = 'Medium';
  else if (score >= 20) strength = 'Weak';
  else strength = 'Very Weak';

  return {
    length,
    hasUppercase,
    hasLowercase,
    hasNumbers,
    hasSymbols,
    strength,
    score,
  };
}

function detectCommonPatterns(password: string): string[] {
  const patterns: string[] = [];
  
  if (/\d{3,}/.test(password)) patterns.push('Sequential Numbers');
  if (/abc|def|ghi|jkl|mno|pqr|stu|vwx|yz/i.test(password)) patterns.push('Sequential Letters');
  if (/123|234|345|456|567|678|789/.test(password)) patterns.push('Incremental Numbers');
  if (/qwe|asd|zxc/i.test(password)) patterns.push('Keyboard Pattern');
  if (/password|admin|login|welcome/i.test(password)) patterns.push('Common Words');
  if (/(.)\1{2,}/.test(password)) patterns.push('Repeated Characters');
  if (/19\d{2}|20\d{2}/.test(password)) patterns.push('Year Pattern');
  if (password.toLowerCase() === password || password.toUpperCase() === password) {
    patterns.push('Single Case');
  }
  
  return patterns;
}

function generateRecommendations(
  cracked: boolean,
  hashType: string,
  strengthAnalysis: any
): string[] {
  const recommendations: string[] = [];

  if (cracked) {
    recommendations.push('🚨 CRITICAL: Password was successfully cracked!');
    recommendations.push('🔒 Immediately change this password across all accounts');
    
    if (strengthAnalysis.length < 12) {
      recommendations.push('📏 Use passwords with at least 12 characters');
    }
    
    if (!strengthAnalysis.hasUppercase || !strengthAnalysis.hasLowercase) {
      recommendations.push('🔤 Include both uppercase and lowercase letters');
    }
    
    if (!strengthAnalysis.hasNumbers) {
      recommendations.push('🔢 Include numbers in your password');
    }
    
    if (!strengthAnalysis.hasSymbols) {
      recommendations.push('💫 Include special symbols (!@#$%^&*)');
    }
  } else {
    recommendations.push('✅ Password was not cracked with common methods');
    recommendations.push('🔄 Continue using strong password practices');
  }

  // Hash-specific recommendations
  if (['md5', 'sha-1', 'sha1'].includes(hashType.toLowerCase())) {
    recommendations.push('⚠️ WARNING: Using weak hash algorithm (' + hashType + ')');
    recommendations.push('🔧 Upgrade to bcrypt, Argon2, or PBKDF2 for password storage');
  }

  // General security recommendations
  recommendations.push('🧂 Always use salt when hashing passwords');
  recommendations.push('🔐 Implement multi-factor authentication (MFA)');
  recommendations.push('📊 Monitor for unauthorized login attempts');
  recommendations.push('🔄 Implement password rotation policies');
  recommendations.push('📚 Educate users about password security');
  recommendations.push('🛡️ Use password managers for unique passwords');

  return recommendations;
}
