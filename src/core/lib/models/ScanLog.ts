import mongoose from "mongoose"

// Common interfaces for scan findings
interface Finding {
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cvssScore?: number;
  cve?: string[];
  remediation: string;
  affected?: string[];
  references?: string[];
}

interface Target {
  host: string;
  port?: number;
  protocol?: string;
  service?: string;
  domain?: string;
  ip?: string;
}

interface ScanInput {
  target: Target
  options?: Record<string, any>
  customParameters?: Record<string, any>
}

interface ScanOutput {
  summary: string
  findings: Finding[]
  rawOutput: string
  technicalDetails?: Record<string, any>
}

interface Statistics {
  vulnerabilitiesByType?: Record<string, number>
  severityDistribution?: Record<string, number>
  totalVulnerabilities: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  infoCount: number
  risksFound: string[]
  affectedServices: string[]
}

interface ScanMetrics {
  startTime: Date
  endTime: Date
  duration: number
  requestsSent?: number
  responsesReceived?: number
  bytesTransferred?: number
  cpuUsage?: number
  memoryUsage?: number
}

export interface IScanLog extends mongoose.Document {
  userId: mongoose.Types.ObjectId
  toolName: string
  toolCategory: string
  toolVersion?: string
  input: ScanInput
  output: ScanOutput
  status: "success" | "error" | "timeout" | "in-progress" | "cancelled"
  errorDetails?: {
    code: string
    message: string
    stack?: string
  }
  metrics: ScanMetrics
  statistics: Statistics
  tags?: string[]
  priority: "low" | "medium" | "high" | "critical"
  assignedTo?: mongoose.Types.ObjectId
  notes?: string[]
  createdAt: Date
  updatedAt: Date
  lastActivityAt: Date
}

const findingSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  severity: {
    type: String,
    enum: ["critical", "high", "medium", "low", "info"],
    required: true,
  },
  cvssScore: { type: Number },
  cve: [String],
  remediation: { type: String, required: true },
  affected: [String],
  references: [String],
})

const targetSchema = new mongoose.Schema({
  host: { type: String, required: true },
  port: Number,
  protocol: String,
  service: String,
  domain: String,
  ip: String,
})

const scanLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    toolName: {
      type: String,
      required: true,
      enum: [
        // Basic tools
        "nmap", "sublist3r", "nikto", "whois", "dig", "curl", "dns-lookup", "port-scanner",
        "network-scan", "subdomain-enum", "vuln-scanner", "vuln-scan", "http-headers", "subdomain",

        // Advanced tools  
        "gobuster", "dirb", "theHarvester", "iwlist", "setoolkit", "apktool", "file", 
        "crypto-analysis", "masscan", "burpsuite", "radare2", "tcpdump", "scout", "docker",
        "social-engineering", "osint-toolkit", "dirbuster", "wireless-security", "mobile-security",
        "cryptography", "forensics", "digital-forensics",
        // Expert tools
        "msfconsole", "wireshark", "owasp-zap", "recon-ng", "msfvenom", "ghidra", "scoutsuite", "docker-bench",
        "metasploit", "burp-suite", "cloud-security", "network-analysis", "binary-analysis", "container-security"
      ],
      index: true,
    },
    toolCategory: {
      type: String,
      required: true,
      enum: [
        "Network Security",
        "Web Security",
        "Application Security",
        "Cloud Security",
        "Mobile Security",
        "IoT Security",
        "Forensics",
        "Cryptography",
        "OSINT",
        "AI Security",
        "Other"
      ],
    },
    toolVersion: String,
    input: {
      target: { type: targetSchema, required: true },
      options: { type: Map, of: mongoose.Schema.Types.Mixed },
      customParameters: { type: Map, of: mongoose.Schema.Types.Mixed },
    },
    output: {
      summary: { type: String, required: true },
      findings: [findingSchema],
      rawOutput: { type: String, required: true },
      technicalDetails: { type: Map, of: mongoose.Schema.Types.Mixed },
    },
    status: {
      type: String,
      enum: ["success", "error", "timeout", "in-progress", "cancelled"],
      required: true,
      index: true,
    },
    errorDetails: {
      code: String,
      message: String,
      stack: String,
    },
    metrics: {
      startTime: { type: Date, required: true },
      endTime: { type: Date, required: true },
      duration: { type: Number, required: true },
      requestsSent: Number,
      responsesReceived: Number,
      bytesTransferred: Number,
      cpuUsage: Number,
      memoryUsage: Number,
    },
    statistics: {
      vulnerabilitiesByType: { type: Map, of: Number },
      severityDistribution: { type: Map, of: Number },
      totalVulnerabilities: { type: Number, required: true, default: 0 },
      criticalCount: { type: Number, required: true, default: 0 },
      highCount: { type: Number, required: true, default: 0 },
      mediumCount: { type: Number, required: true, default: 0 },
      lowCount: { type: Number, required: true, default: 0 },
      infoCount: { type: Number, required: true, default: 0 },
      risksFound: [String],
      affectedServices: [String],
    },
    tags: {
      type: [String],
      index: true,
    },
    priority: {
      type: String,
      enum: ["low", "medium", "high", "critical"],
      required: true,
      default: "low",
      index: true,
    },
    assignedTo: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      index: true,
    },
    notes: [String],
    lastActivityAt: {
      type: Date,
      required: true,
      default: Date.now,
      index: true,
    },
  },
  {
    timestamps: true,
    // Create compound indexes for common queries
    indexes: [
      { userId: 1, createdAt: -1 },
      { userId: 1, toolName: 1 },
      { userId: 1, status: 1 },
      { userId: 1, priority: 1 },
      { userId: 1, toolCategory: 1 },
    ],
  }
)

// Add a method to calculate risk score based on findings
scanLogSchema.methods.calculateRiskScore = function(): number {
  const severity = {
    critical: 10,
    high: 7,
    medium: 4,
    low: 1,
    info: 0
  }

  const findings = this.output.findings
  if (!findings || findings.length === 0) return 0

  const totalSeverityScore = findings.reduce((score: number, finding: any) => {
    return score + (severity[finding.severity as keyof typeof severity] || 0)
  }, 0)

  return Math.min(Math.round((totalSeverityScore / findings.length) * 10), 100)
}

// Add method to get security improvement recommendations
scanLogSchema.methods.getRecommendations = function(): string[] {
  const recommendations = new Set<string>()
  this.output.findings.forEach((finding: any) => {
    if (finding.remediation) {
      recommendations.add(finding.remediation)
    }
  })
  return Array.from(recommendations)
}

// Add method to get summary statistics
scanLogSchema.methods.getSummaryStats = function() {
  return {
    totalFindings: this.statistics.totalVulnerabilities,
    criticalIssues: this.statistics.criticalCount,
    highIssues: this.statistics.highCount,
    mediumIssues: this.statistics.mediumCount,
    lowIssues: this.statistics.lowCount,
    infoIssues: this.statistics.infoCount,
    executionTime: this.metrics.duration,
    status: this.status,
    riskScore: this.calculateRiskScore(),
  }
}

const ScanLog = mongoose.models.ScanLog || mongoose.model<IScanLog>("ScanLog", scanLogSchema);
export default ScanLog;
export { ScanLog };
