import mongoose from "mongoose"

export interface IScanLog extends mongoose.Document {
  userId: mongoose.Types.ObjectId
  toolName: string
  input: string
  output: string
  status: "success" | "error" | "timeout"
  executionTime: number
  createdAt: Date
}

const scanLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
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
    },
    input: {
      type: String,
      required: true,
    },
    output: {
      type: String,
      required: true,
    },
    status: {
      type: String,
      enum: ["success", "error", "timeout"],
      required: true,
    },
    executionTime: {
      type: Number,
      required: true,
    },
  },
  {
    timestamps: true,
  },
)

export default mongoose.models.ScanLog || mongoose.model<IScanLog>("ScanLog", scanLogSchema)
