export interface ToolResult {
  output: string
  error?: string
  executionTime: number
  status: "success" | "error" | "timeout"
}

export interface ServiceName {
  [key: number]: string
}
