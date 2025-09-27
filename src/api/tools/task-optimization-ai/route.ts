import { NextRequest, NextResponse } from 'next/server'

interface Task {
  id: string
  title: string
  description: string
  priority: 'low' | 'medium' | 'high' | 'critical'
  status: 'todo' | 'in-progress' | 'completed' | 'blocked'
  category: string
  estimatedHours: number
  deadline?: string
  dependencies: string[]
  tags: string[]
  aiScore: number
  createdAt: string
}

// Advanced Task Optimization AI class
class TaskOptimizationAI {
  private priorityWeights = {
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
  }

  private statusWeights = {
    blocked: 0,
    todo: 1,
    'in-progress': 2,
    completed: 3
  }

  private categoryComplexities = {
    'Development': 0.9,
    'Design': 0.7,
    'Research': 0.8,
    'Marketing': 0.6,
    'Administration': 0.4,
    'Communication': 0.3,
    'Testing': 0.8,
    'Documentation': 0.5,
    'Planning': 0.6,
    'Review': 0.4
  }

  calculateProductivityIndex(tasks: Task[]): number {
    if (tasks.length === 0) return 0

    const completedTasks = tasks.filter(t => t.status === 'completed')
    const inProgressTasks = tasks.filter(t => t.status === 'in-progress')
    const blockedTasks = tasks.filter(t => t.status === 'blocked')
    
    // Base completion rate
    const completionRate = (completedTasks.length / tasks.length) * 100
    
    // Progress bonus
    const progressBonus = (inProgressTasks.length / tasks.length) * 20
    
    // Penalty for blocked tasks
    const blockedPenalty = (blockedTasks.length / tasks.length) * 30
    
    // Priority alignment bonus
    const highPriorityCompleted = completedTasks.filter(t => t.priority === 'high' || t.priority === 'critical').length
    const totalHighPriority = tasks.filter(t => t.priority === 'high' || t.priority === 'critical').length
    const priorityBonus = totalHighPriority > 0 ? (highPriorityCompleted / totalHighPriority) * 15 : 0
    
    const productivityIndex = Math.max(0, Math.min(100, 
      completionRate + progressBonus - blockedPenalty + priorityBonus
    ))

    return Math.round(productivityIndex)
  }

  calculateAverageScore(tasks: Task[]): number {
    if (tasks.length === 0) return 0
    const totalScore = tasks.reduce((sum, task) => sum + task.aiScore, 0)
    return Math.round(totalScore / tasks.length)
  }

  calculateTimeToCompletion(tasks: Task[]): number {
    const incompleteTasks = tasks.filter(t => t.status !== 'completed')
    return incompleteTasks.reduce((total, task) => total + task.estimatedHours, 0)
  }

  identifyBottlenecks(tasks: Task[]): Array<{
    task: string
    issue: string
    impact: 'low' | 'medium' | 'high'
    suggestion: string
  }> {
    const bottlenecks: Array<{
      task: string
      issue: string
      impact: 'low' | 'medium' | 'high'
      suggestion: string
    }> = []

    // Check for blocked tasks
    const blockedTasks = tasks.filter(t => t.status === 'blocked')
    for (const task of blockedTasks) {
      bottlenecks.push({
        task: task.title,
        issue: 'Task is currently blocked and cannot proceed',
        impact: (task.priority === 'critical' || task.priority === 'high') ? 'high' as const : 'medium' as const,
        suggestion: 'Identify and resolve blocking dependencies to unblock this task'
      })
    }

    // Check for overdue tasks
    const currentDate = new Date()
    const overdueTasks = tasks.filter(t => 
      t.deadline && 
      new Date(t.deadline) < currentDate && 
      t.status !== 'completed'
    )
    for (const task of overdueTasks) {
      bottlenecks.push({
        task: task.title,
        issue: 'Task is overdue and still incomplete',
        impact: 'high' as const,
        suggestion: 'Reprioritize this task or adjust timeline expectations'
      })
    }

    // Check for high-complexity tasks without progress
    const stuckHighComplexityTasks = tasks.filter(t => 
      t.aiScore > 85 && 
      t.status === 'todo' && 
      this.getDaysOld(t.createdAt) > 3
    )
    for (const task of stuckHighComplexityTasks) {
      bottlenecks.push({
        task: task.title,
        issue: 'High-complexity task has been pending for several days',
        impact: 'medium' as const,
        suggestion: 'Break down into smaller sub-tasks or allocate dedicated focus time'
      })
    }

    // Check for tasks with many dependencies
    for (const task of tasks) {
      if (task.dependencies.length > 2 && task.status === 'todo') {
        bottlenecks.push({
          task: task.title,
          issue: 'Task has multiple dependencies that may cause delays',
          impact: 'medium' as const,
          suggestion: 'Review dependencies and consider if any can be removed or parallelized'
        })
      }
    }

    // Check for category overload
    const categoryDistribution = this.getCategoryDistribution(tasks)
    const overloadedCategories = categoryDistribution.filter(cat => cat.percentage > 40)
    for (const category of overloadedCategories) {
      bottlenecks.push({
        task: `${category.category} category workload`,
        issue: `Over 40% of tasks are in ${category.category} category`,
        impact: 'low' as const,
        suggestion: 'Consider distributing workload across different categories or team members'
      })
    }

    return bottlenecks.slice(0, 8) // Limit to most important bottlenecks
  }

  generateRecommendations(tasks: Task[]): Array<{
    type: 'priority' | 'workflow' | 'resource' | 'scheduling'
    title: string
    description: string
    impact: number
  }> {
    const recommendations: Array<{
      type: 'priority' | 'workflow' | 'resource' | 'scheduling'
      title: string
      description: string
      impact: number
    }> = []

    // Priority optimization
    const highPriorityTasks = tasks.filter(t => t.priority === 'critical' || t.priority === 'high')
    const completedHighPriority = highPriorityTasks.filter(t => t.status === 'completed')
    if (completedHighPriority.length / highPriorityTasks.length < 0.7) {
      recommendations.push({
        type: 'priority' as const,
        title: 'Focus on High-Priority Tasks',
        description: 'Complete critical and high-priority tasks first to maximize impact',
        impact: 85
      })
    }

    // Workflow optimization
    const blockedTasks = tasks.filter(t => t.status === 'blocked')
    if (blockedTasks.length > 0) {
      recommendations.push({
        type: 'workflow' as const,
        title: 'Resolve Blocked Tasks',
        description: 'Address dependencies and blockers to improve workflow efficiency',
        impact: 90
      })
    }

    // Time estimation improvement
    const avgScore = this.calculateAverageScore(tasks)
    if (avgScore > 80) {
      recommendations.push({
        type: 'resource' as const,
        title: 'Consider Task Complexity',
        description: 'High-complexity tasks may need additional resources or expertise',
        impact: 75
      })
    }

    // Category balancing
    const categoryDist = this.getCategoryDistribution(tasks)
    const imbalancedCategories = categoryDist.filter(cat => cat.percentage > 50)
    if (imbalancedCategories.length > 0) {
      recommendations.push({
        type: 'workflow' as const,
        title: 'Balance Task Categories',
        description: 'Distribute work across different categories to avoid burnout',
        impact: 60
      })
    }

    // Deadline management
    const upcomingDeadlines = tasks.filter(t => 
      t.deadline && 
      this.getDaysUntilDeadline(t.deadline) <= 7 && 
      t.status !== 'completed'
    )
    if (upcomingDeadlines.length > 0) {
      recommendations.push({
        type: 'scheduling' as const,
        title: 'Address Upcoming Deadlines',
        description: 'Focus on tasks with deadlines in the next 7 days',
        impact: 95
      })
    }

    // Progress optimization
    const todoTasks = tasks.filter(t => t.status === 'todo')
    const oldTodoTasks = todoTasks.filter(t => this.getDaysOld(t.createdAt) > 5)
    if (oldTodoTasks.length > 0) {
      recommendations.push({
        type: 'workflow' as const,
        title: 'Start Pending Tasks',
        description: 'Begin work on tasks that have been pending for more than 5 days',
        impact: 70
      })
    }

    // Resource allocation
    const longTasks = tasks.filter(t => t.estimatedHours > 8 && t.status !== 'completed')
    if (longTasks.length > 0) {
      recommendations.push({
        type: 'resource' as const,
        title: 'Break Down Large Tasks',
        description: 'Split tasks over 8 hours into smaller, manageable subtasks',
        impact: 80
      })
    }

    return recommendations.sort((a, b) => b.impact - a.impact).slice(0, 10)
  }

  getCategoryDistribution(tasks: Task[]): Array<{ category: string; count: number; percentage: number }> {
    const categoryCount: { [key: string]: number } = {}
    
    for (const task of tasks) {
      categoryCount[task.category] = (categoryCount[task.category] || 0) + 1
    }

    return Object.entries(categoryCount).map(([category, count]) => ({
      category,
      count,
      percentage: Math.round((count / tasks.length) * 100)
    })).sort((a, b) => b.count - a.count)
  }

  getPriorityDistribution(tasks: Task[]): Array<{ priority: string; count: number; percentage: number }> {
    const priorityCount: { [key: string]: number } = {}
    
    for (const task of tasks) {
      priorityCount[task.priority] = (priorityCount[task.priority] || 0) + 1
    }

    return Object.entries(priorityCount).map(([priority, count]) => ({
      priority,
      count,
      percentage: Math.round((count / tasks.length) * 100)
    })).sort((a, b) => this.priorityWeights[b.priority as keyof typeof this.priorityWeights] - this.priorityWeights[a.priority as keyof typeof this.priorityWeights])
  }

  generateCompletionTrends(tasks: Task[]): Array<{ period: string; completed: number; productivity: number }> {
    // Simulate historical data for trends
    const periods = ['Last Week', 'This Week', 'Projected Next Week']
    const completedTasks = tasks.filter(t => t.status === 'completed')
    
    return periods.map((period, index) => {
      const baseCompleted = Math.max(1, Math.floor(completedTasks.length / 3))
      const variance = Math.floor(Math.random() * 3) - 1 // -1 to +1
      const completed = Math.max(0, baseCompleted + variance)
      
      return {
        period,
        completed,
        productivity: Math.min(100, 60 + (completed * 5) + Math.floor(Math.random() * 20))
      }
    })
  }

  analyzeTimeEstimation(tasks: Task[]): {
    accuracy: number
    averageDeviation: number
    suggestions: string[]
  } {
    // Simulate estimation accuracy analysis
    const accuracy = Math.floor(Math.random() * 20) + 70 // 70-90%
    const averageDeviation = Math.round((Math.random() * 3 + 1) * 10) / 10 // 1.0-4.0 hours
    
    const suggestions = [
      'Track actual time spent vs estimates to improve future accuracy',
      'Consider breaking down complex tasks into smaller, more predictable subtasks',
      'Factor in potential interruptions and context switching time',
      'Use historical data from similar tasks for better estimates'
    ]

    if (accuracy < 75) {
      suggestions.unshift('Current estimation accuracy is below optimal - consider more detailed task analysis')
    }

    if (averageDeviation > 3) {
      suggestions.push('High deviation indicates need for better task scoping and requirements gathering')
    }

    return {
      accuracy,
      averageDeviation,
      suggestions: suggestions.slice(0, 4)
    }
  }

  generateAutomationSuggestions(tasks: Task[]): Array<{
    id: string
    title: string
    description: string
    automationType: 'recurring' | 'trigger-based' | 'schedule' | 'workflow'
    potentialSavings: number
    complexity: 'low' | 'medium' | 'high'
  }> {
    const suggestions: Array<{
      id: string
      title: string
      description: string
      automationType: 'recurring' | 'trigger-based' | 'schedule' | 'workflow'
      potentialSavings: number
      complexity: 'low' | 'medium' | 'high'
    }> = []

    // Check for recurring tasks
    const recurringKeywords = ['daily', 'weekly', 'monthly', 'regular', 'routine', 'standup', 'meeting', 'report']
    const potentialRecurring = tasks.filter(task => 
      recurringKeywords.some(keyword => 
        task.title.toLowerCase().includes(keyword) || 
        task.description.toLowerCase().includes(keyword) ||
        task.tags.some(tag => tag.toLowerCase().includes(keyword))
      )
    )

    if (potentialRecurring.length > 0) {
      suggestions.push({
        id: 'auto_1',
        title: 'Automate Recurring Tasks',
        description: 'Set up automatic creation of recurring tasks like daily standups, weekly reports, and routine maintenance',
        automationType: 'recurring' as const,
        potentialSavings: Math.min(10, potentialRecurring.length * 2),
        complexity: 'low' as const
      })
    }

    // Check for documentation tasks
    const docTasks = tasks.filter(t => 
      t.category === 'Documentation' || 
      t.tags.some(tag => ['docs', 'documentation', 'readme'].includes(tag.toLowerCase()))
    )

    if (docTasks.length > 0) {
      suggestions.push({
        id: 'auto_2',
        title: 'Auto-generate Documentation',
        description: 'Use AI to automatically generate initial documentation drafts from code comments and specifications',
        automationType: 'trigger-based' as const,
        potentialSavings: docTasks.length * 2,
        complexity: 'medium' as const
      })
    }

    // Check for testing tasks
    const testTasks = tasks.filter(t => 
      t.category === 'Testing' || 
      t.tags.some(tag => ['test', 'testing', 'qa'].includes(tag.toLowerCase()))
    )

    if (testTasks.length > 0) {
      suggestions.push({
        id: 'auto_3',
        title: 'Automated Testing Pipeline',
        description: 'Set up continuous integration to automatically run tests when code changes are made',
        automationType: 'trigger-based' as const,
        potentialSavings: testTasks.length * 1.5,
        complexity: 'high' as const
      })
    }

    // Check for code review tasks
    const reviewTasks = tasks.filter(t => 
      t.title.toLowerCase().includes('review') || 
      t.tags.some(tag => tag.toLowerCase().includes('review'))
    )

    if (reviewTasks.length > 0) {
      suggestions.push({
        id: 'auto_4',
        title: 'Automated Code Analysis',
        description: 'Use automated tools for initial code review to catch common issues before human review',
        automationType: 'workflow' as const,
        potentialSavings: reviewTasks.length * 1,
        complexity: 'medium' as const
      })
    }

    // Check for deployment tasks
    const deployTasks = tasks.filter(t => 
      t.title.toLowerCase().includes('deploy') || 
      t.tags.some(tag => ['deploy', 'deployment', 'release'].includes(tag.toLowerCase()))
    )

    if (deployTasks.length > 0) {
      suggestions.push({
        id: 'auto_5',
        title: 'Continuous Deployment',
        description: 'Automate deployment process to reduce manual effort and potential errors',
        automationType: 'workflow' as const,
        potentialSavings: deployTasks.length * 3,
        complexity: 'high' as const
      })
    }

    // Check for communication tasks
    const commTasks = tasks.filter(t => 
      t.category === 'Communication' || 
      t.tags.some(tag => ['email', 'notification', 'update'].includes(tag.toLowerCase()))
    )

    if (commTasks.length > 0) {
      suggestions.push({
        id: 'auto_6',
        title: 'Automated Status Updates',
        description: 'Set up automatic progress notifications and status updates to stakeholders',
        automationType: 'schedule' as const,
        potentialSavings: commTasks.length * 0.5,
        complexity: 'low' as const
      })
    }

    return suggestions.slice(0, 6)
  }

  getDaysOld(dateString: string): number {
    const taskDate = new Date(dateString)
    const currentDate = new Date()
    return Math.floor((currentDate.getTime() - taskDate.getTime()) / (1000 * 60 * 60 * 24))
  }

  getDaysUntilDeadline(deadlineString: string): number {
    const deadline = new Date(deadlineString)
    const currentDate = new Date()
    return Math.floor((deadline.getTime() - currentDate.getTime()) / (1000 * 60 * 60 * 24))
  }

  async optimizeWorkflow(tasks: Task[]) {
    const startTime = Date.now()

    // Calculate core metrics
    const totalTasks = tasks.length
    const completedTasks = tasks.filter(t => t.status === 'completed').length
    const averageScore = this.calculateAverageScore(tasks)
    const productivityIndex = this.calculateProductivityIndex(tasks)
    const timeToCompletion = this.calculateTimeToCompletion(tasks)

    // Identify issues and opportunities
    const bottlenecks = this.identifyBottlenecks(tasks)
    const recommendations = this.generateRecommendations(tasks)

    // Generate insights
    const categoryDistribution = this.getCategoryDistribution(tasks)
    const priorityDistribution = this.getPriorityDistribution(tasks)
    const completionTrends = this.generateCompletionTrends(tasks)
    const timeEstimation = this.analyzeTimeEstimation(tasks)

    // Generate automation suggestions
    const automationSuggestions = this.generateAutomationSuggestions(tasks)

    const processingTime = Date.now() - startTime

    return {
      id: `optimization_${Date.now()}`,
      tasks,
      optimization: {
        totalTasks,
        completedTasks,
        averageScore,
        productivityIndex,
        timeToCompletion,
        bottlenecks,
        recommendations
      },
      insights: {
        categoryDistribution,
        priorityDistribution,
        completionTrends,
        timeEstimation
      },
      automationSuggestions,
      timestamp: new Date().toISOString()
    }
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { type, tasks } = body

    if (type !== 'optimize') {
      return NextResponse.json({ error: 'Invalid request type' }, { status: 400 })
    }

    if (!tasks || !Array.isArray(tasks)) {
      return NextResponse.json({ error: 'Tasks array is required' }, { status: 400 })
    }

    const taskOptimizationAI = new TaskOptimizationAI()
    const optimization = await taskOptimizationAI.optimizeWorkflow(tasks)

    return NextResponse.json(optimization)
  } catch (error) {
    console.error('Task Optimization AI Error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Optimization failed' },
      { status: 500 }
    )
  }
}
