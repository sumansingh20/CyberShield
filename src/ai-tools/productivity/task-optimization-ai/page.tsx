'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Button } from '@/src/ui/components/ui/button'
import { Label } from '@/src/ui/components/ui/label'
import { Input } from '@/src/ui/components/ui/input'
import { Textarea } from '@/src/ui/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/src/ui/components/ui/select'
import { Badge } from '@/src/ui/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/src/ui/components/ui/tabs'
import { Progress } from '@/src/ui/components/ui/progress'
import { Alert, AlertDescription } from '@/src/ui/components/ui/alert'
import { CheckCircle, Clock, TrendingUp, Target, Zap, Brain, AlertTriangle, Plus, Edit, Trash2, Play } from 'lucide-react'

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

interface WorkflowOptimization {
  id: string
  tasks: Task[]
  optimization: {
    totalTasks: number
    completedTasks: number
    averageScore: number
    productivityIndex: number
    timeToCompletion: number
    bottlenecks: Array<{
      task: string
      issue: string
      impact: 'low' | 'medium' | 'high'
      suggestion: string
    }>
    recommendations: Array<{
      type: 'priority' | 'workflow' | 'resource' | 'scheduling'
      title: string
      description: string
      impact: number
    }>
  }
  insights: {
    categoryDistribution: Array<{ category: string; count: number; percentage: number }>
    priorityDistribution: Array<{ priority: string; count: number; percentage: number }>
    completionTrends: Array<{ period: string; completed: number; productivity: number }>
    timeEstimation: {
      accuracy: number
      averageDeviation: number
      suggestions: string[]
    }
  }
  automationSuggestions: Array<{
    id: string
    title: string
    description: string
    automationType: 'recurring' | 'trigger-based' | 'schedule' | 'workflow'
    potentialSavings: number
    complexity: 'low' | 'medium' | 'high'
  }>
  timestamp: string
}

const TASK_CATEGORIES = [
  'Development',
  'Design',
  'Research',
  'Marketing',
  'Administration',
  'Communication',
  'Testing',
  'Documentation',
  'Planning',
  'Review'
]

const PRIORITY_LEVELS = [
  { value: 'low', label: 'Low', color: 'bg-green-100 text-green-800' },
  { value: 'medium', label: 'Medium', color: 'bg-yellow-100 text-yellow-800' },
  { value: 'high', label: 'High', color: 'bg-orange-100 text-orange-800' },
  { value: 'critical', label: 'Critical', color: 'bg-red-100 text-red-800' }
]

const STATUS_OPTIONS = [
  { value: 'todo', label: 'To Do', color: 'bg-gray-100 text-gray-800' },
  { value: 'in-progress', label: 'In Progress', color: 'bg-blue-100 text-blue-800' },
  { value: 'completed', label: 'Completed', color: 'bg-green-100 text-green-800' },
  { value: 'blocked', label: 'Blocked', color: 'bg-red-100 text-red-800' }
]

export default function TaskOptimizationPage() {
  const [tasks, setTasks] = useState<Task[]>([])
  const [optimization, setOptimization] = useState<WorkflowOptimization | null>(null)
  const [isOptimizing, setIsOptimizing] = useState(false)
  const [isAddingTask, setIsAddingTask] = useState(false)
  const [editingTask, setEditingTask] = useState<Task | null>(null)
  const [error, setError] = useState<string | null>(null)
  
  // New task form state
  const [newTask, setNewTask] = useState({
    title: '',
    description: '',
    priority: 'medium' as 'low' | 'medium' | 'high' | 'critical',
    category: '',
    estimatedHours: 1,
    deadline: '',
    tags: ''
  })

  useEffect(() => {
    // Load sample tasks on component mount
    loadSampleTasks()
  }, [])

  const loadSampleTasks = () => {
    const sampleTasks: Task[] = [
      {
        id: 'task_1',
        title: 'Implement user authentication system',
        description: 'Design and develop secure login/logout functionality with JWT tokens',
        priority: 'high',
        status: 'in-progress',
        category: 'Development',
        estimatedHours: 8,
        deadline: '2024-02-15',
        dependencies: [],
        tags: ['backend', 'security', 'api'],
        aiScore: 85,
        createdAt: new Date(Date.now() - 86400000).toISOString()
      },
      {
        id: 'task_2',
        title: 'Create landing page design mockups',
        description: 'Design responsive mockups for the main landing page including mobile views',
        priority: 'medium',
        status: 'todo',
        category: 'Design',
        estimatedHours: 4,
        deadline: '2024-02-10',
        dependencies: [],
        tags: ['ui', 'responsive', 'mockup'],
        aiScore: 72,
        createdAt: new Date(Date.now() - 172800000).toISOString()
      },
      {
        id: 'task_3',
        title: 'Write API documentation',
        description: 'Document all REST API endpoints with examples and authentication details',
        priority: 'medium',
        status: 'blocked',
        category: 'Documentation',
        estimatedHours: 6,
        dependencies: ['task_1'],
        tags: ['api', 'docs', 'rest'],
        aiScore: 68,
        createdAt: new Date(Date.now() - 259200000).toISOString()
      },
      {
        id: 'task_4',
        title: 'Set up CI/CD pipeline',
        description: 'Configure automated testing and deployment pipeline using GitHub Actions',
        priority: 'high',
        status: 'todo',
        category: 'Development',
        estimatedHours: 10,
        deadline: '2024-02-20',
        dependencies: [],
        tags: ['devops', 'automation', 'testing'],
        aiScore: 90,
        createdAt: new Date(Date.now() - 345600000).toISOString()
      },
      {
        id: 'task_5',
        title: 'Market research analysis',
        description: 'Analyze competitor features and pricing strategies',
        priority: 'low',
        status: 'completed',
        category: 'Research',
        estimatedHours: 12,
        dependencies: [],
        tags: ['market', 'competitors', 'analysis'],
        aiScore: 78,
        createdAt: new Date(Date.now() - 432000000).toISOString()
      }
    ]
    
    setTasks(sampleTasks)
  }

  const handleAddTask = () => {
    if (!newTask.title.trim()) {
      setError('Task title is required')
      return
    }

    const task: Task = {
      id: `task_${Date.now()}`,
      title: newTask.title.trim(),
      description: newTask.description.trim(),
      priority: newTask.priority,
      status: 'todo',
      category: newTask.category || 'General',
      estimatedHours: newTask.estimatedHours,
      deadline: newTask.deadline || undefined,
      dependencies: [],
      tags: newTask.tags.split(',').map(tag => tag.trim()).filter(tag => tag.length > 0),
      aiScore: Math.floor(Math.random() * 30) + 70, // 70-100
      createdAt: new Date().toISOString()
    }

    setTasks(prev => [...prev, task])
    setNewTask({
      title: '',
      description: '',
      priority: 'medium',
      category: '',
      estimatedHours: 1,
      deadline: '',
      tags: ''
    })
    setIsAddingTask(false)
    setError(null)
  }

  const handleEditTask = (taskId: string, updates: Partial<Task>) => {
    setTasks(prev => prev.map(task => 
      task.id === taskId ? { ...task, ...updates } : task
    ))
    setEditingTask(null)
  }

  const handleDeleteTask = (taskId: string) => {
    setTasks(prev => prev.filter(task => task.id !== taskId))
  }

  const handleOptimizeWorkflow = async () => {
    if (tasks.length === 0) {
      setError('Please add some tasks before optimizing')
      return
    }

    setIsOptimizing(true)
    setError(null)

    try {
      const response = await fetch('/api/tools/task-optimization-ai', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'optimize',
          tasks: tasks
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Optimization failed')
      }

      setOptimization(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Optimization failed')
    } finally {
      setIsOptimizing(false)
    }
  }

  const getPriorityColor = (priority: string): string => {
    const priorityData = PRIORITY_LEVELS.find(p => p.value === priority)
    return priorityData?.color || 'bg-gray-100 text-gray-800'
  }

  const getStatusColor = (status: string): string => {
    const statusData = STATUS_OPTIONS.find(s => s.value === status)
    return statusData?.color || 'bg-gray-100 text-gray-800'
  }

  const getImpactColor = (impact: string): string => {
    const colors = {
      low: 'bg-green-100 text-green-800',
      medium: 'bg-yellow-100 text-yellow-800',
      high: 'bg-red-100 text-red-800'
    }
    return colors[impact as keyof typeof colors] || 'bg-gray-100 text-gray-800'
  }

  const formatDate = (dateString: string): string => {
    return new Date(dateString).toLocaleDateString()
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl">
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-4 bg-gradient-to-r from-green-600 to-blue-600 bg-clip-text text-transparent">
          Task Optimization System
        </h1>
        <p className="text-lg text-muted-foreground">
          AI-powered task management with priority scoring, workflow automation, and productivity insights
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Task Management Panel */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Target className="w-5 h-5" />
                    Task Management
                  </CardTitle>
                  <CardDescription>
                    Manage and optimize your workflow
                  </CardDescription>
                </div>
                <Button 
                  size="sm" 
                  onClick={() => setIsAddingTask(true)}
                  disabled={isOptimizing}
                >
                  <Plus className="w-4 h-4 mr-1" />
                  Add
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Task Statistics */}
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center p-3 bg-gray-50 rounded-lg">
                  <div className="text-2xl font-bold">{tasks.length}</div>
                  <div className="text-xs text-muted-foreground">Total Tasks</div>
                </div>
                <div className="text-center p-3 bg-green-50 rounded-lg">
                  <div className="text-2xl font-bold text-green-600">
                    {tasks.filter(t => t.status === 'completed').length}
                  </div>
                  <div className="text-xs text-muted-foreground">Completed</div>
                </div>
              </div>

              {/* Add Task Form */}
              {isAddingTask && (
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm">Add New Task</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="space-y-2">
                      <Label htmlFor="taskTitle">Title *</Label>
                      <Input
                        id="taskTitle"
                        value={newTask.title}
                        onChange={(e) => setNewTask(prev => ({ ...prev, title: e.target.value }))}
                        placeholder="Enter task title..."
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="taskDescription">Description</Label>
                      <Textarea
                        id="taskDescription"
                        value={newTask.description}
                        onChange={(e) => setNewTask(prev => ({ ...prev, description: e.target.value }))}
                        placeholder="Describe the task..."
                        rows={2}
                      />
                    </div>

                    <div className="grid grid-cols-2 gap-2">
                      <div className="space-y-2">
                        <Label htmlFor="taskPriority">Priority</Label>
                        <Select 
                          value={newTask.priority} 
                          onValueChange={(value: any) => setNewTask(prev => ({ ...prev, priority: value }))}
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {PRIORITY_LEVELS.map((priority) => (
                              <SelectItem key={priority.value} value={priority.value}>
                                {priority.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>

                      <div className="space-y-2">
                        <Label htmlFor="taskCategory">Category</Label>
                        <Select 
                          value={newTask.category} 
                          onValueChange={(value) => setNewTask(prev => ({ ...prev, category: value }))}
                        >
                          <SelectTrigger>
                            <SelectValue placeholder="Select..." />
                          </SelectTrigger>
                          <SelectContent>
                            {TASK_CATEGORIES.map((category) => (
                              <SelectItem key={category} value={category}>
                                {category}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-2">
                      <div className="space-y-2">
                        <Label htmlFor="estimatedHours">Hours</Label>
                        <Input
                          id="estimatedHours"
                          type="number"
                          min="0.5"
                          step="0.5"
                          value={newTask.estimatedHours}
                          onChange={(e) => setNewTask(prev => ({ ...prev, estimatedHours: parseFloat(e.target.value) || 1 }))}
                        />
                      </div>

                      <div className="space-y-2">
                        <Label htmlFor="deadline">Deadline</Label>
                        <Input
                          id="deadline"
                          type="date"
                          value={newTask.deadline}
                          onChange={(e) => setNewTask(prev => ({ ...prev, deadline: e.target.value }))}
                        />
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="tags">Tags (comma-separated)</Label>
                      <Input
                        id="tags"
                        value={newTask.tags}
                        onChange={(e) => setNewTask(prev => ({ ...prev, tags: e.target.value }))}
                        placeholder="api, frontend, urgent..."
                      />
                    </div>

                    <div className="flex gap-2">
                      <Button onClick={handleAddTask} size="sm" className="flex-1">
                        Add Task
                      </Button>
                      <Button 
                        onClick={() => setIsAddingTask(false)} 
                        variant="outline" 
                        size="sm"
                      >
                        Cancel
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Task List */}
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {tasks.map((task) => (
                  <Card key={task.id} className="p-3">
                    <div className="space-y-2">
                      <div className="flex items-start justify-between">
                        <h4 className="font-medium text-sm leading-tight">{task.title}</h4>
                        <div className="flex gap-1">
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-6 w-6 p-0"
                            onClick={() => setEditingTask(task)}
                          >
                            <Edit className="w-3 h-3" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-6 w-6 p-0 text-red-500"
                            onClick={() => handleDeleteTask(task.id)}
                          >
                            <Trash2 className="w-3 h-3" />
                          </Button>
                        </div>
                      </div>
                      
                      <div className="flex flex-wrap gap-1">
                        <Badge className={getPriorityColor(task.priority)} variant="secondary">
                          {task.priority}
                        </Badge>
                        <Badge className={getStatusColor(task.status)} variant="secondary">
                          {task.status}
                        </Badge>
                        <Badge variant="outline" className="text-xs">
                          AI: {task.aiScore}%
                        </Badge>
                      </div>
                      
                      {task.deadline && (
                        <div className="flex items-center gap-1 text-xs text-muted-foreground">
                          <Clock className="w-3 h-3" />
                          Due: {formatDate(task.deadline)}
                        </div>
                      )}
                    </div>
                  </Card>
                ))}
              </div>

              {error && (
                <Alert variant="destructive">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <Button 
                onClick={handleOptimizeWorkflow} 
                disabled={isOptimizing || tasks.length === 0}
                className="w-full"
              >
                <Brain className="w-4 h-4 mr-2" />
                {isOptimizing ? 'Optimizing...' : 'Optimize Workflow'}
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Optimization Results */}
        <div className="lg:col-span-2">
          {optimization && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <TrendingUp className="w-5 h-5" />
                  Workflow Optimization Results
                </CardTitle>
                <CardDescription>
                  AI-powered insights and recommendations for productivity improvement
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="overview" className="w-full">
                  <TabsList className="grid w-full grid-cols-4">
                    <TabsTrigger value="overview">Overview</TabsTrigger>
                    <TabsTrigger value="insights">Insights</TabsTrigger>
                    <TabsTrigger value="bottlenecks">Issues</TabsTrigger>
                    <TabsTrigger value="automation">Automation</TabsTrigger>
                  </TabsList>

                  <TabsContent value="overview" className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Productivity Index</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="flex items-center gap-2">
                            <span className="text-2xl font-bold">{optimization.optimization.productivityIndex}%</span>
                            <TrendingUp className="w-4 h-4 text-green-500" />
                          </div>
                          <Progress value={optimization.optimization.productivityIndex} className="mt-2" />
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Average AI Score</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-2xl font-bold">{optimization.optimization.averageScore}%</div>
                          <p className="text-xs text-muted-foreground">Task complexity</p>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Completion Rate</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-2xl font-bold">
                            {Math.round((optimization.optimization.completedTasks / optimization.optimization.totalTasks) * 100)}%
                          </div>
                          <p className="text-xs text-muted-foreground">
                            {optimization.optimization.completedTasks} of {optimization.optimization.totalTasks}
                          </p>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm">Est. Completion</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-2xl font-bold">{optimization.optimization.timeToCompletion}h</div>
                          <p className="text-xs text-muted-foreground">Remaining work</p>
                        </CardContent>
                      </Card>
                    </div>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Top Recommendations</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          {optimization.optimization.recommendations.slice(0, 5).map((rec, index) => (
                            <div key={index} className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
                              <div className="flex-shrink-0">
                                <Badge variant="outline" className="text-xs">
                                  {rec.type}
                                </Badge>
                              </div>
                              <div className="flex-1">
                                <h4 className="font-medium text-sm">{rec.title}</h4>
                                <p className="text-xs text-muted-foreground mt-1">{rec.description}</p>
                                <div className="flex items-center gap-1 mt-2">
                                  <span className="text-xs font-medium">Impact:</span>
                                  <Progress value={rec.impact} className="flex-1 h-2" />
                                  <span className="text-xs">{rec.impact}%</span>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="insights" className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm">Category Distribution</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-3">
                            {optimization.insights.categoryDistribution.map((cat, index) => (
                              <div key={index}>
                                <div className="flex items-center justify-between text-sm">
                                  <span>{cat.category}</span>
                                  <span>{cat.count} ({cat.percentage}%)</span>
                                </div>
                                <Progress value={cat.percentage} className="h-2" />
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm">Priority Distribution</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-3">
                            {optimization.insights.priorityDistribution.map((pri, index) => (
                              <div key={index}>
                                <div className="flex items-center justify-between text-sm">
                                  <span className="capitalize">{pri.priority}</span>
                                  <span>{pri.count} ({pri.percentage}%)</span>
                                </div>
                                <Progress value={pri.percentage} className="h-2" />
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    </div>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Time Estimation Analysis</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <div className="text-2xl font-bold">{optimization.insights.timeEstimation.accuracy}%</div>
                            <p className="text-sm text-muted-foreground">Estimation Accuracy</p>
                          </div>
                          <div>
                            <div className="text-2xl font-bold">{optimization.insights.timeEstimation.averageDeviation}h</div>
                            <p className="text-sm text-muted-foreground">Average Deviation</p>
                          </div>
                        </div>
                        <div className="mt-4 space-y-2">
                          <Label className="text-xs font-medium">Suggestions:</Label>
                          {optimization.insights.timeEstimation.suggestions.map((suggestion, index) => (
                            <div key={index} className="flex items-start gap-2">
                              <div className="w-2 h-2 bg-blue-500 rounded-full mt-2 flex-shrink-0" />
                              <span className="text-sm">{suggestion}</span>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="bottlenecks" className="space-y-4">
                    <h3 className="font-semibold">Identified Bottlenecks & Issues</h3>
                    
                    <div className="space-y-3">
                      {optimization.optimization.bottlenecks.map((bottleneck, index) => (
                        <Card key={index}>
                          <CardContent className="pt-4">
                            <div className="flex items-start justify-between">
                              <div className="flex-1">
                                <div className="flex items-center gap-2 mb-2">
                                  <h4 className="font-medium">{bottleneck.task}</h4>
                                  <Badge className={getImpactColor(bottleneck.impact)}>
                                    {bottleneck.impact} impact
                                  </Badge>
                                </div>
                                <p className="text-sm text-muted-foreground mb-2">{bottleneck.issue}</p>
                                <div className="p-2 bg-blue-50 rounded border-l-2 border-blue-200">
                                  <p className="text-sm font-medium text-blue-800">Suggestion:</p>
                                  <p className="text-sm text-blue-700">{bottleneck.suggestion}</p>
                                </div>
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </TabsContent>

                  <TabsContent value="automation" className="space-y-4">
                    <div className="flex items-center gap-2 mb-4">
                      <Zap className="w-5 h-5" />
                      <h3 className="font-semibold">Automation Opportunities</h3>
                    </div>
                    
                    <div className="space-y-3">
                      {optimization.automationSuggestions.map((suggestion) => (
                        <Card key={suggestion.id}>
                          <CardContent className="pt-4">
                            <div className="flex items-start justify-between">
                              <div className="flex-1">
                                <div className="flex items-center gap-2 mb-2">
                                  <h4 className="font-medium">{suggestion.title}</h4>
                                  <Badge variant="outline" className="text-xs">
                                    {suggestion.automationType}
                                  </Badge>
                                  <Badge className={suggestion.complexity === 'low' ? 'bg-green-100 text-green-800' : 
                                    suggestion.complexity === 'medium' ? 'bg-yellow-100 text-yellow-800' : 
                                    'bg-red-100 text-red-800'}>
                                    {suggestion.complexity} complexity
                                  </Badge>
                                </div>
                                <p className="text-sm text-muted-foreground mb-2">{suggestion.description}</p>
                                <div className="flex items-center gap-2">
                                  <Clock className="w-4 h-4 text-green-500" />
                                  <span className="text-sm font-medium text-green-600">
                                    Potential savings: {suggestion.potentialSavings}h/week
                                  </span>
                                </div>
                              </div>
                              <Button size="sm" variant="outline">
                                <Play className="w-4 h-4 mr-1" />
                                Setup
                              </Button>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          )}

          {!optimization && (
            <Card>
              <CardContent className="py-12 text-center">
                <Target className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">No Optimization Available</h3>
                <p className="text-muted-foreground">
                  Add tasks and click "Optimize Workflow" to get AI-powered productivity insights and recommendations.
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
