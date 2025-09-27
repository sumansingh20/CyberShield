"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Badge } from "@/src/ui/components/ui/badge"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/src/ui/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/src/ui/components/ui/dialog"
import { Label } from "@/src/ui/components/ui/label"
import { Switch } from "@/src/ui/components/ui/switch"
import { useAuth } from "@/src/auth/utils/AuthContext"
import { 
  Users,
  User as UserIcon,
  Activity,
  Shield,
  Settings, 
  Search,
  Edit,
  Trash2,
  UserCheck,
  UserX,
  Crown,
  TrendingUp,
  Eye
} from "lucide-react"
import { toast } from "@/src/ui/hooks/use-toast"

interface DashboardStats {
  totalUsers: number
  activeUsers: number
  totalActivities: number
  registrationsToday: number
}

interface User {
  _id: string
  username: string
  email: string
  firstName: string
  lastName: string
  role: 'user' | 'admin'
  isVerified: boolean
  lastLoginAt?: string
  activityCount: number
  createdAt: string
}

interface Activity {
  id: string
  user: {
    username: string
    email: string
    name: string
  } | null
  toolName: string
  action: string
  status: 'success' | 'error' | 'warning' | 'info'
  duration: number
  createdAt: string
}

export default function AdminDashboard() {
  const { user } = useAuth()
  const router = useRouter()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [users, setUsers] = useState<User[]>([])
  const [activities, setActivities] = useState<Activity[]>([])
  const [loading, setLoading] = useState(true)
  const [usersLoading, setUsersLoading] = useState(false)
  const [searchTerm, setSearchTerm] = useState("")
  const [roleFilter, setRoleFilter] = useState("")
  const [statusFilter, setStatusFilter] = useState("")
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [editDialogOpen, setEditDialogOpen] = useState(false)
  const [viewDialogOpen, setViewDialogOpen] = useState(false)

  // Check admin access
  useEffect(() => {
    if (!user || user.role !== 'admin') {
      router.push('/dashboard')
      return
    }
    fetchDashboardData()
  }, [user, router])

  const fetchDashboardData = async () => {
    try {
      const token = localStorage.getItem('accessToken')
      const response = await fetch('/api/admin/dashboard', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })

      if (response.ok) {
        const data = await response.json()
        setStats(data.data.overview)
        setActivities(data.data.recentActivities)
      } else {
        toast({
          title: "Error",
          description: "Failed to fetch dashboard data",
          variant: "destructive"
        })
      }
    } catch (error) {
      console.error('Dashboard fetch error:', error)
      toast({
        title: "Error",
        description: "Failed to load dashboard",
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }

  const fetchUsers = async () => {
    setUsersLoading(true)
    try {
      const token = localStorage.getItem('accessToken')
      const params = new URLSearchParams()
      if (searchTerm) params.append('search', searchTerm)
      if (roleFilter) params.append('role', roleFilter)
      if (statusFilter) params.append('status', statusFilter)

      const response = await fetch(`/api/admin/users?${params}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })

      if (response.ok) {
        const data = await response.json()
        setUsers(data.data.users)
      } else {
        toast({
          title: "Error",
          description: "Failed to fetch users",
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error('Users fetch error:', error)
      toast({
        title: "Error",
        description: "Failed to load users",
        variant: "destructive",
      })
    } finally {
      setUsersLoading(false)
    }
  }

  useEffect(() => {
    if (user?.role === 'admin') {
      fetchUsers()
    }
  }, [searchTerm, roleFilter, statusFilter, user])

  const updateUser = async (userId: string, updates: Partial<User>) => {
    try {
      const token = localStorage.getItem('accessToken')
      const response = await fetch('/api/admin/users', {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ userId, updates })
      })

      if (response.ok) {
        toast({
          title: "Success",
          description: "User updated successfully"
        })
        fetchUsers()
        setEditDialogOpen(false)
      } else {
        const error = await response.json()
        toast({
          title: "Error",
          description: error.error || 'Failed to update user',
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error('Update user error:', error)
      toast({
        title: "Error",
        description: "Failed to update user",
        variant: "destructive",
      })
    }
  }

  const deleteUser = async (userId: string) => {
    if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
      return
    }

    try {
      const token = localStorage.getItem('accessToken')
      const response = await fetch(`/api/admin/users?userId=${userId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })

      if (response.ok) {
        toast({
          title: "Success",
          description: "User deleted successfully",
        })
        fetchUsers()
      } else {
        const error = await response.json()
        toast({
          title: "Error",
          description: error.error || 'Failed to delete user',
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error('Delete user error:', error)
      toast({
        title: "Error",
        description: "Failed to delete user",
        variant: "destructive",
      })
    }
  }

  const getStatusBadge = (user: User) => {
    if (!user.isVerified) {
      return <Badge variant="destructive">Unverified</Badge>
    }
    if (user.lastLoginAt && new Date(user.lastLoginAt) > new Date(Date.now() - 24 * 60 * 60 * 1000)) {
      return <Badge variant="default">Active</Badge>
    }
    return <Badge variant="secondary">Inactive</Badge>
  }

  const getActivityStatusBadge = (status: string) => {
    const variants = {
      success: 'default',
      error: 'destructive',
      warning: 'secondary',
      info: 'outline'
    } as const

    return <Badge variant={variants[status as keyof typeof variants] || 'outline'}>{status}</Badge>
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary"></div>
      </div>
    )
  }

  return (
    <div className="container mx-auto p-6 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Admin Dashboard</h1>
          <p className="text-muted-foreground">
            Manage users, monitor activity, and configure system settings
          </p>
        </div>
        <Badge variant="outline" className="flex items-center gap-2">
          <Crown className="h-4 w-4" />
          Administrator
        </Badge>
      </div>

      {/* Stats Overview */}
      {stats && (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Users</CardTitle>
              <Users className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.totalUsers}</div>
              <p className="text-xs text-muted-foreground">
                {stats.registrationsToday} registered today
              </p>
            </CardContent>
          </Card>
          
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Active Users</CardTitle>
              <UserCheck className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.activeUsers}</div>
              <p className="text-xs text-muted-foreground">
                Last 24 hours
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Activities</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.totalActivities}</div>
              <p className="text-xs text-muted-foreground">
                All time
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">System Status</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">Online</div>
              <p className="text-xs text-muted-foreground">
                All systems operational
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        {/* User Management */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>User Management</CardTitle>
                <CardDescription>
                  Manage user accounts and permissions
                </CardDescription>
              </div>
              <Button onClick={fetchUsers} size="sm">
                Refresh
              </Button>
            </div>
            
            <div className="flex gap-4 mt-4">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search users..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
              <Select value={roleFilter} onValueChange={setRoleFilter}>
                <SelectTrigger className="w-32">
                  <SelectValue placeholder="Role" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="">All roles</SelectItem>
                  <SelectItem value="user">User</SelectItem>
                  <SelectItem value="admin">Admin</SelectItem>
                </SelectContent>
              </Select>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-32">
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="">All status</SelectItem>
                  <SelectItem value="active">Active</SelectItem>
                  <SelectItem value="inactive">Inactive</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Activities</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {usersLoading ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8">
                      Loading users...
                    </TableCell>
                  </TableRow>
                ) : users.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8">
                      No users found
                    </TableCell>
                  </TableRow>
                ) : (
                  users.map((user) => (
                    <TableRow key={user._id}>
                      <TableCell>
                        <div>
                          <div className="font-medium">{user.firstName} {user.lastName}</div>
                          <div className="text-sm text-muted-foreground">{user.email}</div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={user.role === 'admin' ? 'default' : 'secondary'}>
                          {user.role}
                        </Badge>
                      </TableCell>
                      <TableCell>{getStatusBadge(user)}</TableCell>
                      <TableCell>{user.activityCount}</TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setSelectedUser(user)
                              setViewDialogOpen(true)
                            }}
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setSelectedUser(user)
                              setEditDialogOpen(true)
                            }}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => deleteUser(user._id)}
                            className="text-destructive hover:text-destructive"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Recent Activities */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Activities</CardTitle>
            <CardDescription>Latest user actions</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {activities.map((activity) => (
                <div key={activity.id} className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">
                      {activity.user?.name || 'Unknown User'}
                    </p>
                    <p className="text-sm text-muted-foreground truncate">
                      {activity.action}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {new Date(activity.createdAt).toLocaleString()}
                    </p>
                  </div>
                  <div className="ml-4">
                    {getActivityStatusBadge(activity.status)}
                  </div>
                </div>
              ))}
              {activities.length === 0 && (
                <p className="text-sm text-muted-foreground text-center py-4">
                  No recent activities
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Edit User Dialog */}
      <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit User</DialogTitle>
          </DialogHeader>
          {selectedUser && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="firstName">First Name</Label>
                  <Input
                    id="firstName"
                    defaultValue={selectedUser.firstName}
                    onChange={(e) => 
                      setSelectedUser({ ...selectedUser, firstName: e.target.value })
                    }
                  />
                </div>
                <div>
                  <Label htmlFor="lastName">Last Name</Label>
                  <Input
                    id="lastName"
                    defaultValue={selectedUser.lastName}
                    onChange={(e) => 
                      setSelectedUser({ ...selectedUser, lastName: e.target.value })
                    }
                  />
                </div>
              </div>
              
              <div>
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  defaultValue={selectedUser.email}
                  onChange={(e) => 
                    setSelectedUser({ ...selectedUser, email: e.target.value })
                  }
                />
              </div>

              <div>
                <Label htmlFor="role">Role</Label>
                <Select 
                  value={selectedUser.role}
                  onValueChange={(value: 'user' | 'admin') =>
                    setSelectedUser({ ...selectedUser, role: value })
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="user">User</SelectItem>
                    <SelectItem value="admin">Admin</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex items-center space-x-2">
                <Switch
                  id="verified"
                  checked={selectedUser.isVerified}
                  onCheckedChange={(checked) =>
                    setSelectedUser({ ...selectedUser, isVerified: checked })
                  }
                />
                <Label htmlFor="verified">Email Verified</Label>
              </div>

              <div className="flex justify-end space-x-2">
                <Button
                  variant="outline"
                  onClick={() => setEditDialogOpen(false)}
                >
                  Cancel
                </Button>
                <Button
                  onClick={() => {
                    updateUser(selectedUser._id, {
                      firstName: selectedUser.firstName,
                      lastName: selectedUser.lastName,
                      email: selectedUser.email,
                      role: selectedUser.role,
                      isVerified: selectedUser.isVerified
                    })
                  }}
                >
                  Save Changes
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* View User Details Dialog */}
      <Dialog open={viewDialogOpen} onOpenChange={setViewDialogOpen}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Eye className="h-5 w-5" />
              User Profile Details
            </DialogTitle>
          </DialogHeader>
          {selectedUser && (
            <div className="space-y-6">
              {/* User Basic Info */}
              <div className="grid md:grid-cols-2 gap-6">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg flex items-center gap-2">
                      <UserIcon className="h-4 w-4" />
                      Basic Information
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label className="text-sm font-medium text-muted-foreground">Full Name</Label>
                      <p className="font-medium">{selectedUser.firstName} {selectedUser.lastName}</p>
                    </div>
                    <div className="space-y-2">
                      <Label className="text-sm font-medium text-muted-foreground">Username</Label>
                      <p className="font-medium">{selectedUser.username}</p>
                    </div>
                    <div className="space-y-2">
                      <Label className="text-sm font-medium text-muted-foreground">Email</Label>
                      <p className="font-medium">{selectedUser.email}</p>
                    </div>
                    <div className="space-y-2">
                      <Label className="text-sm font-medium text-muted-foreground">Role</Label>
                      <Badge variant={selectedUser.role === 'admin' ? 'default' : 'secondary'}>
                        {selectedUser.role}
                      </Badge>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg flex items-center gap-2">
                      <Shield className="h-4 w-4" />
                      Account Status
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label className="text-sm font-medium text-muted-foreground">Verification Status</Label>
                      {getStatusBadge(selectedUser)}
                    </div>
                    <div className="space-y-2">
                      <Label className="text-sm font-medium text-muted-foreground">Account Created</Label>
                      <p className="font-medium">{new Date(selectedUser.createdAt).toLocaleDateString()}</p>
                    </div>
                    <div className="space-y-2">
                      <Label className="text-sm font-medium text-muted-foreground">Last Login</Label>
                      <p className="font-medium">
                        {selectedUser.lastLoginAt 
                          ? new Date(selectedUser.lastLoginAt).toLocaleString()
                          : 'Never'
                        }
                      </p>
                    </div>
                    <div className="space-y-2">
                      <Label className="text-sm font-medium text-muted-foreground">Total Activities</Label>
                      <p className="font-medium">{selectedUser.activityCount}</p>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Activity Summary */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Activity className="h-4 w-4" />
                    Activity Summary
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid md:grid-cols-3 gap-4">
                    <div className="text-center p-4 rounded-lg bg-blue-50 dark:bg-blue-950/20">
                      <div className="text-2xl font-bold text-blue-600">{selectedUser.activityCount}</div>
                      <div className="text-sm text-muted-foreground">Total Actions</div>
                    </div>
                    <div className="text-center p-4 rounded-lg bg-green-50 dark:bg-green-950/20">
                      <div className="text-2xl font-bold text-green-600">
                        {selectedUser.lastLoginAt && new Date(selectedUser.lastLoginAt) > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) ? 'Active' : 'Inactive'}
                      </div>
                      <div className="text-sm text-muted-foreground">Status (7 days)</div>
                    </div>
                    <div className="text-center p-4 rounded-lg bg-purple-50 dark:bg-purple-950/20">
                      <div className="text-2xl font-bold text-purple-600">
                        {Math.floor((new Date().getTime() - new Date(selectedUser.createdAt).getTime()) / (1000 * 3600 * 24))}
                      </div>
                      <div className="text-sm text-muted-foreground">Days Active</div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Quick Actions */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Quick Actions</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setViewDialogOpen(false)
                        setEditDialogOpen(true)
                      }}
                    >
                      <Edit className="h-4 w-4 mr-2" />
                      Edit User
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        updateUser(selectedUser._id, { 
                          isVerified: !selectedUser.isVerified 
                        })
                        setSelectedUser({
                          ...selectedUser,
                          isVerified: !selectedUser.isVerified
                        })
                      }}
                    >
                      {selectedUser.isVerified ? <UserX className="h-4 w-4 mr-2" /> : <UserCheck className="h-4 w-4 mr-2" />}
                      {selectedUser.isVerified ? 'Unverify' : 'Verify'} User
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        const newRole = selectedUser.role === 'admin' ? 'user' : 'admin'
                        updateUser(selectedUser._id, { role: newRole })
                        setSelectedUser({
                          ...selectedUser,
                          role: newRole
                        })
                      }}
                    >
                      <Crown className="h-4 w-4 mr-2" />
                      {selectedUser.role === 'admin' ? 'Remove Admin' : 'Make Admin'}
                    </Button>
                  </div>
                </CardContent>
              </Card>

              <div className="flex justify-end">
                <Button
                  variant="outline"
                  onClick={() => setViewDialogOpen(false)}
                >
                  Close
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
