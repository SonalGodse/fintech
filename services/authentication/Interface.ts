export interface CreateUser {
    firstName: string;
    lastName: string;
    phone?: string;
    email: string;
    type?: string;
    isDeleted?: boolean;
    createdTs?: number;
    updatedTs?: number;
    accountId?: number;
    userRoles?: UserRole[];
  }
  
  export interface CreateAccountDto {
    username: string;
    password: string;
    active?: boolean;
    wrongAttempt?: number;
    wrongOtpAttempt?: number;
    lastLogin?: number;
    status?: number;
    locked?: boolean;
    isDeleted?: boolean;
    mPin?: number;
    deviceType?: string;
    deviceId?: number;
  }
  
  export interface User {
    id: number;
    firstName: string;
    lastName: string;
    phone?: string;
    email: string;
    type?: string;
    isDeleted: boolean;
    createdTs: number;
    updatedTs?: number;
    accountId?: number;
    account?: Account;
    userRoles?: UserRole[];
  }
  
  export interface UserRole {
    id: number;
    userId: number;
    roleId: number;
    startDate: number;
    endDate?: number;
    createdTs: number;
    updatedTs?: number;
    user?: User;
    role?: Role;
  }
  
  export interface Permission {
    id: number;
    permissionName: string;
    description?: string;
    rolePermissions: RolePermission[];
  }
  
  export interface RolePermission {
    id: number;
    roleId: number;
    permissionId: number;
    createdTs: number;
    updatedTs?: number;
    role: Role;
    permission: Permission;
  }
  
  export interface Role {
    id: number;
    name: string;
    code: string;
    userRoles: UserRole[];
    rolePermissions: RolePermission[];
  }
  
  export interface Enrollment {
    id: number;
    guid: string;
    startDate: number;
    expiryDate: number;
    type: string;
    status: string;
    createdTs: number;
    updatedTs?: number;
    account: Account;
  }
  
  export interface Account {
    id: number;
    username: string;
    password: string;
    active: boolean;
    wrongAttempt: number;
    wrongOtpAttempt: number;
    lastLogin?: number;
    status?: number;
    locked: boolean;
    isDeleted: boolean;
    createdTs: number;
    updatedTs?: number;
    users: User[];
    enrollments: Enrollment[];
  }
  
  export interface UserResponse {
    /** Indicates if the request was successful */
    success: boolean;
    /** Error message if the request was not successful */
    message?: string;
    /** Category data */
    result?: User | User[];
  }
  