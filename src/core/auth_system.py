"""
Authentication and User Management System for Cybersecurity Reporting Agent.
Supports multi-organization access control with role-based permissions.
"""

import os
import sqlite3
import bcrypt
import streamlit as st
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import json
import hashlib
from dataclasses import dataclass
from enum import Enum

class UserRole(Enum):
    """User role enumeration."""
    ADMIN = "admin"
    PARTNER = "partner"
    REPORTER = "reporter"
    READER = "reader"

@dataclass
class User:
    """User data structure."""
    id: int
    username: str
    email: str
    organization_id: int
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    password_hash: str

@dataclass
class Organization:
    """Organization data structure."""
    id: int
    name: str
    domain: str
    industry: str
    country: str
    compliance_framework: str
    organization_type: str  # 'platform', 'partner', 'client'
    parent_organization_id: Optional[int]
    created_at: datetime
    is_active: bool
    logo_url: Optional[str] = None  # URL to organization logo

class AuthenticationSystem:
    """Multi-organization authentication system with role-based access control."""
    
    def __init__(self, db_path: str = "cybersecurity_users.db"):
        """Initialize the authentication system."""
        self.db_path = db_path
        self.init_database()
        self.create_default_data()
    
    def init_database(self):
        """Initialize the SQLite database with required tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Organizations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                domain TEXT NOT NULL UNIQUE,
                industry TEXT,
                country TEXT,
                compliance_framework TEXT,
                organization_type TEXT NOT NULL DEFAULT 'client',
                parent_organization_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                logo_url TEXT,
                FOREIGN KEY (parent_organization_id) REFERENCES organizations (id)
            )
        ''')
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                organization_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                FOREIGN KEY (organization_id) REFERENCES organizations (id)
            )
        ''')
        
        # User sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Analysis reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                organization_id INTEGER NOT NULL,
                target_type TEXT NOT NULL,
                target_value TEXT NOT NULL,
                analysis_data TEXT NOT NULL,
                report_type TEXT NOT NULL,
                compliance_framework TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (organization_id) REFERENCES organizations (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_default_data(self):
        """Create default organizations and admin users if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if Cohesive platform organization exists
        cursor.execute("SELECT id FROM organizations WHERE name = 'Cohesive'")
        if not cursor.fetchone():
            cursor.execute('''
                INSERT INTO organizations (name, domain, industry, country, compliance_framework, organization_type, parent_organization_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', ('Cohesive', 'cohesive.com', 'Technology', 'Global', 'NIS2', 'platform', None))
            cohesive_org_id = cursor.lastrowid
            
            # Create default admin user
            admin_password = "admin123"  # Change in production
            password_hash = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
            
            cursor.execute('''
                INSERT INTO users (username, email, organization_id, role, password_hash)
                VALUES (?, ?, ?, ?, ?)
            ''', ('admin', 'admin@cohesive.com', cohesive_org_id, UserRole.ADMIN.value, password_hash.decode('utf-8')))
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify a password against its hash."""
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    
    def create_user(self, username: str, email: str, password: str, 
                    organization_id: int, role: UserRole) -> bool:
        """Create a new user."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            password_hash = self.hash_password(password)
            
            cursor.execute('''
                INSERT INTO users (username, email, organization_id, role, password_hash)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, email, organization_id, role.value, password_hash))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error creating user: {e}")
            return False
    
    def create_organization(self, name: str, domain: str, industry: str = "Technology", 
                           country: str = "Global", compliance_framework: str = "NIS2",
                           organization_type: str = "client", parent_organization_id: int = None) -> int:
        """Create a new organization and return its ID."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if organization with same name or domain already exists
            cursor.execute("SELECT id FROM organizations WHERE name = ? OR domain = ?", (name, domain))
            existing = cursor.fetchone()
            if existing:
                print(f"Organization with name '{name}' or domain '{domain}' already exists")
                conn.close()
                return -1
            
            # Auto-fetch organization logo
            logo_url = self.auto_fetch_organization_logo(name)
            
            cursor.execute('''
                INSERT INTO organizations (name, domain, industry, country, compliance_framework, organization_type, parent_organization_id, logo_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (name, domain, industry, country, compliance_framework, organization_type, parent_organization_id, logo_url))
            
            org_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            if logo_url:
                print(f"Organization '{name}' created successfully with logo: {logo_url}")
            else:
                print(f"Organization '{name}' created successfully (no logo found)")
            
            return org_id
        except Exception as e:
            print(f"Error creating organization: {e}")
            return -1
    
    def update_organization(self, organization_id: int, name: str, domain: str, industry: str,
                           country: str, compliance_framework: str, is_active: bool,
                           parent_organization_id: int = None) -> bool:
        """
        Update an organization's information.
        
        Args:
            organization_id: ID of the organization to update
            name: New organization name
            domain: New domain
            industry: New industry
            country: New country
            compliance_framework: New compliance framework
            is_active: Whether the organization is active
            parent_organization_id: New parent organization ID (None for direct to Cohesive)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if organization exists
            cursor.execute("SELECT id FROM organizations WHERE id = ?", (organization_id,))
            if not cursor.fetchone():
                conn.close()
                return False
            
            # Check if new name/domain conflicts with other organizations
            cursor.execute("""
                SELECT id FROM organizations 
                WHERE (name = ? OR domain = ?) AND id != ?
            """, (name, domain, organization_id))
            
            if cursor.fetchone():
                print(f"Organization with name '{name}' or domain '{domain}' already exists")
                conn.close()
                return False
            
            # Update organization
            cursor.execute('''
                UPDATE organizations 
                SET name = ?, domain = ?, industry = ?, country = ?, 
                    compliance_framework = ?, is_active = ?, parent_organization_id = ?
                WHERE id = ?
            ''', (name, domain, industry, country, compliance_framework, 
                  is_active, parent_organization_id, organization_id))
            
            conn.commit()
            conn.close()
            
            print(f"Organization '{name}' updated successfully")
            return True
            
        except Exception as e:
            print(f"Error updating organization: {e}")
            return False
    
    def delete_organization(self, organization_id: int, force_delete: bool = False) -> bool:
        """
        Delete an organization and all associated data.
        
        Args:
            organization_id: ID of the organization to delete
            force_delete: If True, delete even if there are active users
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if organization exists
            cursor.execute("SELECT name, organization_type FROM organizations WHERE id = ?", (organization_id,))
            org_data = cursor.fetchone()
            if not org_data:
                conn.close()
                return False
            
            org_name, org_type = org_data
            
            # Check if this is the main Cohesive platform organization
            if org_name == "Cohesive" and org_type == "platform":
                print("Cannot delete the main Cohesive platform organization")
                conn.close()
                return False
            
            # Check for active users in the organization
            cursor.execute("SELECT COUNT(*) FROM users WHERE organization_id = ? AND is_active = 1", (organization_id,))
            active_users = cursor.fetchone()[0]
            
            if active_users > 0 and not force_delete:
                print(f"Organization '{org_name}' has {active_users} active users. Use force_delete=True to proceed.")
                conn.close()
                return False
            
            # Check for child organizations
            cursor.execute("SELECT COUNT(*) FROM organizations WHERE parent_organization_id = ? AND is_active = 1", (organization_id,))
            child_orgs = cursor.fetchone()[0]
            
            if child_orgs > 0 and not force_delete:
                print(f"Organization '{org_name}' has {child_orgs} child organizations. Use force_delete=True to proceed.")
                conn.close()
                return False
            
            # Begin transaction
            cursor.execute("BEGIN TRANSACTION")
            
            try:
                # Delete all users in the organization
                cursor.execute("DELETE FROM users WHERE organization_id = ?", (organization_id,))
                
                # Delete all user sessions for users in the organization
                cursor.execute("""
                    DELETE FROM user_sessions 
                    WHERE user_id IN (SELECT id FROM users WHERE organization_id = ?)
                """, (organization_id,))
                
                # Delete all analysis reports for the organization
                cursor.execute("DELETE FROM analysis_reports WHERE organization_id = ?", (organization_id,))
                
                # Update child organizations to remove parent reference
                cursor.execute("""
                    UPDATE organizations 
                    SET parent_organization_id = NULL 
                    WHERE parent_organization_id = ?
                """, (organization_id,))
                
                # Finally, delete the organization
                cursor.execute("DELETE FROM organizations WHERE id = ?", (organization_id,))
                
                # Commit transaction
                cursor.execute("COMMIT")
                conn.close()
                
                print(f"Organization '{org_name}' deleted successfully")
                return True
                
            except Exception as e:
                # Rollback on error
                cursor.execute("ROLLBACK")
                conn.close()
                print(f"Error during organization deletion, transaction rolled back: {e}")
                return False
                
        except Exception as e:
            print(f"Error deleting organization: {e}")
            return False
    
    def get_organization_statistics(self, organization_id: int) -> Dict[str, int]:
        """
        Get statistics about an organization for impact assessment.
        
        Args:
            organization_id: ID of the organization
            
        Returns:
            Dictionary with statistics
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            stats = {}
            
            # Count active users
            cursor.execute("SELECT COUNT(*) FROM users WHERE organization_id = ? AND is_active = 1", (organization_id,))
            stats['active_users'] = cursor.fetchone()[0]
            
            # Count total users
            cursor.execute("SELECT COUNT(*) FROM users WHERE organization_id = ?", (organization_id,))
            stats['total_users'] = cursor.fetchone()[0]
            
            # Count child organizations
            cursor.execute("SELECT COUNT(*) FROM organizations WHERE parent_organization_id = ? AND is_active = 1", (organization_id,))
            stats['child_organizations'] = cursor.fetchone()[0]
            
            # Count analysis reports
            cursor.execute("SELECT COUNT(*) FROM analysis_reports WHERE organization_id = ?", (organization_id,))
            stats['analysis_reports'] = cursor.fetchone()[0]
            
            conn.close()
            return stats
            
        except Exception as e:
            print(f"Error getting organization statistics: {e}")
            return {
                'active_users': 0,
                'total_users': 0,
                'child_organizations': 0,
                'analysis_reports': 0
            }
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate a user and return user object if successful."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT u.id, u.username, u.email, u.organization_id, u.role, 
                       u.is_active, u.created_at, u.last_login, u.password_hash
                FROM users u
                WHERE u.username = ? AND u.is_active = 1
            ''', (username,))
            
            user_data = cursor.fetchone()
            if user_data and self.verify_password(password, user_data[8]):
                # Update last login
                cursor.execute('''
                    UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
                ''', (user_data[0],))
                
                conn.commit()
                conn.close()
                
                return User(
                    id=user_data[0],
                    username=user_data[1],
                    email=user_data[2],
                    organization_id=user_data[3],
                    role=UserRole(user_data[4]),
                    is_active=user_data[5],
                    created_at=datetime.fromisoformat(user_data[6]),
                    last_login=datetime.fromisoformat(user_data[7]) if user_data[7] else None,
                    password_hash=user_data[8]
                )
            
            conn.close()
            return None
        except Exception as e:
            print(f"Error authenticating user: {e}")
            return None
    
    def get_user_organizations(self, user_id: int) -> List[Organization]:
        """Get organizations accessible to a user based on their role."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get user's role and organization
            cursor.execute('''
                SELECT role, organization_id FROM users WHERE id = ?
            ''', (user_id,))
            
            user_data = cursor.fetchone()
            if not user_data:
                return []
            
            user_role, user_org_id = user_data
            
            # Check if logo_url column exists
            cursor.execute("PRAGMA table_info(organizations)")
            columns = [column[1] for column in cursor.fetchall()]
            has_logo_column = 'logo_url' in columns
            
            # Admin users can access all organizations
            if user_role == 'admin':
                if has_logo_column:
                    cursor.execute('''
                        SELECT id, name, domain, industry, country, compliance_framework, 
                               organization_type, parent_organization_id, created_at, is_active, logo_url
                        FROM organizations 
                        WHERE is_active = 1
                        ORDER BY name
                    ''')
                else:
                    cursor.execute('''
                        SELECT id, name, domain, industry, country, compliance_framework, 
                               organization_type, parent_organization_id, created_at, is_active
                        FROM organizations 
                        WHERE is_active = 1
                        ORDER BY name
                    ''')
            else:
                # Non-admin users can only access their own organization
                if has_logo_column:
                    cursor.execute('''
                        SELECT id, name, domain, industry, country, compliance_framework, 
                               organization_type, parent_organization_id, created_at, is_active, logo_url
                        FROM organizations 
                        WHERE id = ? AND is_active = 1
                    ''', (user_org_id,))
                else:
                    cursor.execute('''
                        SELECT id, name, domain, industry, country, compliance_framework, 
                               organization_type, parent_organization_id, created_at, is_active
                        FROM organizations 
                        WHERE id = ? AND is_active = 1
                    ''', (user_org_id,))
            
            organizations = []
            for row in cursor.fetchall():
                org = Organization(
                    id=row[0],
                    name=row[1],
                    domain=row[2],
                    industry=row[3] or "Unknown",
                    country=row[4] or "Unknown",
                    compliance_framework=row[5] or "NIS2",
                    organization_type=row[6] or "client",
                    parent_organization_id=row[7],
                    created_at=datetime.fromisoformat(row[8]) if row[8] else datetime.now(),
                    is_active=bool(row[9]),
                    logo_url=row[10] if has_logo_column and len(row) > 10 else None
                )
                organizations.append(org)
            
            conn.close()
            return organizations
            
        except Exception as e:
            print(f"Error getting user organizations: {e}")
            return []
    
    def get_all_organizations(self) -> List[Organization]:
        """Get all organizations in the system (admin only)."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if logo_url column exists
            cursor.execute("PRAGMA table_info(organizations)")
            columns = [column[1] for column in cursor.fetchall()]
            has_logo_column = 'logo_url' in columns
            
            if has_logo_column:
                cursor.execute('''
                    SELECT id, name, domain, industry, country, compliance_framework, 
                           organization_type, parent_organization_id, created_at, is_active, logo_url
                    FROM organizations 
                    WHERE is_active = 1
                    ORDER BY name
                ''')
            else:
                # Fallback for databases without logo_url column
                cursor.execute('''
                    SELECT id, name, domain, industry, country, compliance_framework, 
                           organization_type, parent_organization_id, created_at, is_active
                    FROM organizations 
                    WHERE is_active = 1
                    ORDER BY name
                ''')
            
            organizations = []
            for row in cursor.fetchall():
                org = Organization(
                    id=row[0],
                    name=row[1],
                    domain=row[2],
                    industry=row[3] or "Unknown",
                    country=row[4] or "Unknown",
                    compliance_framework=row[5] or "NIS2",
                    organization_type=row[6] or "client",
                    parent_organization_id=row[7],
                    created_at=datetime.fromisoformat(row[8]) if row[8] else datetime.now(),
                    is_active=bool(row[9]),
                    logo_url=row[10] if has_logo_column and len(row) > 10 else None
                )
                organizations.append(org)
            
            conn.close()
            return organizations
            
        except Exception as e:
            print(f"Error getting all organizations: {e}")
            return []
    
    def can_access_organization(self, user_id: int, organization_id: int) -> bool:
        """Check if a user can access a specific organization."""
        user_orgs = self.get_user_organizations(user_id)
        return any(org.id == organization_id for org in user_orgs)
    
    def get_user_permissions(self, user_id: int) -> Dict[str, bool]:
        """Get user permissions based on role."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                return {}
            
            role = result[0]
            permissions = {
                'can_create_users': role in ['admin'],
                'can_delete_users': role in ['admin'],
                'can_manage_organizations': role in ['admin'],
                'can_switch_organizations': role in ['admin', 'partner'],
                'can_view_all_incidents': role in ['admin', 'partner'],
                'can_manage_incidents': role in ['admin', 'partner', 'reporter'],
                'can_view_reports': role in ['admin', 'partner', 'reader'],
                'can_manage_security_controls': role in ['admin', 'partner'],
                'can_manage_scope_assessment': role in ['admin', 'partner'],
                'can_manage_reporting_entities': role in ['admin', 'partner']
            }
            
            return permissions
            
        except Exception as e:
            print(f"Error getting user permissions: {e}")
            return {}
    
    def get_all_users(self) -> List[User]:
        """Get all users in the system (admin only)."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT u.id, u.username, u.email, u.role, u.organization_id, u.is_active, u.created_at,
                       u.last_login, u.password_hash, o.name as org_name
                FROM users u
                LEFT JOIN organizations o ON u.organization_id = o.id
                ORDER BY u.username
            """)
            
            users = []
            for row in cursor.fetchall():
                user = User(
                    id=row[0],
                    username=row[1],
                    email=row[2],
                    role=UserRole(row[3]),
                    organization_id=row[4],
                    is_active=bool(row[5]),
                    created_at=datetime.fromisoformat(row[6]) if row[6] else datetime.now(),
                    last_login=datetime.fromisoformat(row[7]) if row[7] else None,
                    password_hash=row[8] if row[8] else ""
                )
                users.append(user)
            
            conn.close()
            return users
            
        except Exception as e:
            print(f"Error getting all users: {e}")
            return []
    
    def get_users_for_organization(self, organization_id: int) -> List[User]:
        """Get all users for a specific organization."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, username, email, role, organization_id, is_active, created_at, last_login, password_hash
                FROM users
                WHERE organization_id = ?
                ORDER BY username
            """, (organization_id,))
            
            users = []
            for row in cursor.fetchall():
                user = User(
                    id=row[0],
                    username=row[1],
                    email=row[2],
                    role=UserRole(row[3]),
                    organization_id=row[4],
                    is_active=bool(row[5]),
                    created_at=datetime.fromisoformat(row[6]) if row[6] else datetime.now(),
                    last_login=datetime.fromisoformat(row[7]) if row[7] else None,
                    password_hash=row[8] if row[8] else ""
                )
                users.append(user)
            
            conn.close()
            return users
            
        except Exception as e:
            print(f"Error getting users for organization: {e}")
            return []
    
    def update_user(self, user_id: int, username: str = None, email: str = None, 
                   role: UserRole = None, organization_id: int = None, is_active: bool = None) -> bool:
        """Update user information."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Build update query dynamically
            update_fields = []
            update_values = []
            
            if username is not None:
                update_fields.append("username = ?")
                update_values.append(username)
            
            if email is not None:
                update_fields.append("email = ?")
                update_values.append(email)
            
            if role is not None:
                update_fields.append("role = ?")
                update_values.append(role.value)
            
            if organization_id is not None:
                update_fields.append("organization_id = ?")
                update_values.append(organization_id)
            
            if is_active is not None:
                update_fields.append("is_active = ?")
                update_values.append(is_active)
            
            if not update_fields:
                conn.close()
                return False
            
            update_values.append(user_id)
            query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
            
            cursor.execute(query, update_values)
            conn.commit()
            conn.close()
            
            print(f"User {user_id} updated successfully")
            return True
            
        except Exception as e:
            print(f"Error updating user: {e}")
            return False
    
    def delete_user(self, user_id: int, force_delete: bool = False) -> bool:
        """Delete a user from the system."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if user exists
            cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            if not cursor.fetchone():
                conn.close()
                return False
            
            # Check if user is the last admin
            if not force_delete:
                cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1")
                admin_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
                user_role = cursor.fetchone()[0]
                
                if user_role == 'admin' and admin_count <= 1:
                    conn.close()
                    print("Cannot delete the last admin user")
                    return False
            
            # Delete user
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            conn.close()
            
            print(f"User {user_id} deleted successfully")
            return True
            
        except Exception as e:
            print(f"Error deleting user: {e}")
            return False
    
    def change_user_password(self, user_id: int, new_password: str) -> bool:
        """Change a user's password."""
        try:
            import bcrypt
            
            # Hash the new password
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed_password, user_id))
            conn.commit()
            conn.close()
            
            print(f"Password changed successfully for user {user_id}")
            return True
            
        except Exception as e:
            print(f"Error changing password: {e}")
            return False
    
    def save_analysis_report(self, user_id: int, organization_id: int, target_type: str,
                            target_value: str, analysis_data: Dict, report_type: str,
                            compliance_framework: str = None) -> bool:
        """Save an analysis report to the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO analysis_reports 
                (user_id, organization_id, target_type, target_value, analysis_data, 
                 report_type, compliance_framework)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, organization_id, target_type, target_value, 
                  json.dumps(analysis_data), report_type, compliance_framework))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error saving analysis report: {e}")
            return False
    
    def get_user_reports(self, user_id: int, organization_id: int = None) -> List[Dict]:
        """Get reports for a user based on their access level."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if organization_id:
                cursor.execute('''
                    SELECT ar.*, u.username, o.name as org_name
                    FROM analysis_reports ar
                    JOIN users u ON ar.user_id = u.id
                    JOIN organizations o ON ar.organization_id = o.id
                    WHERE ar.organization_id = ?
                    ORDER BY ar.created_at DESC
                ''', (organization_id,))
            else:
                # Get all reports from user's accessible organizations
                user_orgs = self.get_user_organizations(user_id)
                org_ids = [org.id for org in user_orgs]
                
                if not org_ids:
                    conn.close()
                    return []
                
                placeholders = ','.join('?' * len(org_ids))
                cursor.execute(f'''
                    SELECT ar.*, u.username, o.name as org_name
                    FROM analysis_reports ar
                    JOIN users u ON ar.user_id = u.id
                    JOIN organizations o ON ar.organization_id = o.id
                    WHERE ar.organization_id IN ({placeholders})
                    ORDER BY ar.created_at DESC
                ''', org_ids)
            
            reports = []
            for row in cursor.fetchall():
                reports.append({
                    'id': row[0],
                    'user_id': row[1],
                    'organization_id': row[2],
                    'target_type': row[3],
                    'target_value': row[4],
                    'analysis_data': json.loads(row[5]),
                    'report_type': row[6],
                    'compliance_framework': row[7],
                    'created_at': row[8],
                    'username': row[9],
                    'org_name': row[10]
                })
            
            conn.close()
            return reports
        except Exception as e:
            print(f"Error getting user reports: {e}")
            return []

    def auto_fetch_organization_logo(self, organization_name: str) -> Optional[str]:
        """Auto-fetch organization logo from multiple web sources with improved reliability."""
        try:
            import requests
            from urllib.parse import quote_plus, urlparse
            import re
            
            print(f"🔍 Attempting to fetch logo for: {organization_name}")
            
            # Method 0: Check manual logo mappings for known organizations
            manual_logos = {
                "cohesive": "https://img.icons8.com/color/96/000000/shield.png",  # Generic shield icon
                "usafety": "https://img.icons8.com/color/96/000000/safety.png",   # Safety icon
                "crh": "https://img.icons8.com/color/96/000000/construction.png", # Construction icon
                "bank of ireland": "https://img.icons8.com/color/96/000000/bank.png", # Bank icon
                "aer lingus": "https://img.icons8.com/color/96/000000/airplane.png", # Airplane icon
                "intuity": "https://img.icons8.com/color/96/000000/lightbulb.png", # Innovation icon
            }
            
            org_lower = organization_name.lower()
            if org_lower in manual_logos:
                logo_url = manual_logos[org_lower]
                print(f"  🎯 Manual logo mapping found: {logo_url}")
                return logo_url
            
            # Method 1: Try Clearbit Logo API (most reliable)
            try:
                # Clean organization name for domain search
                clean_name = re.sub(r'[^\w\s]', '', organization_name).lower().replace(' ', '')
                clearbit_url = f"https://logo.clearbit.com/{clean_name}.com"
                print(f"  🎯 Trying Clearbit: {clearbit_url}")
                
                response = requests.head(clearbit_url, timeout=10)
                if response.status_code == 200:
                    print(f"  ✅ Clearbit logo found: {clearbit_url}")
                    return clearbit_url
                else:
                    print(f"  ❌ Clearbit failed: {response.status_code}")
            except Exception as e:
                print(f"  ❌ Clearbit error: {e}")
            
            # Method 2: Try organization's own website (if domain is known)
            try:
                # Try common domain patterns
                domain_patterns = [
                    f"{organization_name.lower().replace(' ', '')}.com",
                    f"{organization_name.lower().replace(' ', '')}.org",
                    f"{organization_name.lower().replace(' ', '')}.ie",  # Ireland
                    f"{organization_name.lower().replace(' ', '')}.co.uk",  # UK
                    f"{organization_name.lower().replace(' ', '')}.eu"  # EU
                ]
                
                for domain in domain_patterns:
                    try:
                        # Try common logo paths
                        logo_paths = [
                            f"https://{domain}/logo.png",
                            f"https://{domain}/logo.svg",
                            f"https://{domain}/images/logo.png",
                            f"https://{domain}/assets/logo.png",
                            f"https://{domain}/favicon.ico"
                        ]
                        
                        for logo_path in logo_paths:
                            try:
                                response = requests.head(logo_path, timeout=5)
                                if response.status_code == 200:
                                    print(f"  ✅ Domain logo found: {logo_path}")
                                    return logo_path
                            except:
                                continue
                                
                    except:
                        continue
                        
            except Exception as e:
                print(f"  ❌ Domain search error: {e}")
            
            # Method 3: Try Wikipedia for well-known organizations
            try:
                wiki_search = f"{organization_name} site:wikipedia.org"
                encoded_wiki_query = quote_plus(wiki_search)
                wiki_search_url = f"https://www.google.com/search?q={encoded_wiki_query}"
                
                print(f"  📚 Trying Wikipedia search: {organization_name}")
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                
                response = requests.get(wiki_search_url, headers=headers, timeout=15)
                if response.status_code == 200:
                    # Extract Wikipedia URL from search results
                    wiki_pattern = r'https://[^"]*wikipedia\.org[^"]*'
                    wiki_matches = re.findall(wiki_pattern, response.text)
                    
                    if wiki_matches:
                        wiki_url = wiki_matches[0]
                        print(f"  📖 Found Wikipedia page: {wiki_url}")
                        
                        # Get the Wikipedia page content
                        wiki_response = requests.get(wiki_url, headers=headers, timeout=15)
                        if wiki_response.status_code == 200:
                            # Look for logo images in Wikipedia page
                            logo_patterns = [
                                r'<img[^>]*src="([^"]*logo[^"]*\.(?:png|jpg|jpeg|svg))"[^>]*>',
                                r'<img[^>]*src="([^"]*Logo[^"]*\.(?:png|jpg|jpeg|svg))"[^>]*>',
                                r'<img[^>]*src="([^"]*emblem[^"]*\.(?:png|jpg|jpeg|svg))"[^>]*>'
                            ]
                            
                            for pattern in logo_patterns:
                                logo_matches = re.findall(pattern, wiki_response.text, re.IGNORECASE)
                                if logo_matches:
                                    logo_url = logo_matches[0]
                                    # Fix relative URLs
                                    if logo_url.startswith('//'):
                                        logo_url = 'https:' + logo_url
                                    elif logo_url.startswith('/'):
                                        logo_url = 'https://en.wikipedia.org' + logo_url
                                    
                                    print(f"  ✅ Wikipedia logo found: {logo_url}")
                                    return logo_url
                            
                            print(f"  ❌ No logo found in Wikipedia page")
                        else:
                            print(f"  ❌ Failed to fetch Wikipedia page: {wiki_response.status_code}")
                    else:
                        print(f"  ❌ No Wikipedia page found")
                else:
                    print(f"  ❌ Wikipedia search failed: {response.status_code}")
            except Exception as e:
                print(f"  ❌ Wikipedia search error: {e}")
            
            # Method 4: Fallback to generic icon based on organization type
            try:
                # Determine organization type and provide appropriate generic icon
                org_lower = organization_name.lower()
                if any(word in org_lower for word in ['bank', 'financial', 'credit']):
                    generic_logo = "https://img.icons8.com/color/96/000000/bank.png"
                elif any(word in org_lower for word in ['air', 'airline', 'aviation']):
                    generic_logo = "https://img.icons8.com/color/96/000000/airplane.png"
                elif any(word in org_lower for word in ['construction', 'building', 'infrastructure']):
                    generic_logo = "https://img.icons8.com/color/96/000000/construction.png"
                elif any(word in org_lower for word in ['tech', 'technology', 'digital', 'software']):
                    generic_logo = "https://img.icons8.com/color/96/000000/lightbulb.png"
                elif any(word in org_lower for word in ['safety', 'security', 'protection']):
                    generic_logo = "https://img.icons8.com/color/96/000000/shield.png"
                else:
                    generic_logo = "https://img.icons8.com/color/96/000000/business.png"
                
                print(f"  🎨 Using generic icon: {generic_logo}")
                return generic_logo
                
            except Exception as e:
                print(f"  ❌ Generic icon error: {e}")
            
            print(f"  ❌ No logo found for {organization_name} after trying all methods")
            return None
                    
        except Exception as e:
            print(f"❌ Error in logo fetching for {organization_name}: {e}")
            return None
    
    def update_organization_logo(self, organization_id: int, logo_url: str) -> bool:
        """Update organization logo URL."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE organizations 
                SET logo_url = ? 
                WHERE id = ?
            ''', (logo_url, organization_id))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error updating organization logo: {e}")
            return False

    def refresh_organization_logos(self) -> Dict[str, str]:
        """Refresh logos for all organizations and return results."""
        results = {}
        try:
            organizations = self.get_all_organizations()
            for org in organizations:
                if not org.logo_url:  # Only refresh if no logo exists
                    logo_url = self.auto_fetch_organization_logo(org.name)
                    if logo_url:
                        self.update_organization_logo(org.id, logo_url)
                        results[org.name] = f"✅ Logo found: {logo_url}"
                    else:
                        results[org.name] = "❌ No logo found"
                else:
                    results[org.name] = f"ℹ️ Logo already exists: {org.logo_url}"
        except Exception as e:
            print(f"Error refreshing organization logos: {e}")
            results["Error"] = f"Failed to refresh logos: {e}"
        
        return results
    
    def get_organization_by_id(self, organization_id: int) -> Optional[Organization]:
        """Get a single organization by ID with logo."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if logo_url column exists
            cursor.execute("PRAGMA table_info(organizations)")
            columns = [column[1] for column in cursor.fetchall()]
            has_logo_column = 'logo_url' in columns
            
            if has_logo_column:
                cursor.execute('''
                    SELECT id, name, domain, industry, country, compliance_framework, 
                           organization_type, parent_organization_id, created_at, is_active, logo_url
                    FROM organizations 
                    WHERE id = ? AND is_active = 1
                ''', (organization_id,))
            else:
                cursor.execute('''
                    SELECT id, name, domain, industry, country, compliance_framework, 
                           organization_type, parent_organization_id, created_at, is_active
                    FROM organizations 
                    WHERE id = ? AND is_active = 1
                ''', (organization_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return Organization(
                    id=row[0],
                    name=row[1],
                    domain=row[2],
                    industry=row[3] or "Unknown",
                    country=row[4] or "Unknown",
                    compliance_framework=row[5] or "NIS2",
                    organization_type=row[6] or "client",
                    parent_organization_id=row[7],
                    created_at=datetime.fromisoformat(row[8]) if row[8] else datetime.now(),
                    is_active=bool(row[9]),
                    logo_url=row[10] if has_logo_column and len(row) > 10 else None
                )
            return None
            
        except Exception as e:
            print(f"Error getting organization by ID: {e}")
            return None

class StreamlitAuth:
    """Streamlit-specific authentication wrapper."""
    
    def __init__(self, auth_system: AuthenticationSystem):
        """Initialize Streamlit authentication."""
        self.auth_system = auth_system
        
        # Initialize session state
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False
        if 'current_user' not in st.session_state:
            st.session_state.current_user = None
        if 'current_organization' not in st.session_state:
            st.session_state.current_organization = None
    
    def login_form(self) -> bool:
        """Display login form and return True if authentication successful."""
        # Add Cohesive logo to login page
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            try:
                # Try to load the Cohesive logo
                import os
                logo_path = os.path.join(os.getcwd(), 'cohesive_logo.svg')
                if os.path.exists(logo_path):
                    st.image(logo_path, width=300)
                else:
                    st.markdown("### 🚀 Cohesive")
            except:
                st.markdown("### 🚀 Cohesive")
        
        # Center the title
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.header("🔐 Cohesive Cyber Compliance - Login")
        
        # Center the login form
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            with st.form("login_form"):
                username = st.text_input("Username", max_chars=50)
                password = st.text_input("Password", type="password", max_chars=50)
                submit_button = st.form_submit_button("Login", use_container_width=True)
                
                if submit_button:
                    if username and password:
                        user = self.auth_system.authenticate_user(username, password)
                        if user:
                            st.session_state.authenticated = True
                            st.session_state.current_user = user
                            st.success(f"Welcome, {user.username}!")
                            st.rerun()
                        else:
                            st.error("Invalid username or password")
                    else:
                        st.warning("Please enter both username and password")
        
        return st.session_state.authenticated
    
    def organization_selector(self) -> Optional[Organization]:
        """Display organization selector for users with access to multiple orgs."""
        if not st.session_state.authenticated or not st.session_state.current_user:
            return None
        
        user = st.session_state.current_user
        user_orgs = self.auth_system.get_user_organizations(user.id)
        
        if len(user_orgs) == 1:
            st.session_state.current_organization = user_orgs[0]
            return user_orgs[0]
        
        if len(user_orgs) > 1:
            # For admin users, prioritize their own organization
            if user.role.value == 'admin':
                # Find the user's own organization (the one they're associated with in the database)
                user_own_org = next((org for org in user_orgs if org.id == user.organization_id), None)
                if user_own_org:
                    # Set the user's own organization as default
                    st.session_state.current_organization = user_own_org
                    return user_own_org
            
            # For other users or if admin's own org not found, use the first one
            org_names = [org.name for org in user_orgs]
            selected_org_name = st.selectbox(
                "Select Organization",
                org_names,
                index=0
            )
            
            selected_org = next(org for org in user_orgs if org.name == selected_org_name)
            st.session_state.current_organization = selected_org
            return selected_org
        
        return None
    
    def require_auth(self) -> bool:
        """Require authentication for the current page."""
        if not st.session_state.authenticated:
            return self.login_form()
        
        if not st.session_state.current_organization:
            self.organization_selector()
        
        return True
    
    def logout(self):
        """Logout the current user."""
        st.session_state.authenticated = False
        st.session_state.current_user = None
        st.session_state.current_organization = None
        st.rerun()
    
    def get_current_user(self) -> Optional[User]:
        """Get the currently authenticated user."""
        return st.session_state.current_user
    
    def get_current_organization(self) -> Optional[Organization]:
        """Get the currently selected organization."""
        return st.session_state.current_organization
    
    def check_permission(self, permission: str) -> bool:
        """Check if the current user has a specific permission."""
        if not st.session_state.current_user:
            return False
        
        permissions = self.auth_system.get_user_permissions(st.session_state.current_user.id)
        return permissions.get(permission, False)
