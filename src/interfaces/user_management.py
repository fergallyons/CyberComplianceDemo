"""
User Management Interface for Cybersecurity Reporting Agent
Provides administrative functions for managing users, organizations, and permissions.
"""

import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional
import plotly.express as px
from src.core.auth_system import AuthenticationSystem, UserRole, User, Organization, StreamlitAuth

class UserManagementInterface:
    """User management interface for administrators and partners."""
    
    def __init__(self, auth_system: AuthenticationSystem):
        """Initialize the user management interface."""
        self.auth_system = auth_system
    
    def display_user_management_dashboard(self, current_user: User):
        """Display the main user management dashboard."""
        st.header("👥 User Management Dashboard")
        
        # Check permissions
        permissions = self.auth_system.get_user_permissions(current_user.id)
        
        if not permissions.get('can_manage_users', False):
            st.error("You don't have permission to access user management.")
            return
        
        # Navigation tabs
        tab1, tab2, tab3, tab4 = st.tabs([
            "👤 Users", 
            "🏢 Organizations", 
            "🔐 Permissions", 
            "📊 Analytics"
        ])
        
        with tab1:
            self.display_users_tab(current_user)
        
        with tab2:
            self.display_organizations_tab(current_user)
        
        with tab3:
            self.display_permissions_tab(current_user)
        
        with tab4:
            self.display_analytics_tab(current_user)
    
    def display_users_tab(self, current_user: User):
        """Display users management tab."""
        st.subheader("👤 User Management")
        
        # Action buttons
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("➕ Create New User", key="user_create_new", type="primary"):
                st.session_state.show_create_user = True
        
        with col2:
            if st.button("📝 Edit Users", key="user_edit_users"):
                st.session_state.show_edit_users = True
        
        with col3:
            if st.button("🗑️ Delete Users", key="user_delete_users"):
                st.session_state.show_delete_users = True
        
        # Create new user form
        if st.session_state.get('show_create_user', False):
            self.create_user_form(current_user)
        
        # Edit users
        if st.session_state.get('show_edit_users', False):
            self.edit_users_interface(current_user)
        
        # Delete users
        if st.session_state.get('show_delete_users', False):
            self.delete_users_interface(current_user)
        
        # Display current users
        self.display_users_table(current_user)
    
    def create_user_form(self, current_user: User):
        """Form for creating new users."""
        st.subheader("➕ Create New User")
        
        with st.form("create_user_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                username = st.text_input("Username *")
                email = st.text_input("Email *")
                password = st.text_input("Password *", type="password")
                confirm_password = st.text_input("Confirm Password *", type="password")
            
            with col2:
                # Get accessible organizations
                user_orgs = self.auth_system.get_user_organizations(current_user.id)
                org_options = {f"{org.name} ({org.organization_type})": org.id for org in user_orgs}
                
                organization = st.selectbox("Organization *", list(org_options.keys()))
                role = st.selectbox("Role *", [role.value for role in UserRole])
                
                is_active = st.checkbox("Active", value=True)
            
            submit_button = st.form_submit_button("Create User")
            
            if submit_button:
                if not all([username, email, password, organization, role]):
                    st.error("Please fill in all required fields.")
                    return
                
                if password != confirm_password:
                    st.error("Passwords do not match.")
                    return
                
                if len(password) < 8:
                    st.error("Password must be at least 8 characters long.")
                    return
                
                # Create user
                org_id = org_options[organization]
                success = self.auth_system.create_user(
                    username=username,
                    email=email,
                    password=password,
                    organization_id=org_id,
                    role=UserRole(role)
                )
                
                if success:
                    st.success(f"User '{username}' created successfully!")
                    st.session_state.show_create_user = False
                    st.rerun()
                else:
                    st.error("Failed to create user. Please try again.")
        
        if st.button("❌ Cancel", key="user_create_cancel"):
            st.session_state.show_create_user = False
            st.rerun()
    
    def display_users_table(self, current_user: User):
        """Display a table of all accessible users."""
        st.subheader("📋 Current Users")
        
        try:
            # Get users from accessible organizations
            user_orgs = self.auth_system.get_user_organizations(current_user.id)
            org_ids = [org.id for org in user_orgs]
            
            if not org_ids:
                st.info("No organizations accessible.")
                return
            
            # Get users from database
            import sqlite3
            conn = sqlite3.connect(self.auth_system.db_path)
            cursor = conn.cursor()
            
            placeholders = ','.join('?' * len(org_ids))
            cursor.execute(f'''
                SELECT u.id, u.username, u.email, u.role, u.is_active, u.created_at, u.last_login, o.name as org_name
                FROM users u
                JOIN organizations o ON u.organization_id = o.id
                WHERE u.organization_id IN ({placeholders})
                ORDER BY u.created_at DESC
            ''', org_ids)
            
            users_data = cursor.fetchall()
            conn.close()
            
            if not users_data:
                st.info("No users found.")
                return
            
            # Convert to DataFrame
            users_df = pd.DataFrame(users_data, columns=[
                'ID', 'Username', 'Email', 'Role', 'Active', 'Created', 'Last Login', 'Organization'
            ])
            
            # Format dates
            users_df['Created'] = pd.to_datetime(users_df['Created']).dt.strftime('%Y-%m-%d %H:%M')
            users_df['Last Login'] = pd.to_datetime(users_df['Last Login']).dt.strftime('%Y-%m-%d %H:%M')
            
            # Display table
            st.dataframe(users_df, use_container_width=True)
            
            # Export options
            col1, col2, col3 = st.columns(3)
            
            with col1:
                csv = users_df.to_csv(index=False)
                st.download_button(
                    label="📥 Download CSV",
                    data=csv,
                    file_name=f"users_{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv"
                )
            
            with col2:
                # JSON export
                json_data = users_df.to_json(orient='records', indent=2)
                st.download_button(
                    label="📥 Download JSON",
                    data=json_data,
                    file_name=f"users_{datetime.now().strftime('%Y%m%d')}.json",
                    mime="application/json"
                )
            
            with col3:
                # Excel export
                try:
                    import io
                    buffer = io.BytesIO()
                    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
                        users_df.to_excel(writer, sheet_name='Users', index=False)
                    buffer.seek(0)
                    
                    st.download_button(
                        label="📥 Download Excel",
                        data=buffer.getvalue(),
                        file_name=f"users_{datetime.now().strftime('%Y%m%d')}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )
                except ImportError:
                    st.info("Excel export requires openpyxl package")
        
        except Exception as e:
            st.error(f"Error loading users: {str(e)}")
    
    def edit_users_interface(self, current_user: User):
        """Interface for editing user information."""
        st.subheader("📝 Edit Users")
        
        # Get users for editing
        user_orgs = self.auth_system.get_user_organizations(current_user.id)
        org_ids = [org.id for org in user_orgs]
        
        if not org_ids:
            st.info("No organizations accessible.")
            return
        
        try:
            conn = sqlite3.connect(self.auth_system.db_path)
            cursor = conn.cursor()
            
            placeholders = ','.join('?' * len(org_ids))
            cursor.execute(f'''
                SELECT u.id, u.username, u.email, u.role, u.is_active, o.name as org_name
                FROM users u
                JOIN organizations o ON u.organization_id = o.id
                WHERE u.organization_id IN ({placeholders})
                ORDER BY u.username
            ''', org_ids)
            
            users_data = cursor.fetchall()
            conn.close()
            
            if not users_data:
                st.info("No users found for editing.")
                return
            
            # User selection
            user_options = {f"{row[1]} ({row[5]})": row[0] for row in users_data}
            selected_user_label = st.selectbox("Select User to Edit", list(user_options.keys()))
            
            if selected_user_label:
                selected_user_id = user_options[selected_user_label]
                selected_user_data = next(row for row in users_data if row[0] == selected_user_id)
                
                # Edit form
                with st.form("edit_user_form"):
                    st.write(f"**Editing User**: {selected_user_data[1]}")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        new_email = st.text_input("Email", value=selected_user_data[2])
                        new_role = st.selectbox("Role", [role.value for role in UserRole], 
                                              index=[role.value for role in UserRole].index(selected_user_data[3]))
                        new_active = st.checkbox("Active", value=bool(selected_user_data[4]))
                    
                    with col2:
                        new_password = st.text_input("New Password (leave blank to keep current)", type="password")
                        confirm_new_password = st.text_input("Confirm New Password", type="password")
                    
                    submit_edit = st.form_submit_button("Update User")
                    
                    if submit_edit:
                        # Validate password if changing
                        if new_password and new_password != confirm_new_password:
                            st.error("New passwords do not match.")
                            return
                        
                        if new_password and len(new_password) < 8:
                            st.error("New password must be at least 8 characters long.")
                            return
                        
                        # Update user
                        try:
                            conn = sqlite3.connect(self.auth_system.db_path)
                            cursor = conn.cursor()
                            
                            if new_password:
                                # Hash new password
                                password_hash = self.auth_system.hash_password(new_password)
                                cursor.execute('''
                                    UPDATE users 
                                    SET email = ?, role = ?, is_active = ?, password_hash = ?
                                    WHERE id = ?
                                ''', (new_email, new_role, new_active, password_hash, selected_user_id))
                            else:
                                cursor.execute('''
                                    UPDATE users 
                                    SET email = ?, role = ?, is_active = ?
                                    WHERE id = ?
                                ''', (new_email, new_role, new_active, selected_user_id))
                            
                            conn.commit()
                            conn.close()
                            
                            st.success("User updated successfully!")
                            st.rerun()
                        
                        except Exception as e:
                            st.error(f"Error updating user: {str(e)}")
        
        except Exception as e:
            st.error(f"Error loading users for editing: {str(e)}")
        
        if st.button("❌ Close Edit Interface", key="user_close_edit_users"):
            st.session_state.show_edit_users = False
            st.rerun()
    
    def delete_users_interface(self, current_user: User):
        """Interface for deleting users."""
        st.subheader("🗑️ Delete Users")
        st.warning("⚠️ This action cannot be undone. Please be careful when deleting users.")
        
        # Get users for deletion
        user_orgs = self.auth_system.get_user_organizations(current_user.id)
        org_ids = [org.id for org in user_orgs]
        
        if not org_ids:
            st.info("No organizations accessible.")
            return
        
        try:
            conn = sqlite3.connect(self.auth_system.db_path)
            cursor = conn.cursor()
            
            placeholders = ','.join('?' * len(org_ids))
            cursor.execute(f'''
                SELECT u.id, u.username, u.email, u.role, o.name as org_name
                FROM users u
                JOIN organizations o ON u.organization_id = o.id
                WHERE u.organization_id IN ({placeholders}) AND u.id != ?
                ORDER BY u.username
            ''', org_ids + [current_user.id])  # Exclude current user
            
            users_data = cursor.fetchall()
            conn.close()
            
            if not users_data:
                st.info("No users found for deletion.")
                return
            
            # User selection
            user_options = {f"{row[1]} ({row[4]})": row[0] for row in users_data}
            selected_user_label = st.selectbox("Select User to Delete", list(user_options.keys()))
            
            if selected_user_label:
                selected_user_id = user_options[selected_user_label]
                selected_user_data = next(row for row in users_data if row[0] == selected_user_id)
                
                st.write(f"**User to Delete**: {selected_user_data[1]}")
                st.write(f"**Email**: {selected_user_data[2]}")
                st.write(f"**Role**: {selected_user_data[3]}")
                st.write(f"**Organization**: {selected_user_data[4]}")
                
                # Confirmation
                confirm_delete = st.checkbox("I understand this action cannot be undone")
                confirm_username = st.text_input("Type the username to confirm deletion")
                
                if st.button("🗑️ Delete User", type="secondary", disabled=not (confirm_delete and confirm_username == selected_user_data[1])):
                    try:
                        conn = sqlite3.connect(self.auth_system.db_path)
                        cursor = conn.cursor()
                        
                        # Soft delete - mark as inactive
                        cursor.execute('''
                            UPDATE users SET is_active = 0 WHERE id = ?
                        ''', (selected_user_id,))
                        
                        conn.commit()
                        conn.close()
                        
                        st.success(f"User '{selected_user_data[1]}' has been deactivated.")
                        st.rerun()
                    
                    except Exception as e:
                        st.error(f"Error deleting user: {str(e)}")
        
        except Exception as e:
            st.error(f"Error loading users for deletion: {str(e)}")
        
        if st.button("❌ Close Delete Interface", key="user_close_delete_users"):
            st.session_state.show_delete_users = False
            st.rerun()
    
    def display_organizations_tab(self, current_user: User):
        """Display organizations management tab."""
        st.subheader("🏢 Organization Management")
        
        permissions = self.auth_system.get_user_permissions(current_user.id)
        
        if not permissions.get('can_manage_organizations', False):
            st.error("You don't have permission to manage organizations.")
            return
        
        # Action buttons
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("➕ Create New Organization", key="org_create_new", type="primary"):
                st.session_state.show_create_org = True
        
        with col2:
            if st.button("📝 Edit Organizations", key="org_edit_orgs"):
                st.session_state.show_edit_orgs = True
        
        with col3:
            if st.button("🗑️ Delete Organizations", key="org_delete_orgs"):
                st.session_state.show_delete_orgs = True
        
        # Create new organization form
        if st.session_state.get('show_create_org', False):
            self.create_organization_form(current_user)
        
        # Edit organizations
        if st.session_state.get('show_edit_orgs', False):
            self.edit_organizations_interface(current_user)
        
        # Delete organizations
        if st.session_state.get('show_delete_orgs', False):
            self.delete_organizations_interface(current_user)
        
        # Display current organizations
        self.display_organizations_table(current_user)
    
    def create_organization_form(self, current_user: User):
        """Form for creating new organizations."""
        st.subheader("➕ Create New Organization")
        
        with st.form("create_organization_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                name = st.text_input("Organization Name *")
                domain = st.text_input("Domain *")
                industry = st.text_input("Industry", value="Technology")
                organization_type = st.selectbox("Organization Type *", 
                                              ["client", "partner"], 
                                              help="Partner organizations can manage multiple client organizations")
            
            with col2:
                country = st.text_input("Country", value="Global")
                compliance_framework = st.selectbox("Compliance Framework", 
                                                 ["NIS2", "ISO 27001", "NIST", "GDPR", "SOC 2", "Other"])
                
                # Get accessible organizations for parent assignment
                user_orgs = self.auth_system.get_user_organizations(current_user.id)
                partner_orgs = [org for org in user_orgs if org.organization_type == 'partner']
                
                if partner_orgs:
                    parent_options = ["None (Direct to Cohesive)"] + [org.name for org in partner_orgs]
                    parent_selection = st.selectbox("Parent Organization", parent_options)
                    parent_org_id = None if parent_selection == "None (Direct to Cohesive)" else next(org.id for org in partner_orgs if org.name == parent_selection)
                else:
                    parent_org_id = None
                
                is_active = st.checkbox("Active", value=True)
            
            submit_button = st.form_submit_button("Create Organization")
            
            if submit_button:
                if not all([name, domain, organization_type]):
                    st.error("Please fill in all required fields.")
                    return
                
                # Create organization
                org_id = self.auth_system.create_organization(
                    name=name,
                    domain=domain,
                    industry=industry,
                    country=country,
                    compliance_framework=compliance_framework,
                    organization_type=organization_type,
                    parent_organization_id=parent_org_id
                )
                
                if org_id > 0:
                    st.success(f"Organization '{name}' created successfully!")
                    st.session_state.show_create_org = False
                    st.rerun()
                else:
                    st.error("Failed to create organization. The name or domain may already exist, or there was a database error.")
        
        if st.button("❌ Cancel", key="user_create_org_cancel"):
            st.session_state.show_create_org = False
            st.rerun()
    
    def display_organizations_table(self, current_user: User):
        """Display a table of all accessible organizations."""
        st.subheader("📋 Current Organizations")
        
        try:
            user_orgs = self.auth_system.get_user_organizations(current_user.id)
            
            if not user_orgs:
                st.info("No organizations accessible.")
                return
            
            # Convert to DataFrame
            orgs_data = []
            for org in user_orgs:
                # Get parent organization name
                parent_name = "Cohesive (Direct)" if org.parent_organization_id is None else "N/A"
                if org.parent_organization_id:
                    try:
                        conn = sqlite3.connect(self.auth_system.db_path)
                        cursor = conn.cursor()
                        cursor.execute("SELECT name FROM organizations WHERE id = ?", (org.parent_organization_id,))
                        parent_result = cursor.fetchone()
                        if parent_result:
                            parent_name = parent_result[0]
                        conn.close()
                    except:
                        parent_name = "Unknown"
                
                orgs_data.append({
                    'ID': org.id,
                    'Name': org.name,
                    'Type': org.organization_type.title(),
                    'Domain': org.domain,
                    'Parent': parent_name,
                    'Industry': org.industry,
                    'Country': org.country,
                    'Compliance Framework': org.compliance_framework,
                    'Created': org.created_at.strftime('%Y-%m-%d %H:%M'),
                    'Active': 'Yes' if org.is_active else 'No'
                })
            
            orgs_df = pd.DataFrame(orgs_data)
            
            # Display table
            st.dataframe(orgs_df, use_container_width=True)
            
            # Export options
            col1, col2 = st.columns(2)
            
            with col1:
                csv = orgs_df.to_csv(index=False)
                st.download_button(
                    label="📥 Download CSV",
                    data=csv,
                    file_name=f"organizations_{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv"
                )
            
            with col2:
                json_data = orgs_df.to_json(orient='records', indent=2)
                st.download_button(
                    label="📥 Download JSON",
                    data=json_data,
                    file_name=f"organizations_{datetime.now().strftime('%Y%m%d')}.json",
                    mime="application/json"
                )
        
        except Exception as e:
            st.error(f"Error loading organizations: {str(e)}")
    
    def edit_organizations_interface(self, current_user: User):
        """Interface for editing organization information."""
        st.subheader("📝 Edit Organizations")
        
        # Get organizations for editing
        user_orgs = self.auth_system.get_user_organizations(current_user.id)
        
        if not user_orgs:
            st.info("No organizations accessible for editing.")
            return
        
        # Organization selection
        org_options = {org.name: org.id for org in user_orgs}
        selected_org_name = st.selectbox("Select Organization to Edit", list(org_options.keys()))
        
        if selected_org_name:
            selected_org = next(org for org in user_orgs if org.name == selected_org_name)
            
            # Edit form
            with st.form("edit_organization_form"):
                st.write(f"**Editing Organization**: {selected_org.name}")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    new_name = st.text_input("Name", value=selected_org.name)
                    new_domain = st.text_input("Domain", value=selected_org.domain)
                    new_industry = st.text_input("Industry", value=selected_org.industry)
                
                with col2:
                    new_country = st.text_input("Country", value=selected_org.country)
                    new_compliance = st.selectbox("Compliance Framework", 
                                                ["NIS2", "ISO 27001", "NIST", "GDPR", "SOC 2", "Other"],
                                                index=["NIS2", "ISO 27001", "NIST", "GDPR", "SOC 2", "Other"].index(selected_org.compliance_framework))
                    new_active = st.checkbox("Active", value=selected_org.is_active)
                    
                    # Parent organization selection
                    user_orgs = self.auth_system.get_user_organizations(current_user.id)
                    partner_orgs = [org for org in user_orgs if org.organization_type == 'partner' and org.id != selected_org.id]
                    
                    if partner_orgs:
                        parent_options = ["None (Direct to Cohesive)"] + [org.name for org in partner_orgs]
                        current_parent_index = 0
                        if selected_org.parent_organization_id:
                            try:
                                conn = sqlite3.connect(self.auth_system.db_path)
                                cursor = conn.cursor()
                                cursor.execute("SELECT name FROM organizations WHERE id = ?", (selected_org.parent_organization_id,))
                                parent_result = cursor.fetchone()
                                if parent_result:
                                    current_parent_name = parent_result[0]
                                    if current_parent_name in [org.name for org in partner_orgs]:
                                        current_parent_index = parent_options.index(current_parent_name)
                                conn.close()
                            except:
                                pass
                        
                        new_parent_selection = st.selectbox("Parent Organization", parent_options, index=current_parent_index)
                        new_parent_org_id = None if new_parent_selection == "None (Direct to Cohesive)" else next(org.id for org in partner_orgs if org.name == new_parent_selection)
                    else:
                        new_parent_org_id = selected_org.parent_organization_id
                
                submit_edit = st.form_submit_button("Update Organization")
                
                if submit_edit:
                    if not all([new_name, new_domain]):
                        st.error("Please fill in all required fields.")
                        return
                    
                    # Update organization using the auth system method
                    success = self.auth_system.update_organization(
                        organization_id=selected_org.id,
                        name=new_name,
                        domain=new_domain,
                        industry=new_industry,
                        country=new_country,
                        compliance_framework=new_compliance,
                        is_active=new_active,
                        parent_organization_id=new_parent_org_id
                    )
                    
                    if success:
                        st.success("Organization updated successfully!")
                        st.rerun()
                    else:
                        st.error("Failed to update organization. The name or domain may already exist, or there was a database error.")
        
        if st.button("❌ Close Edit Interface", key="org_close_edit"):
            st.session_state.show_edit_orgs = False
            st.rerun()
    
    def delete_organizations_interface(self, current_user: User):
        """Interface for deleting organizations."""
        st.subheader("🗑️ Delete Organizations")
        st.warning("⚠️ **DANGER ZONE**: This action cannot be undone. Deleting an organization will remove all associated users, data, and reports.")
        
        # Get organizations for deletion
        user_orgs = self.auth_system.get_user_organizations(current_user.id)
        
        if not user_orgs:
            st.info("No organizations accessible for deletion.")
            return
        
        # Filter out the main Cohesive platform organization
        deletable_orgs = [org for org in user_orgs if not (org.name == "Cohesive" and org.organization_type == "platform")]
        
        if not deletable_orgs:
            st.info("No organizations can be deleted.")
            return
        
        # Organization selection
        org_options = {f"{org.name} ({org.organization_type})": org.id for org in deletable_orgs}
        selected_org_label = st.selectbox("Select Organization to Delete", list(org_options.keys()))
        
        if selected_org_label:
            selected_org_id = org_options[selected_org_label]
            selected_org = next(org for org in deletable_orgs if org.id == selected_org_id)
            
            # Display organization details and warnings
            st.subheader(f"Organization: {selected_org.name}")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Organization Details:**")
                st.write(f"- **Type**: {selected_org.organization_type.title()}")
                st.write(f"- **Domain**: {selected_org.domain}")
                st.write(f"- **Industry**: {selected_org.industry}")
                st.write(f"- **Country**: {selected_org.country}")
                st.write(f"- **Compliance**: {selected_org.compliance_framework}")
                st.write(f"- **Created**: {selected_org.created_at.strftime('%Y-%m-%d %H:%M')}")
            
            with col2:
                st.write("**Impact Assessment:**")
                
                            # Get organization statistics
            stats = self.auth_system.get_organization_statistics(selected_org.id)
            active_users = stats['active_users']
            total_users = stats['total_users']
            child_orgs = stats['child_organizations']
            reports = stats['analysis_reports']
            
            st.write(f"- **Active Users**: {active_users}")
            st.write(f"- **Total Users**: {total_users}")
            st.write(f"- **Child Organizations**: {child_orgs}")
            st.write(f"- **Analysis Reports**: {reports}")
            
            if active_users > 0 or child_orgs > 0:
                st.error(f"⚠️ This organization has {active_users} active users and {child_orgs} child organizations!")
            
            # Confirmation and deletion
            st.subheader("Deletion Confirmation")
            
            # Safety checks
            safety_checks = []
            
            if selected_org.organization_type == "platform":
                safety_checks.append("❌ Cannot delete platform organizations")
            
            if selected_org.name == "Cohesive":
                safety_checks.append("❌ Cannot delete the main Cohesive organization")
            
            if active_users > 0:
                safety_checks.append(f"⚠️ Organization has {active_users} active users")
            
            if child_orgs > 0:
                safety_checks.append(f"⚠️ Organization has {child_orgs} child organizations")
            
            if reports > 0:
                safety_checks.append(f"⚠️ Organization has {reports} analysis reports")
            
            # Display safety check results
            for check in safety_checks:
                st.write(check)
            
            # Deletion options
            if active_users > 0 or child_orgs > 0:
                st.warning("**Force Delete Required**: This organization has active users or child organizations.")
                force_delete = st.checkbox("Force Delete (will remove all users and child organizations)", value=False)
                
                if not force_delete:
                    st.error("Cannot proceed without force delete enabled.")
                    return
            else:
                force_delete = False
            
            # Final confirmation
            st.error("**FINAL WARNING**: This action will permanently delete the organization and ALL associated data!")
            
            # Confirmation inputs
            col1, col2 = st.columns(2)
            
            with col1:
                confirm_name = st.text_input("Type the organization name to confirm deletion", 
                                           placeholder=f"Type: {selected_org.name}")
            
            with col2:
                confirm_delete = st.checkbox("I understand this action cannot be undone", value=False)
            
            # Delete button
            if confirm_name == selected_org.name and confirm_delete:
                if st.button("🗑️ DELETE ORGANIZATION", key="org_delete_confirm", type="primary", help="This will permanently delete the organization"):
                    try:
                        # Perform deletion
                        success = self.auth_system.delete_organization(selected_org.id, force_delete=force_delete)
                        
                        if success:
                            st.success(f"Organization '{selected_org.name}' deleted successfully!")
                            st.session_state.show_delete_orgs = False
                            st.rerun()
                        else:
                            st.error("Failed to delete organization. Check the console for details.")
                    
                    except Exception as e:
                        st.error(f"Error deleting organization: {str(e)}")
            else:
                if confirm_name and confirm_name != selected_org.name:
                    st.error("Organization name does not match")
                if not confirm_delete:
                    st.error("Please confirm that you understand the action cannot be undone")
        
        if st.button("❌ Close Delete Interface", key="org_close_delete"):
            st.session_state.show_delete_orgs = False
            st.rerun()
    
    def display_permissions_tab(self, current_user: User):
        """Display permissions management tab."""
        st.subheader("🔐 Permissions Management")
        
        # Display current user permissions
        permissions = self.auth_system.get_user_permissions(current_user.id)
        
        st.write("**Your Current Permissions:**")
        
        permission_descriptions = {
            'can_create_reports': 'Create and manage security analysis reports',
            'can_view_reports': 'View security analysis reports',
            'can_manage_users': 'Manage users and their permissions',
            'can_manage_organizations': 'Manage organizations and their settings',
            'can_export_data': 'Export data and reports',
            'can_access_compliance': 'Access compliance and regulatory features',
            'can_view_analytics': 'View system analytics and metrics',
            'can_configure_system': 'Configure system settings and parameters'
        }
        
        for permission, description in permission_descriptions.items():
            status = "✅" if permissions.get(permission, False) else "❌"
            st.write(f"{status} **{permission.replace('_', ' ').title()}**: {description}")
        
        # Role information
        st.write(f"\n**Your Role**: {current_user.role.value.upper()}")
        
        # Role capabilities
        role_capabilities = {
            UserRole.ADMIN: "Full system access, can manage all aspects of the system",
            UserRole.PARTNER: "Multi-organization access, can manage users and organizations",
            UserRole.REPORTER: "Can create reports and access compliance features",
            UserRole.READER: "Read-only access to reports and basic features"
        }
        
        st.write(f"**Role Capabilities**: {role_capabilities.get(current_user.role, 'Unknown')}")
    
    def display_analytics_tab(self, current_user: User):
        """Display user management analytics."""
        st.subheader("📊 User Management Analytics")
        
        try:
            # Get analytics data
            user_orgs = self.auth_system.get_user_organizations(current_user.id)
            org_ids = [org.id for org in user_orgs]
            
            if not org_ids:
                st.info("No organizations accessible for analytics.")
                return
            
            conn = sqlite3.connect(self.auth_system.auth_system.db_path)
            cursor = conn.cursor()
            
            # User count by organization
            placeholders = ','.join('?' * len(org_ids))
            cursor.execute(f'''
                SELECT o.name, COUNT(u.id) as user_count
                FROM organizations o
                LEFT JOIN users u ON o.id = u.organization_id AND u.is_active = 1
                WHERE o.id IN ({placeholders})
                GROUP BY o.id, o.name
                ORDER BY user_count DESC
            ''', org_ids)
            
            org_user_counts = cursor.fetchall()
            
            # Role distribution
            cursor.execute(f'''
                SELECT u.role, COUNT(*) as count
                FROM users u
                WHERE u.organization_id IN ({placeholders}) AND u.is_active = 1
                GROUP BY u.role
                ORDER BY count DESC
            ''', org_ids)
            
            role_distribution = cursor.fetchall()
            
            # Recent activity
            cursor.execute(f'''
                SELECT u.username, u.last_login, o.name as org_name
                FROM users u
                JOIN organizations o ON u.organization_id = o.id
                WHERE u.organization_id IN ({placeholders}) AND u.is_active = 1
                ORDER BY u.last_login DESC
                LIMIT 10
            ''', org_ids)
            
            recent_activity = cursor.fetchall()
            
            conn.close()
            
            # Display analytics
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Users by Organization**")
                org_df = pd.DataFrame(org_user_counts, columns=['Organization', 'User Count'])
                st.dataframe(org_df, use_container_width=True)
                
                # Chart
                fig = px.bar(org_df, x='Organization', y='User Count', 
                           title="User Distribution by Organization")
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.write("**Role Distribution**")
                role_df = pd.DataFrame(role_distribution, columns=['Role', 'Count'])
                st.dataframe(role_df, use_container_width=True)
                
                # Pie chart
                fig = px.pie(role_df, values='Count', names='Role', 
                           title="User Role Distribution")
                st.plotly_chart(fig, use_container_width=True)
            
            # Recent activity
            st.write("**Recent User Activity**")
            if recent_activity:
                activity_df = pd.DataFrame(recent_activity, columns=['Username', 'Last Login', 'Organization'])
                activity_df['Last Login'] = pd.to_datetime(activity_df['Last Login']).dt.strftime('%Y-%m-%d %H:%M')
                st.dataframe(activity_df, use_container_width=True)
            else:
                st.info("No recent activity data available.")
        
        except Exception as e:
            st.error(f"Error loading analytics: {str(e)}")
