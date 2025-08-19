# 🏛️ Reporting Entities Management Guide

## Overview

The Reporting Entities Management System provides a comprehensive way to manage regulatory bodies, law enforcement agencies, and cyber insurance companies that organizations need to report cybersecurity incidents to for NIS2 compliance and other regulatory requirements.

## Features

### 🎯 **Comprehensive Entity Management**
- **Regulatory Bodies**: NCSC Ireland, NCSC UK, CCB Belgium, ENISA, etc.
- **Law Enforcement**: Garda Síochána, FBI Cyber Division, Europol EC3, etc.
- **Cyber Insurance**: AIG, Chubb, Beazley, etc.
- **Data Protection Authorities**: DPC Ireland, etc.
- **Financial Regulators**: Sector-specific regulatory bodies
- **Other Entities**: Custom entities for specific requirements

### 🌍 **Multi-Jurisdiction Support**
- **Ireland**: NCSC Ireland, Garda Síochána, DPC Ireland
- **United Kingdom**: NCSC UK
- **Belgium**: CCB Belgium
- **European Union**: ENISA, Europol EC3
- **United States**: FBI Cyber Division
- **International**: Cyber insurance companies
- **Other**: Custom jurisdictions

### 📋 **Detailed Entity Information**
- **Contact Methods**: Email, phone, web forms, portals, APIs
- **Reporting Requirements**: Timeframes, required fields, mandatory status
- **NIS2 Scope**: Whether the entity is in scope for NIS2 compliance
- **Sectors Covered**: Essential, important, digital, financial, healthcare, etc.
- **Status Tracking**: Active/inactive status, creation/update dates

## Default Entities Included

### 🇮🇪 **Ireland**
- **NCSC Ireland**: Primary cybersecurity regulator for Ireland
  - NIS2 Scope: ✅ Yes
  - Sectors: Essential, Important, Digital
  - Contact: incidents@ncsc.gov.ie
  - Requirements: 24h initial, 72h final report

- **Garda Síochána**: Irish Police Force - Cybercrime Unit
  - NIS2 Scope: ❌ No (Law enforcement)
  - Sectors: All sectors
  - Contact: cybercrime@garda.ie
  - Requirements: 24h cybercrime report

- **DPC Ireland**: Data Protection Commission
  - NIS2 Scope: ❌ No (Data protection)
  - Sectors: All sectors
  - Contact: info@dataprotection.ie
  - Requirements: 72h data breach report

### 🇬🇧 **United Kingdom**
- **NCSC UK**: National Cyber Security Centre
  - NIS2 Scope: ✅ Yes
  - Sectors: Essential, Important
  - Contact: incidents@ncsc.gov.uk
  - Requirements: 24h significant incident report

### 🇧🇪 **Belgium**
- **CCB Belgium**: Centre for Cybersecurity Belgium
  - NIS2 Scope: ✅ Yes
  - Sectors: Essential, Important
  - Contact: incidents@ccb.belgium.be
  - Requirements: 24h significant incident report

### 🇪🇺 **European Union**
- **ENISA**: European Union Agency for Cybersecurity
  - NIS2 Scope: ✅ Yes
  - Sectors: Essential, Important
  - Contact: incidents@enisa.europa.eu
  - Requirements: 24h cross-border incident report

- **Europol EC3**: European Cybercrime Centre
  - NIS2 Scope: ❌ No (Law enforcement)
  - Sectors: All sectors
  - Contact: ec3@europol.europa.eu
  - Requirements: 24h cross-border cybercrime report

### 🇺🇸 **United States**
- **FBI Cyber Division**: Federal Bureau of Investigation
  - NIS2 Scope: ❌ No (US law enforcement)
  - Sectors: All sectors
  - Contact: cyber@fbi.gov
  - Requirements: 24h cyber incident report

### 🌐 **International**
- **AIG Cyber Insurance**: CyberEdge Cyber Liability Insurance
  - NIS2 Scope: ❌ No (Insurance)
  - Sectors: All sectors
  - Contact: cyberclaims@aig.com
  - Requirements: 24h cyber incident report

- **Chubb Cyber Insurance**: Cyber Enterprise Risk Management
  - NIS2 Scope: ❌ No (Insurance)
  - Sectors: All sectors
  - Contact: cyberclaims@chubb.com
  - Requirements: 24h cyber incident report

- **Beazley Cyber Insurance**: Breach Response Cyber Insurance
  - NIS2 Scope: ❌ No (Insurance)
  - Sectors: All sectors
  - Contact: breach@beazley.com
  - Requirements: 24h data breach report

## How to Use

### 📋 **Viewing Entities**
1. Navigate to the **"🏛️ Reporting Entities"** tab
2. Use filters to find specific entities:
   - **Type**: Regulatory Body, Law Enforcement, Cyber Insurance, etc.
   - **Jurisdiction**: Ireland, UK, Belgium, EU, USA, etc.
   - **Search**: Search by name, description, or notes
3. Click on entity expanders to view detailed information

### ➕ **Adding New Entities**
1. Go to the **"➕ Add Entity"** tab
2. Fill in required fields:
   - **Entity ID**: Unique identifier (e.g., `ncsc_netherlands`)
   - **Entity Name**: Full name of the entity
   - **Entity Type**: Category of the entity
   - **Jurisdiction**: Geographic scope
   - **Description**: Brief description of role and responsibilities
3. Optional fields:
   - **Website**: Official website URL
   - **NIS2 Scope**: Whether in scope for NIS2 compliance
   - **Sectors Covered**: Specific sectors the entity regulates
   - **Notes**: Additional information
4. Click **"➕ Add Entity"** to save

### ✏️ **Editing Entities**
1. Go to the **"✏️ Edit Entity"** tab
2. Select the entity to edit from the dropdown
3. Modify any fields as needed
4. Click **"💾 Update Entity"** to save changes

### 🗑️ **Deleting Entities**
1. Go to the **"🗑️ Delete Entity"** tab
2. Select the entity to delete from the dropdown
3. Review the entity details
4. Click **"🗑️ Delete Entity"** to remove

## Integration with Incident Reporting

The Reporting Entities system integrates with the Incident Reporting module to:

1. **Identify Required Reports**: Automatically determine which entities need to be notified based on incident type and jurisdiction
2. **Track Deadlines**: Monitor reporting deadlines for different entities
3. **Generate Reports**: Create properly formatted reports for each entity's requirements
4. **Compliance Tracking**: Ensure all mandatory reporting obligations are met

## Data Storage

- **File**: `reporting_entities.json`
- **Format**: JSON with structured data
- **Backup**: Automatic backup when entities are modified
- **Versioning**: Creation and update timestamps for audit trails

## Best Practices

### 🔍 **Entity Management**
- **Regular Updates**: Keep contact information and requirements current
- **Verification**: Periodically verify contact methods and reporting requirements
- **Documentation**: Add notes for any special requirements or procedures
- **Status Tracking**: Mark entities as inactive if they're no longer relevant

### 📊 **Compliance Monitoring**
- **NIS2 Focus**: Prioritize entities that are in scope for NIS2 compliance
- **Sector Alignment**: Ensure entities cover your organization's sectors
- **Jurisdiction Mapping**: Map entities to your operational jurisdictions
- **Requirement Tracking**: Monitor changes in reporting requirements

### 🚨 **Incident Response**
- **Quick Access**: Use the quick action button in the sidebar for rapid access
- **Entity Selection**: Choose appropriate entities based on incident type and scope
- **Deadline Management**: Track all reporting deadlines in one place
- **Audit Trail**: Maintain records of all entity interactions

## Troubleshooting

### ❌ **Common Issues**
- **Import Errors**: Ensure all required dependencies are installed
- **File Permissions**: Check write permissions for the JSON data file
- **Data Corruption**: Backup and restore from previous version if needed
- **Streamlit Warnings**: Ignore "missing ScriptRunContext" warnings in test mode

### 🔧 **Maintenance**
- **Regular Backups**: Export entity data periodically
- **Data Validation**: Verify entity data integrity
- **Performance**: Monitor for large numbers of entities affecting performance
- **Updates**: Keep the module updated with the latest features

## Future Enhancements

### 🚀 **Planned Features**
- **API Integration**: Direct integration with entity reporting systems
- **Automated Reporting**: Automatic report generation and submission
- **Compliance Scoring**: Automated compliance assessment
- **Entity Verification**: Automated verification of contact information
- **Multi-language Support**: Support for multiple languages and jurisdictions

### 🔗 **Integration Opportunities**
- **Incident Management**: Deeper integration with incident lifecycle
- **Compliance Dashboard**: Enhanced compliance tracking and reporting
- **Audit Systems**: Integration with audit and compliance management systems
- **Risk Assessment**: Entity-specific risk assessment and scoring

## Support and Documentation

For additional support or questions about the Reporting Entities Management System:

1. **Documentation**: Check this guide and related documentation
2. **Testing**: Use the test scripts to verify functionality
3. **Development**: Review the source code for implementation details
4. **Updates**: Monitor for new features and improvements

---

**Note**: This system is designed to support NIS2 Article 23 compliance and general cybersecurity incident reporting. Always verify current requirements with the relevant authorities as regulations and requirements may change over time.

