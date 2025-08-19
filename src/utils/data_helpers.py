"""
Data processing utilities for the Cohesive Cyber Compliance Platform.

This module provides helper functions for:
- Data transformation and cleaning
- Date and time processing
- Data validation and sanitization
- Export and import operations
"""

import json
import csv
import io
from datetime import datetime, date
from typing import Dict, List, Any, Optional, Union
import pandas as pd


def format_datetime(dt: Union[datetime, date, str]) -> str:
    """Format datetime objects to consistent string format."""
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        except ValueError:
            return dt
    
    if isinstance(dt, date) and not isinstance(dt, datetime):
        dt = datetime.combine(dt, datetime.min.time())
    
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else ""


def clean_text(text: str) -> str:
    """Clean and sanitize text input."""
    if not text:
        return ""
    
    # Remove extra whitespace
    text = " ".join(text.split())
    
    # Basic HTML tag removal
    import re
    text = re.sub(r'<[^>]+>', '', text)
    
    return text.strip()


def validate_email(email: str) -> bool:
    """Validate email address format."""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def export_to_csv(data: List[Dict[str, Any]], filename: str = None) -> str:
    """Export data to CSV format."""
    if not data:
        return ""
    
    if not filename:
        filename = f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    # Convert to DataFrame for easier handling
    df = pd.DataFrame(data)
    
    # Export to CSV
    output = io.StringIO()
    df.to_csv(output, index=False)
    
    return output.getvalue()


def export_to_json(data: List[Dict[str, Any]], filename: str = None) -> str:
    """Export data to JSON format."""
    if not data:
        return "[]"
    
    if not filename:
        filename = f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    return json.dumps(data, indent=2, default=str)


def parse_risk_score(score: Union[int, str, float]) -> int:
    """Parse and normalize risk scores."""
    try:
        score = int(float(score))
        return max(0, min(100, score))  # Clamp between 0-100
    except (ValueError, TypeError):
        return 0


def calculate_compliance_percentage(implemented: int, total: int) -> float:
    """Calculate compliance percentage."""
    if total == 0:
        return 0.0
    return round((implemented / total) * 100, 1)


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file operations."""
    import re
    # Remove or replace unsafe characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    # Limit length
    if len(filename) > 100:
        filename = filename[:100]
    return filename or "unnamed_file"


def merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two dictionaries, with dict2 taking precedence."""
    result = dict1.copy()
    result.update(dict2)
    return result


def flatten_nested_dict(data: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
    """Flatten nested dictionary structure."""
    items = []
    for k, v in data.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_nested_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def safe_get_nested(data: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    """Safely get nested dictionary value."""
    try:
        for key in keys:
            data = data[key]
        return data
    except (KeyError, TypeError, IndexError):
        return default


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    if size_bytes == 0:
        return "0B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f}{size_names[i]}"


def generate_unique_id(prefix: str = "", length: int = 8) -> str:
    """Generate a unique identifier."""
    import uuid
    import random
    import string
    
    if prefix:
        prefix = f"{prefix}_"
    
    # Generate random string
    chars = string.ascii_letters + string.digits
    random_part = ''.join(random.choice(chars) for _ in range(length))
    
    # Add timestamp for uniqueness
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    return f"{prefix}{timestamp}_{random_part}"


def validate_required_fields(data: Dict[str, Any], required_fields: List[str]) -> List[str]:
    """Validate that required fields are present and not empty."""
    missing_fields = []
    
    for field in required_fields:
        if field not in data or not data[field]:
            missing_fields.append(field)
    
    return missing_fields


def convert_enum_to_dict(enum_class) -> Dict[str, str]:
    """Convert enum class to dictionary mapping."""
    return {item.name: item.value for item in enum_class}


def safe_json_serialize(obj: Any) -> str:
    """Safely serialize object to JSON, handling non-serializable types."""
    def default_serializer(obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            return str(obj)
    
    return json.dumps(obj, default=default_serializer, indent=2)
