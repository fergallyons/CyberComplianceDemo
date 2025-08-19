"""
Setup script for Cohesive Cyber Compliance Platform
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'docs', 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "Cohesive Cyber Compliance Platform"

# Read requirements
def read_requirements():
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(requirements_path):
        with open(requirements_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

setup(
    name="cohesive-cyber-compliance",
    version="1.0.0",
    description="Enhanced Cybersecurity Reporting Agent with NIS2 Compliance and Multi-Organization Support",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author="Cohesive Team",
    author_email="team@cohesive.com",
    url="https://github.com/cohesive/cyber-compliance-platform",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Office/Business",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
        "docs": [
            "sphinx>=7.0.0",
            "sphinx-rtd-theme>=1.3.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "cohesive-cyber=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.json", "*.db", "*.svg"],
    },
    keywords="cybersecurity, compliance, NIS2, incident reporting, risk management",
    project_urls={
        "Bug Reports": "https://github.com/cohesive/cyber-compliance-platform/issues",
        "Source": "https://github.com/cohesive/cyber-compliance-platform",
        "Documentation": "https://cohesive-cyber-compliance.readthedocs.io/",
    },
)
