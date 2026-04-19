"""
Specter Setup Configuration
=============================
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / "README.md"
long_description = ""
if readme_file.exists():
    long_description = readme_file.read_text()

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = [
        line.strip()
        for line in requirements_file.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="specter-cc",
    version="1.0.0",
    author="Specter Team",
    author_email="specter@example.com",
    description="Confidential Computing AI Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/moggan1337/Specter",
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=3.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.950",
        ],
        "api": [
            "fastapi>=0.100.0",
            "uvicorn[standard]>=0.23.0",
            "requests>=2.28.0",
        ],
        "ml": [
            "numpy>=1.23.0",
            "torch>=2.0.0",
            "tensorflow>=2.10.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "specter=specter:main",
            "specter-cli=specter.api.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "specter": ["py.typed"],
    },
    zip_safe=False,
)
