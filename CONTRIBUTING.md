# Contributing to Specter

Thank you for your interest in contributing to Specter!

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/moggan1337/Specter.git
cd Specter
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -e ".[dev,api,ml]"
```

## Running Tests

```bash
pytest tests/ -v
```

## Code Style

We use:
- Black for formatting
- isort for imports
- flake8 for linting

```bash
black specter/
isort specter/
flake8 specter/
```

## Submitting Changes

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## Reporting Issues

Please report issues on GitHub with:
- Your environment (OS, Python version)
- Specter version
- Steps to reproduce
- Expected vs actual behavior
