git checkout main

cat > USAGE.md << 'EOF'
# Using the AI Code Review Action

## Setup

### 1. Add API Keys to Your Repository

Go to your repository **Settings** → **Secrets and variables** → **Actions**:

1. Add `OPENAI_API_KEY` with your OpenAI API key
2. Add `OPENROUTER_API_KEY` with your OpenRouter API key

### 2. Create Workflow File

Create `.github/workflows/code-review.yml` in your repository:
```yaml
name: AI Code Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Run AI Code Review
        uses: YourUsername/multi-agent-code-review@v1  # Replace with your repo
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          openrouter_api_key: ${{ secrets.OPENROUTER_API_KEY }}
          min_severity: 5  # Optional: 1-10, default is 5
```

### 3. That's It!

Every PR will now be automatically reviewed. The action will:
- ✅ Pass silently if no issues found
- ❌ Fail and block merge if issues are found (with detailed comment)

## What Gets Reviewed

The system uses 4 specialized agents:

1. **Code Analyzer** - Detects bugs, logic errors, antipatterns
2. **Security Agent** - Identifies vulnerabilities (SQL injection, XSS, etc.)
3. **Best Practices Agent** - Checks code quality and style (PEP 8, docstrings)
4. **Test Coverage Agent** - Identifies missing test scenarios

## Customization

### Adjust Severity Threshold

Set `min_severity` (1-10) to control what gets reported:
- `1-3`: Report everything including minor style issues
- `4-6`: Moderate issues
- `7-10`: Only critical bugs and security vulnerabilities

Default is `5`.