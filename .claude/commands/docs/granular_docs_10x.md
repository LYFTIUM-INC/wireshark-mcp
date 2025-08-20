# /docs:granular_10x - Granular Documentation with ML Integration

## Purpose
Generate precise, scope-controlled documentation at multiple granularity levels with ML-enhanced analysis and memory integration.

## Usage
```bash
# File-level documentation
/docs:granular_10x --scope file --target "src/utils/auth.ts" --depth summary
/docs:granular_10x --scope file --target "src/**/*.tsx" --depth detailed

# Function-level documentation
/docs:granular_10x --scope function --target "handleUserAuth" --context full
/docs:granular_10x --scope function --pattern "handle*" --depth api

# Class/Module documentation
/docs:granular_10x --scope class --target "UserService" --include-hierarchy
/docs:granular_10x --scope module --target "src/services" --depth overview

# Snippet/Finding documentation
/docs:granular_10x --scope snippet --file "README.md" --lines "10-25"
/docs:granular_10x --scope finding --url "[webpage]" --extract "security recommendations"

# Combined scopes
/docs:granular_10x --scope mixed --config "docs-config.json"
```

## Parameters

### Required
- `--scope`: Documentation granularity level
  - `file`: Document entire files
  - `function`: Document specific functions/methods
  - `class`: Document classes and their members
  - `module`: Document module/package structure
  - `snippet`: Document specific code segments
  - `finding`: Extract key findings from sources
  - `mixed`: Use configuration file for complex scopes

### Optional
- `--target`: Specific target (file path, function name, class name, glob pattern)
- `--depth`: Documentation detail level
  - `summary`: High-level overview (1-2 paragraphs)
  - `standard`: Balanced documentation (default)
  - `detailed`: Comprehensive with examples
  - `api`: API reference style
  - `overview`: Architecture/design focus
  
- `--context`: Include surrounding context
  - `minimal`: Target only
  - `local`: Include immediate context
  - `full`: Include file/module context
  
- `--format`: Output format
  - `markdown` (default)
  - `jsdoc`/`pydoc`/`rustdoc` (language-specific)
  - `json` (structured data for ML)
  
- `--audience`: Target audience
  - `developer`: Technical implementation details
  - `api-user`: API consumption focus
  - `maintainer`: Architecture and design decisions
  
- `--ml-enhance`: ML enhancement options
  - `auto-categorize`: Automatic topic categorization
  - `extract-patterns`: Pattern recognition
  - `suggest-improvements`: Documentation gap analysis
  - `link-concepts`: Knowledge graph integration

## Implementation Steps

1. **Parse Scope and Target**
   - Use ml-code-intelligence MCP for semantic code analysis
   - Identify target elements using AST parsing
   - Determine context boundaries

2. **Gather Context**
   ```bash
   # For function scope
   - Extract function signature, parameters, return types
   - Analyze function body for logic flow
   - Find usage examples in codebase
   - Check test files for behavior validation
   
   # For file scope
   - Parse imports/exports
   - Identify main components/functions
   - Extract file-level comments
   - Analyze dependencies
   ```

3. **Generate Documentation**
   - Use parallel research agents for:
     - Best practices for similar code
     - Common patterns and anti-patterns
     - Security considerations
     - Performance implications
   
4. **ML Enhancement**
   - Store in context-aware-memory with embeddings
   - Extract concepts for 10x-knowledge-graph
   - Analyze with 10x-workflow-optimizer for patterns
   - Track metrics with 10x-command-analytics

5. **Output Generation**
   - Format according to specified format
   - Adjust detail level per depth parameter
   - Include examples based on audience
   - Generate both human-readable and ML-training formats

## Storage Structure
```
Knowledge/
├── documentation/
│   ├── granular/
│   │   ├── files/
│   │   │   └── [file-hash]/
│   │   │       ├── full.md
│   │   │       ├── summary.md
│   │   │       └── metadata.json
│   │   ├── functions/
│   │   │   └── [function-name]/
│   │   │       ├── doc.md
│   │   │       ├── examples.md
│   │   │       └── usage-patterns.json
│   │   ├── snippets/
│   │   │   └── [timestamp]/
│   │   │       ├── snippet.md
│   │   │       └── context.json
│   │   └── findings/
│   │       └── [source-hash]/
│   │           ├── findings.md
│   │           └── ml-data.json
│   └── ml-training/
│       ├── embeddings/
│       ├── patterns/
│       └── relationships/
```

## Integration with Existing Workflows

### Automatic Integration Points
1. **During /implement_10x**:
   - Auto-document new functions with `--scope function --depth api`
   - Update file docs with `--scope file --target [changed-files]`

2. **During /qa:comprehensive_10x**:
   - Generate test documentation with `--scope function --pattern "*test*"`
   - Document security findings with `--scope finding`

3. **During /git:smart_commit_10x**:
   - Update docs for changed functions only
   - Generate diff-based documentation updates

### ML Data Gathering Optimization
- Every documentation generation creates:
  - Structured JSON for ML training
  - Vector embeddings for similarity search
  - Concept graphs for relationship mapping
  - Usage patterns for workflow optimization

## Example Configurations

### docs-config.json for mixed scope:
```json
{
  "targets": [
    {
      "scope": "file",
      "pattern": "src/core/**/*.ts",
      "depth": "detailed",
      "ml-enhance": ["extract-patterns", "link-concepts"]
    },
    {
      "scope": "function", 
      "pattern": "handle*|process*",
      "depth": "api",
      "audience": "api-user"
    },
    {
      "scope": "finding",
      "sources": ["security-audit.md", "performance-report.html"],
      "extract": ["recommendations", "critical-issues"]
    }
  ],
  "output": {
    "format": "markdown",
    "structure": "hierarchical",
    "include-ml-data": true
  }
}
```

## Success Metrics
- 80% reduction in documentation time through granular targeting
- 90% accuracy in automatic categorization
- 70% reuse of documentation patterns
- 95% coverage of changed code elements
- 100% ML-ready output generation