# /utils:duplicate_analyzer_10x - Advanced Duplicate & Similar File Detection

## Purpose
Intelligent duplicate and similar file detection using multiple analysis methods including hash comparison, semantic analysis, and ML-powered similarity detection.

## Usage
```bash
# Full duplicate analysis
/utils:duplicate_analyzer_10x --mode comprehensive

# Specific analysis types
/utils:duplicate_analyzer_10x --type exact --output-format json
/utils:duplicate_analyzer_10x --type semantic --threshold 0.85
/utils:duplicate_analyzer_10x --type structural --include-comments false

# Focus on specific file types
/utils:duplicate_analyzer_10x --file-types "js,ts,py" --mode exact
/utils:duplicate_analyzer_10x --exclude-dirs "node_modules,build,dist"
```

## Implementation Strategy

### **PHASE 1: MULTI-METHOD DUPLICATE DETECTION** (use "ultrathink")

**1.1 Exact Duplicate Detection**
```bash
# Hash-based exact matching
- **filesystem**: Calculate MD5/SHA256 hashes for all files
- **filesystem**: Group files by identical hash values
- **filesystem**: Compare file sizes and timestamps for validation
- **sqlite**: Store hash database for performance optimization
```

**1.2 Semantic Similarity Detection**
```bash
# ML-powered content analysis
- **ml-code-intelligence**: Parse and analyze code semantics
- **ml-code-intelligence**: Generate semantic embeddings for code files
- **qdrant**: Vector similarity search for functionally similar code
- **ml-code-intelligence**: Detect refactored or modified versions of same logic
```

**1.3 Structural Similarity Analysis**
```bash
# AST-based structural comparison
- **ml-code-intelligence**: Generate Abstract Syntax Trees (AST)
- **ml-code-intelligence**: Compare structural patterns ignoring variable names
- **ml-code-intelligence**: Detect copied code with minor modifications
- **10x-knowledge-graph**: Map structural relationships between files
```

### **PHASE 2: ADVANCED SIMILARITY ALGORITHMS** (use "ultrathink")

**2.1 Content-Based Similarity**
```python
Similarity Detection Methods:
1. Exact Hash Match (100% identical)
2. Fuzzy Hash (ssdeep) for near-identical files
3. Line-by-line diff analysis with similarity scoring
4. Token-based comparison (ignoring whitespace/formatting)
5. Semantic embedding cosine similarity
6. Structural AST comparison
```

**2.2 Metadata-Based Analysis**
```bash
# File metadata comparison
- **filesystem**: Compare file names for naming patterns
- **filesystem**: Analyze creation/modification timestamps
- **filesystem**: Compare file sizes and extensions
- **filesystem**: Detect copied files with timestamp patterns
```

**2.3 Context-Aware Duplicate Detection**
```bash
# Intelligent context analysis
- **ml-code-intelligence**: Understand file purpose and function
- **context-aware-memory**: Load organizational patterns for duplicate identification
- **10x-knowledge-graph**: Analyze file relationships and dependencies
- **ml-code-intelligence**: Detect legitimate vs problematic duplicates
```

### **PHASE 3: INTELLIGENT DUPLICATE CLASSIFICATION** (use "ultrathink")

**3.1 Duplicate Categories**
```yaml
Exact_Duplicates:
  description: "Identical files with same hash"
  action: "Safe to remove all but one"
  confidence: 100%

Near_Duplicates:
  description: "Very similar content with minor differences"
  action: "Manual review recommended"
  confidence: 85-99%

Structural_Duplicates:
  description: "Same logic, different implementation"
  action: "Consider refactoring to shared module"
  confidence: 70-85%

Template_Copies:
  description: "Files created from same template"
  action: "Verify if customizations are significant"
  confidence: 60-70%

Legitimate_Copies:
  description: "Intentional duplicates (configs, templates)"
  action: "Keep but document purpose"
  confidence: varies
```

**3.2 Risk Assessment**
```bash
# Smart duplicate resolution recommendations
- **ml-code-intelligence**: Analyze import dependencies for each duplicate
- **filesystem**: Check if duplicates are referenced in build/config files
- **context-aware-memory**: Apply organizational policies for duplicate handling
- **10x-knowledge-graph**: Understand impact of removing each duplicate
```

### **PHASE 4: COMPREHENSIVE REPORTING** (use "ultrathink")

**4.1 Detailed Duplicate Analysis Report**
```markdown
# Duplicate Analysis Report - $(date +%Y-%m-%d_%H-%M-%S)

## Executive Summary
- Total files analyzed: [count]
- Exact duplicates found: [count] ([size] MB reclaimable)
- Near duplicates found: [count] (manual review needed)
- Structural duplicates: [count] (refactoring opportunities)

## Exact Duplicates (Safe to Remove)
### Group 1: [hash]
- File 1: [path] (size: [size], modified: [date])
- File 2: [path] (size: [size], modified: [date])
- **Recommendation**: Keep most recent, remove others
- **Risk Level**: Low
- **Space Savings**: [size]

## Near Duplicates (Review Recommended)
### Group 1: [similarity score]
- File 1: [path] 
- File 2: [path]
- **Differences**: [summary of differences]
- **Recommendation**: [specific action]
- **Risk Level**: Medium

## Structural Duplicates (Refactoring Opportunities)
### Group 1: [description]
- Files: [list]
- **Common Logic**: [description]
- **Recommendation**: Extract to shared module
- **Effort Estimate**: [hours]
```

**4.2 Actionable Recommendations**
```bash
# Generated action scripts
- **filesystem**: Create removal scripts for safe duplicates
- **filesystem**: Generate refactoring suggestions for structural duplicates
- **docs:granular_10x**: Document duplicate resolution decisions
- **git:smart_commit_10x**: Prepare commit messages for cleanup
```

## Integration with Organization Command

### **Seamless Integration**
```bash
# Called automatically by organize_and_analyze_10x
/organize_and_analyze_10x --mode full
  ├── Project Analysis
  ├── /utils:duplicate_analyzer_10x --mode comprehensive
  ├── Import Dependency Analysis
  ├── Organization Strategy
  └── Safe Reorganization
```

### **Standalone Usage**
```bash
# Independent duplicate analysis
/utils:duplicate_analyzer_10x --mode comprehensive --dry-run
/utils:duplicate_analyzer_10x --focus exact-duplicates --auto-resolve
/utils:duplicate_analyzer_10x --export-results json
```

## Output Formats

### **JSON Export for Automation**
```json
{
  "analysis_timestamp": "2024-01-15T10:30:00Z",
  "total_files": 1250,
  "duplicates": {
    "exact": [
      {
        "hash": "abc123...",
        "files": [
          {"path": "src/utils/helper.js", "size": 1024, "modified": "2024-01-10"},
          {"path": "backup/utils/helper.js", "size": 1024, "modified": "2024-01-05"}
        ],
        "recommendation": "remove_older",
        "risk": "low",
        "space_savings": 1024
      }
    ],
    "near": [...],
    "structural": [...]
  },
  "summary": {
    "space_reclaimable": "15.2 MB",
    "refactoring_opportunities": 5,
    "manual_review_needed": 12
  }
}
```

### **Interactive HTML Report**
```bash
# Generate interactive web report
- Visual file similarity matrix
- Clickable duplicate groups
- Side-by-side diff views
- Action buttons for each recommendation
```

## Safety Features

### **Conservative Approach**
✅ **Never Auto-Delete**: Always require explicit confirmation
✅ **Backup Creation**: Automatic backup before any changes
✅ **Dependency Validation**: Check imports before suggesting removal
✅ **Risk Scoring**: Clear risk assessment for each action

### **Rollback Capabilities**
✅ **Detailed Logs**: Complete record of all analysis and actions
✅ **Restoration Scripts**: Generated scripts to restore deleted files
✅ **Version Control**: Integration with git for change tracking

This duplicate analyzer provides comprehensive, intelligent duplicate detection while maintaining safety and integrating seamlessly with the broader organization system.