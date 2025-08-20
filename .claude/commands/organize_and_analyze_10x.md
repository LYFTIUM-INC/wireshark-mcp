# /organize_and_analyze_10x - Intelligent Project Organization & Analysis

## Purpose
Analyze, organize, and clean project structure using ML-enhanced file analysis, duplicate detection, and import validation with safety-first approach.

## Usage
```bash
# Full analysis and organization
/organize_and_analyze_10x --mode full

# Analysis only (no changes)
/organize_and_analyze_10x --mode analyze --dry-run

# Specific focus areas
/organize_and_analyze_10x --focus duplicates --dry-run
/organize_and_analyze_10x --focus imports --validate-only
/organize_and_analyze_10x --focus structure --suggest-only

# Safe organization with confirmation
/organize_and_analyze_10x --mode organize --interactive
```

## Implementation Strategy

### **PHASE 1: COMPREHENSIVE PROJECT ANALYSIS** (use "ultrathink")

**1.1 Project Structure Intelligence**
- **filesystem**: Deep directory tree analysis - map all files, sizes, types, and relationships
- **filesystem**: Identify file patterns, naming conventions, and organizational logic
- **ml-code-intelligence**: Semantic analysis of code files for purpose and relationships
- **context-aware-memory**: Load previous organization patterns and successful structures

**1.2 Enhanced File Classification & Pattern Recognition**
- **filesystem**: Classify files by type, purpose, and relationship (source, config, docs, assets, etc.)
- **ml-code-intelligence**: Analyze code semantics to understand functional relationships
- **10x-knowledge-graph**: Extract concept relationships between files and modules
- **qdrant**: Vector search for similar file organization patterns in organizational knowledge

**1.3 Duplicate & Similar File Detection**
- **filesystem**: MD5/SHA256 hash comparison for exact duplicates
- **ml-code-intelligence**: Semantic similarity analysis for near-duplicate code
- **qdrant**: Vector-based similarity search for functionally similar files
- **filesystem**: Size and timestamp analysis for potential duplicates

### **PHASE 2: INTELLIGENT IMPORT & DEPENDENCY ANALYSIS** (use "ultrathink")

**2.1 Comprehensive Import Mapping**
```bash
# Multi-language import analysis
- JavaScript/TypeScript: import, require, dynamic imports
- Python: import, from...import, __import__
- Go: import statements and module dependencies
- Rust: use statements and crate dependencies
- Java: import statements and package dependencies
```

**2.2 Import Validation & Safety Checks**
- **filesystem**: Parse all import statements and map to actual file locations
- **ml-code-intelligence**: Analyze import graphs and dependency relationships
- **filesystem**: Validate relative path imports will remain valid after reorganization
- **context-aware-memory**: Check against known import patterns and organizational rules

**2.3 Circular Dependency Detection**
- **10x-knowledge-graph**: Build dependency graph and detect circular references
- **ml-code-intelligence**: Analyze code flow and identify problematic dependencies
- **filesystem**: Map import chains and identify potential breaking changes

### **PHASE 3: ORGANIZATION STRATEGY DESIGN** (use "ultrathink")

**3.1 Intelligent Directory Structure Planning**
Based on analysis results, design optimal organization:

```yaml
Proposed Structure Categories:
  source_code:
    - src/ (main application code)
    - lib/ or utils/ (shared utilities)
    - components/ (reusable components)
    - services/ (business logic services)
    - types/ or models/ (data structures)
    
  configuration:
    - config/ (configuration files)
    - env/ (environment-specific files)
    - scripts/ (build and utility scripts)
    
  documentation:
    - docs/ (documentation files)
    - README files (keep at appropriate levels)
    - examples/ (code examples)
    
  assets_and_resources:
    - assets/ (images, fonts, etc.)
    - public/ (publicly served files)
    - resources/ (data files, templates)
    
  testing:
    - tests/ or __tests__ (test files)
    - fixtures/ (test data)
    - mocks/ (mock files)
    
  development:
    - .github/ (GitHub workflows)
    - .vscode/ (editor configuration)
    - tools/ (development tools)
    
  build_and_deployment:
    - build/ (build outputs)
    - dist/ (distribution files)
    - deploy/ (deployment scripts)
```

**3.2 Smart File Movement Strategy**
- **Priority 1**: Safety-first - never break existing functionality
- **Priority 2**: Logical grouping by purpose and relationships
- **Priority 3**: Follow language/framework conventions
- **Priority 4**: Maintain import compatibility

### **PHASE 4: SAFE REORGANIZATION EXECUTION** (use "ultrathink")

**4.1 Pre-Reorganization Safety Checks**
```bash
Safety Protocol:
1. Create complete backup with timestamp
2. Generate detailed move plan with impact analysis
3. Validate all import statements will remain functional
4. Check for hardcoded paths in configuration files
5. Verify build scripts and deployment configs
6. Test import resolution in development environment
```

**4.2 Intelligent File Movement with Import Updates**
```bash
# Smart reorganization process
1. Create target directory structure
2. Copy files to new locations (preserve originals)
3. Update import statements in copied files
4. Update configuration files with new paths
5. Update build scripts and package.json references
6. Validate all imports resolve correctly
7. Run tests to ensure functionality intact
8. Only then remove original files
```

**4.3 Import Statement Updates**
- **ml-code-intelligence**: Parse and understand import syntax for each language
- **filesystem**: Update relative imports based on new file locations
- **filesystem**: Update configuration files with new paths
- **context-aware-memory**: Store successful import update patterns

### **PHASE 5: VALIDATION & CLEANUP** (use "ultrathink")

**5.1 Comprehensive Validation**
- **filesystem**: Verify all files moved to correct locations
- **ml-code-intelligence**: Validate all imports resolve correctly
- **filesystem**: Check for orphaned files or broken references
- **bash**: Run project build/test commands to ensure functionality

**5.2 Duplicate Resolution & Cleanup**
```bash
Duplicate Handling Strategy:
1. Exact duplicates: Keep most recent, remove others
2. Similar files: Analyze usage and consolidate if safe
3. Legacy files: Move to archive/ directory with documentation
4. Temporary files: Safe deletion after validation
```

**5.3 Documentation & Knowledge Storage**
- **docs:granular_10x**: Document new organization structure
- **context-aware-memory**: Store successful organization patterns
- **10x-knowledge-graph**: Update file relationship mappings

## Command Modes

### **Analysis Mode (--mode analyze --dry-run)**
- Comprehensive analysis without any file changes
- Generate organization recommendations
- Identify duplicates and similar files
- Map import dependencies
- Output: Detailed analysis report with recommendations

### **Interactive Mode (--mode organize --interactive)**
- Step-by-step organization with user confirmation
- Show impact of each proposed change
- Allow selective application of recommendations
- Provide rollback options at each step

### **Focus Modes**
```bash
--focus duplicates    # Focus on duplicate detection and resolution
--focus imports       # Focus on import validation and updates
--focus structure     # Focus on directory organization
--focus cleanup       # Focus on removing unnecessary files
```

### **Safety Options**
```bash
--dry-run            # Analysis only, no changes
--backup             # Create timestamped backup before changes
--validate-only      # Only validate imports, no reorganization
--interactive        # Confirm each change
--rollback           # Rollback to previous state
```

## Output Structure

### **Analysis Report**
```
analysis_report_$(date +%Y-%m-%d_%H-%M-%S).md
├── Project Overview
├── Current Structure Analysis
├── Duplicate Files Report
├── Import Dependency Map
├── Recommended Organization
├── Risk Assessment
└── Action Plan
```

### **Organization Logs**
```
organization_log_$(date +%Y-%m-%d_%H-%M-%S).md
├── Backup Location
├── Files Moved (source → destination)
├── Import Updates Made
├── Configuration Changes
├── Validation Results
└── Rollback Instructions
```

## Integration with Existing Commands

### **Leverage Existing Infrastructure**
- **Pre-analysis**: `/analyze_10x --mode deep` for comprehensive project understanding
- **Import validation**: Use existing ML code intelligence for semantic analysis
- **Documentation**: Auto-generate docs with `/docs:granular_10x` for new structure
- **Git integration**: Use `/git:smart_commit_10x` for organizing changes
- **Memory storage**: Store patterns with existing memory systems

### **Command Chaining**
```bash
# Complete organization workflow
1. /analyze_10x --mode deep                    # Understand project context
2. /organize_and_analyze_10x --mode analyze    # Plan organization
3. /organize_and_analyze_10x --mode organize --interactive  # Execute safely
4. /docs:granular_10x --scope structure       # Document new organization
5. /git:smart_commit_10x                       # Commit organization changes
```

## Success Criteria

### **Safety & Reliability**
✅ **Zero Breaking Changes**: All imports and functionality preserved
✅ **Complete Backup**: Full project backup before any changes
✅ **Rollback Capability**: Ability to revert all changes
✅ **Validation Testing**: Comprehensive testing before finalization

### **Organization Quality**
✅ **Logical Structure**: Files organized by purpose and relationships
✅ **Consistency**: Following language/framework conventions
✅ **Duplicate Resolution**: No unnecessary duplicate files
✅ **Clean Directory Tree**: Clear, navigable project structure

### **Documentation & Knowledge**
✅ **Comprehensive Documentation**: New structure fully documented
✅ **Organization Patterns**: Successful patterns stored for reuse
✅ **Impact Analysis**: Clear understanding of all changes made
✅ **Future Maintainability**: Structure supports continued development

## Example Usage Workflow

```bash
# 1. Initial analysis
/organize_and_analyze_10x --mode analyze --dry-run

# 2. Review recommendations, then organize interactively
/organize_and_analyze_10x --mode organize --interactive --backup

# 3. Focus on specific issues if needed
/organize_and_analyze_10x --focus imports --validate-only

# 4. Document the new structure
/docs:granular_10x --scope structure --depth detailed

# 5. Commit the organization
/git:smart_commit_10x
```

This command provides intelligent, safe project organization while preserving all functionality and leveraging the existing 10X agentic infrastructure for maximum reliability and effectiveness.