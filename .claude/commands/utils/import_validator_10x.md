# /utils:import_validator_10x - Comprehensive Import Statement Analysis & Validation

## Purpose
Intelligent import statement analysis, validation, and automatic updating for project reorganization with zero-breakage guarantee.

## Usage
```bash
# Full import analysis and validation
/utils:import_validator_10x --mode comprehensive

# Language-specific analysis
/utils:import_validator_10x --language javascript --include-dynamic
/utils:import_validator_10x --language python --check-circular
/utils:import_validator_10x --language typescript --validate-types

# Reorganization preparation
/utils:import_validator_10x --simulate-move "src/utils/helper.js" "lib/utilities/helper.js"
/utils:import_validator_10x --batch-update --from-file reorganization_plan.json

# Safety checks
/utils:import_validator_10x --validate-only --report-broken
/utils:import_validator_10x --circular-dependency-check --max-depth 10
```

## Implementation Strategy

### **PHASE 1: MULTI-LANGUAGE IMPORT PARSING** (use "ultrathink")

**1.1 Comprehensive Import Detection**
```yaml
JavaScript/TypeScript:
  static_imports:
    - "import { component } from './path'"
    - "import * as name from 'module'"
    - "import name from 'module'"
    - "import 'module' (side-effect)"
  dynamic_imports:
    - "import('./path')"
    - "require('./path')"
    - "await import('./path')"
  
Python:
  standard_imports:
    - "import module"
    - "from module import component"
    - "from . import local_module"
    - "from ..parent import module"
  dynamic_imports:
    - "__import__('module')"
    - "importlib.import_module()"
  
Go:
  import_statements:
    - 'import "package"'
    - 'import alias "package"'
    - 'import . "package"'
    - 'import _ "package"'
  
Rust:
  use_statements:
    - "use std::collections::HashMap"
    - "use crate::module"
    - "use super::parent_module"
    - "use self::current_module"
```

**1.2 Advanced Import Analysis**
```bash
# Semantic import understanding
- **ml-code-intelligence**: Parse and understand import syntax per language
- **ml-code-intelligence**: Identify import types (local, external, built-in)
- **filesystem**: Resolve import paths to actual file locations
- **ml-code-intelligence**: Detect unused imports and missing dependencies
```

**1.3 Dependency Graph Construction**
```bash
# Build comprehensive dependency map
- **10x-knowledge-graph**: Create nodes for each file and module
- **10x-knowledge-graph**: Map import relationships as edges
- **10x-knowledge-graph**: Identify dependency clusters and patterns
- **qdrant**: Store dependency vectors for similarity analysis
```

### **PHASE 2: INTELLIGENT VALIDATION & ANALYSIS** (use "ultrathink")

**2.1 Import Resolution Validation**
```python
Validation Checks:
1. Path Existence: Verify imported files/modules exist
2. Export Validation: Confirm exported symbols match imports
3. Type Checking: Validate TypeScript type imports
4. Circular Dependencies: Detect and analyze circular imports
5. Unused Imports: Identify imports that are never used
6. Missing Imports: Detect used symbols without imports
7. Version Compatibility: Check package version requirements
```

**2.2 Circular Dependency Detection**
```bash
# Advanced circular dependency analysis
- **10x-knowledge-graph**: Traverse dependency graph for cycles
- **ml-code-intelligence**: Analyze circular dependency patterns
- **context-aware-memory**: Load organizational patterns for cycle resolution
- **filesystem**: Generate dependency cycle reports with recommendations
```

**2.3 Import Impact Analysis**
```bash
# Understand reorganization impact
- **ml-code-intelligence**: Analyze which imports will break with file moves
- **filesystem**: Calculate new relative paths after reorganization
- **10x-knowledge-graph**: Map cascading effects of import changes
- **context-aware-memory**: Apply import update patterns from similar projects
```

### **PHASE 3: INTELLIGENT IMPORT UPDATING** (use "ultrathink")

**3.1 Smart Path Calculation**
```python
Path Update Logic:
1. Relative Path Calculation: Calculate new relative paths
2. Absolute Path Conversion: Convert to absolute imports where beneficial  
3. Alias Preservation: Maintain import aliases and naming
4. Barrel Export Updates: Update index.js/index.ts re-exports
5. Package.json Updates: Update main/exports fields if needed
```

**3.2 Language-Specific Import Updates**
```bash
# JavaScript/TypeScript updates
- **ml-code-intelligence**: Parse import statements with AST
- **filesystem**: Update relative paths based on new file locations  
- **filesystem**: Update TypeScript path mapping in tsconfig.json
- **filesystem**: Update webpack/build tool configurations

# Python updates  
- **ml-code-intelligence**: Handle relative import dot notation
- **filesystem**: Update __init__.py files for package structure
- **filesystem**: Update setup.py/pyproject.toml if needed

# Multi-language configuration updates
- **filesystem**: Update build scripts and configuration files
- **filesystem**: Update IDE configuration files (.vscode, .idea)
```

**3.3 Batch Update Orchestration**
```bash
# Safe batch update process
1. **filesystem**: Create backup of all files before changes
2. **ml-code-intelligence**: Generate update plan with dependency order
3. **filesystem**: Update imports in dependency order (leaves first)
4. **filesystem**: Update configuration files and build scripts
5. **bash**: Validate updates with build/test commands
6. **filesystem**: Rollback if validation fails
```

### **PHASE 4: COMPREHENSIVE VALIDATION & REPORTING** (use "ultrathink")

**4.1 Import Health Analysis**
```markdown
# Import Health Report - $(date +%Y-%m-%d_%H-%M-%S)

## Overall Import Health Score: [85/100]

### Healthy Imports ✅
- Total valid imports: [count]
- Properly resolved paths: [count]
- Type-safe imports: [count]

### Issues Found ⚠️
- Broken imports: [count]
- Circular dependencies: [count]  
- Unused imports: [count]
- Missing imports: [count]

### Reorganization Impact 📊
- Imports requiring updates: [count]
- Configuration files affected: [count]
- Estimated update time: [minutes]
```

**4.2 Detailed Import Analysis**
```yaml
Broken_Imports:
  - file: "src/components/Button.tsx"
    line: 15
    import: "import { utils } from '../utils/helpers'"
    issue: "File not found at path"
    suggestion: "Update path to '../lib/utilities/helpers'"
    risk: "High - Will break build"

Circular_Dependencies:
  - cycle: ["A.js", "B.js", "C.js", "A.js"]
    severity: "Medium"
    suggestion: "Extract shared interface or move common code"
    files_affected: 3

Unused_Imports:
  - file: "src/pages/Home.tsx"
    imports: ["React", "useState"]
    used: ["React"]
    unused: ["useState"]
    suggestion: "Remove unused import"
    space_savings: "50 bytes"
```

**4.3 Update Preview & Validation**
```bash
# Generated update scripts with validation
- **filesystem**: Create .bak files for all changes
- **filesystem**: Generate rollback scripts
- **filesystem**: Create validation test scripts
- **bash**: Test build process after updates
- **docs:granular_10x**: Document all import changes made
```

## Integration with Organization System

### **Reorganization Workflow Integration**
```bash
# Seamless integration with organize_and_analyze_10x
1. Project Structure Analysis
2. File Movement Planning  
3. /utils:import_validator_10x --preview-changes
4. Safe File Reorganization
5. /utils:import_validator_10x --batch-update
6. Validation & Testing
7. Documentation & Commit
```

### **Standalone Import Maintenance**
```bash
# Regular import health checks
/utils:import_validator_10x --health-check --schedule weekly
/utils:import_validator_10x --circular-dependency-report
/utils:import_validator_10x --unused-import-cleanup --dry-run
```

## Advanced Features

### **AI-Powered Import Optimization**
```bash
# ML-enhanced import recommendations
- **ml-code-intelligence**: Suggest better import patterns
- **qdrant**: Find similar projects for import pattern inspiration
- **context-aware-memory**: Apply organizational import standards
- **10x-knowledge-graph**: Optimize import graphs for performance
```

### **Configuration File Updates**
```yaml
Automatic_Config_Updates:
  TypeScript:
    - tsconfig.json path mappings
    - index.ts barrel exports
    - package.json exports field
  
  JavaScript:
    - webpack.config.js aliases
    - babel.config.js module resolvers
    - jest.config.js module mappings
  
  Python:
    - setup.py/pyproject.toml packages
    - __init__.py re-exports
    - requirements.txt if structure changes
  
  Build_Tools:
    - Vite/Rollup configurations
    - ESLint import/no-unresolved rules
    - IDE settings and path mappings
```

### **Import Pattern Analysis**
```bash
# Organizational import patterns
- **context-aware-memory**: Learn from successful import patterns
- **qdrant**: Vector search for optimal import structures
- **ml-code-intelligence**: Detect anti-patterns and suggest improvements
- **10x-knowledge-graph**: Map import relationships for optimization
```

## Safety Guarantees

### **Zero-Breakage Promise**
✅ **Validation Before Changes**: All imports validated before any updates
✅ **Atomic Updates**: All changes applied together or rolled back
✅ **Build Validation**: Project must build successfully after updates  
✅ **Test Validation**: All tests must pass after import updates

### **Comprehensive Rollback**
✅ **Complete Backups**: Full backup of all modified files
✅ **Rollback Scripts**: Automated scripts to revert all changes
✅ **Change Tracking**: Detailed log of every import modification
✅ **Git Integration**: Proper version control of all changes

This import validator ensures safe, intelligent import management during project reorganization while maintaining zero-breakage reliability.