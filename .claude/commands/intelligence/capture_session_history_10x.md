## 📸 CAPTURE SESSION HISTORY 10X
*Comprehensive Session Analysis with Git, Logs, and ML Memory Integration*

**Claude, execute COMPREHENSIVE SESSION HISTORY CAPTURE with INTELLIGENT ANALYSIS, MEMORY INTEGRATION, and PRIORITY-BASED SUMMARIZATION.**

### 🎯 **INTELLIGENT SESSION ORCHESTRATION** (use "ultrathink")

**YOU ARE THE SESSION HISTORIAN** - Capture and analyze all relevant session data:

**1. MULTI-SOURCE AGGREGATION**: Combine git, logs, Claude Code, and memory systems
**2. INTELLIGENT PRIORITIZATION**: Focus on high-value changes and decisions
**3. ML-POWERED ANALYSIS**: Use Context-Aware Memory MCP for pattern detection
**4. COMPACT SUMMARIZATION**: Create concise yet comprehensive summaries
**5. SEAMLESS INTEGRATION**: Store in appropriate memory systems

### ⚡ **PHASE 1: RAPID DATA COLLECTION** (immediate)

**1.1 Git Intelligence Gathering**
```bash
# Recent commits (last 24 hours or 10 commits)
git log --since="24 hours ago" --oneline --graph --all || git log -10 --oneline --graph --all

# Current status and changes
git status --short
git diff --stat

# Branch information
git branch -vv
```

**1.2 Session Context Analysis**
- **Current working directory**: Capture project context
- **Active files**: List recently modified files
- **Open tasks**: Check TodoRead for active items
- **Memory state**: Query Context-Aware Memory MCP for recent memories

**1.3 Log Analysis**
```bash
# Check for error patterns (if logs exist)
find . -name "*.log" -mtime -1 -exec tail -20 {} \; 2>/dev/null | grep -E "(ERROR|WARN|CRITICAL)" || echo "No recent errors"

# Claude Code session info (if available)
ls -la ~/.claude/sessions/ 2>/dev/null | tail -5 || echo "No Claude session logs found"
```

### 🧠 **PHASE 2: ML-ENHANCED ANALYSIS** (use Context-Aware Memory MCP)

**2.1 Pattern Recognition**
- **store_memory**: Save session context with tags ["session", "history", date]
- **retrieve_memories**: Find similar past sessions for pattern analysis
- **predict_workflow**: Identify likely next steps based on history

**2.2 Importance Scoring**
Evaluate each change/event:
- **Critical (🔴)**: Breaking changes, major features, security fixes
- **High (🟡)**: New functionality, significant refactoring
- **Medium (🟢)**: Minor improvements, documentation
- **Low (⚪)**: Formatting, minor tweaks

### 📊 **PHASE 3: INTELLIGENT SUMMARIZATION**

**3.1 Structured Summary Format**
```markdown
# Session Summary: [DATE/TIME]

## 🎯 Key Achievements
- [Critical changes with impact]
- [Major features implemented]
- [Problems solved]

## 📈 Progress Metrics
- Commits: X
- Files Modified: Y
- Lines Changed: +A/-B
- Tests: Pass/Fail
- Active Tasks: N

## 🧠 Technical Decisions
- [Architecture choices made]
- [Technology selections]
- [Trade-offs considered]

## 🔄 Workflow Patterns
- [Detected patterns from ML analysis]
- [Efficiency insights]
- [Suggested optimizations]

## 📝 Context for Next Session
- [Open issues]
- [Pending decisions]
- [Recommended next steps]

## 🔗 Related Sessions
- [Links to similar past sessions]
```

### 💾 **PHASE 4: MEMORY INTEGRATION**

**4.1 Multi-System Storage**
```yaml
Context-Aware Memory MCP:
  - Store session summary with semantic embeddings
  - Tag: ["session_history", project_name, date]
  - Importance: Calculate based on changes
  
Knowledge Base:
  - Save to Knowledge/sessions/[date]_summary.md
  - Update Knowledge/patterns/workflow_patterns.md
  
10X Command Analytics:
  - Log command sequences used
  - Track success rates
```

**4.2 Cross-Reference Creation**
- Link to relevant git commits
- Reference modified files
- Connect to project documentation
- Update workflow patterns

### 🚀 **PHASE 5: RAPID INSIGHTS**

**5.1 Instant Value Extraction**
- **What worked well**: Successful patterns to repeat
- **What to improve**: Bottlenecks or inefficiencies
- **Key learnings**: New insights gained
- **Time savers**: Automation opportunities

**5.2 Predictive Recommendations**
Use ML analysis to suggest:
- Next logical steps
- Potential issues to address
- Optimization opportunities
- Related documentation to review

### 📋 **EXECUTION SUMMARY**

1. **Collect** all relevant data (git, logs, memory)
2. **Analyze** with ML-powered pattern recognition
3. **Summarize** with intelligent prioritization
4. **Store** in integrated memory systems
5. **Predict** next optimal actions

**Expected Output**:
- Comprehensive session summary in 30 seconds
- Intelligent insights from ML analysis
- Seamless memory system integration
- Clear next-step recommendations

Remember: Focus on **VALUE** over volume - capture what matters for future productivity!