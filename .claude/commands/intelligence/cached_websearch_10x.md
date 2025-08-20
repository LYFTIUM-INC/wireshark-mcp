## 🚀 CACHED WEBSEARCH - Smart Search with Intelligence
**Claude, execute INTELLIGENT websearch with automatic caching and redundancy elimination.**

### ⚡ **QUICK USAGE FOR ALL 10X COMMANDS**

**REPLACE:** `websearch "your query"`  
**WITH:** `/cached_websearch_10x "your query"`

### 🧠 **AUTOMATIC EXECUTION SEQUENCE**

**STEP 1: Cache Analysis**
```sql
-- Check for similar searches (last 30 days)
SELECT 
  query, 
  results_file, 
  timestamp, 
  relevance_score,
  usage_count
FROM search_cache 
WHERE 
  (LOWER(query) LIKE '%keyword1%' OR 
   LOWER(query) LIKE '%keyword2%' OR
   LOWER(keywords) LIKE '%topic%')
  AND timestamp > datetime('now', '-30 days')
  AND status = 'active'
ORDER BY relevance_score DESC, timestamp DESC
LIMIT 3;
```

**STEP 2: Intelligence Decision**
- **90%+ similarity**: Return cached results + brief summary
- **70-89% similarity**: Return cached + supplement with focused search
- **<70% similarity**: Execute full new search + cache results

**STEP 3: Automatic Execution**

```bash
# Generate search hash
QUERY_CLEAN=$(echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9 ]//g')
SEARCH_HASH=$(echo "$QUERY_CLEAN" | sha256sum | cut -d' ' -f1)

# Check cache
CACHE_MATCH=$(sqlite3 Knowledge/intelligence/search_cache/index/cache.db \
  "SELECT query, results_file, relevance_score FROM search_cache 
   WHERE query_hash = '$SEARCH_HASH' OR 
   (keywords LIKE '%$(echo $QUERY_CLEAN | cut -d' ' -f1)%' AND 
    keywords LIKE '%$(echo $QUERY_CLEAN | cut -d' ' -f2)%')
   ORDER BY relevance_score DESC LIMIT 1;")

if [ ! -z "$CACHE_MATCH" ]; then
  RELEVANCE=$(echo "$CACHE_MATCH" | cut -d'|' -f3)
  if [ "$RELEVANCE" -gt 80 ]; then
    echo "📋 Using cached search (${RELEVANCE}% match):"
    RESULTS_FILE=$(echo "$CACHE_MATCH" | cut -d'|' -f2)
    cat "Knowledge/intelligence/search_cache/$RESULTS_FILE"
    
    # Update usage statistics
    sqlite3 Knowledge/intelligence/search_cache/index/cache.db \
      "UPDATE search_cache SET usage_count = usage_count + 1, 
       last_accessed = datetime('now') WHERE results_file = '$RESULTS_FILE';"
    exit 0
  fi
fi

# Execute new search
echo "🔍 Executing new search: $1"
SEARCH_RESULTS=$(websearch "$1")

# Cache the results
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CACHE_FILE="by_date/$(date +%Y-%m)/${TIMESTAMP}_${SEARCH_HASH:0:8}.md"
FULL_PATH="Knowledge/intelligence/search_cache/$CACHE_FILE"

# Create directory if needed
mkdir -p "$(dirname "$FULL_PATH")"

# Store results
cat > "$FULL_PATH" << EOF
# Search Results: $1
**Date**: $(date)
**Keywords**: $QUERY_CLEAN
**Hash**: $SEARCH_HASH
**Type**: websearch

## Results

$SEARCH_RESULTS

---
*Cached by 10X Agentic Intelligence System*
EOF

# Update database
sqlite3 Knowledge/intelligence/search_cache/index/cache.db << EOF
INSERT INTO search_cache 
(query, keywords, results_file, query_hash, file_size, domain) 
VALUES 
('$1', '$QUERY_CLEAN', '$CACHE_FILE', '$SEARCH_HASH', 
 $(wc -c < "$FULL_PATH"), 
 '$(echo "$QUERY_CLEAN" | grep -o -E "(development|security|performance|architecture|ai|tools)" | head -1)');

UPDATE search_metrics 
SET total_searches = total_searches + 1 
WHERE date = date('now');
EOF

echo "$SEARCH_RESULTS"
```

### 📊 **INTEGRATION WITH 10X COMMANDS**

**Update ALL 10X commands to replace:**

```markdown
# OLD WAY:
- **websearch**: "react performance optimization 2025"

# NEW WAY:  
- **cached_websearch_10x**: "react performance optimization 2025"
```

### 🎯 **INTELLIGENT SEARCH ENHANCEMENT**

**Context-Aware Searching:**
- Automatically adds project context to searches
- Includes technology stack in search terms
- Filters results by recency and relevance

**Example Enhancement:**
```bash
# Original query: "testing best practices"
# Enhanced query: "testing best practices javascript react 2025 enterprise"
# Based on: Project detection + current year + enterprise context
```

### 📈 **CACHE PERFORMANCE MONITORING**

**View Cache Statistics:**
```sql
SELECT 
  date,
  total_searches,
  cache_hits,
  ROUND(CAST(cache_hits AS FLOAT) / total_searches * 100, 2) as hit_rate_percent,
  api_calls_saved
FROM search_metrics 
WHERE date >= date('now', '-7 days')
ORDER BY date DESC;
```

**Top Cached Searches:**
```sql
SELECT 
  query,
  usage_count,
  last_accessed,
  ROUND(relevance_score, 2) as relevance
FROM search_cache 
WHERE status = 'active'
ORDER BY usage_count DESC
LIMIT 10;
```

### 🔧 **MAINTENANCE COMMANDS**

**Clean Old Cache (30+ days):**
```sql
UPDATE search_cache 
SET status = 'archived' 
WHERE timestamp < datetime('now', '-30 days') 
AND usage_count < 2;
```

**Optimize Cache Database:**
```sql
VACUUM;
REINDEX;
ANALYZE;
```

### ✅ **SUCCESS METRICS**

**Expected Performance:**
- **70% cache hit rate** for repeated searches
- **80% reduction** in redundant API calls  
- **3x faster** response time for cached queries
- **Cumulative intelligence** builds over time

**Daily Usage Report:**
```bash
echo "📊 Cache Performance Today:"
echo "Total Searches: $(sqlite3 cache.db "SELECT total_searches FROM search_metrics WHERE date = date('now');")"
echo "Cache Hits: $(sqlite3 cache.db "SELECT cache_hits FROM search_metrics WHERE date = date('now');")"
echo "API Calls Saved: $(sqlite3 cache.db "SELECT api_calls_saved FROM search_metrics WHERE date = date('now');")"
```

### 🔄 **AUTOMATIC PATTERN LEARNING**

The system automatically:
- **Identifies** common search patterns
- **Suggests** related searches
- **Pre-caches** likely follow-up queries
- **Optimizes** search terms based on successful results

### 📊 **STRUCTURED DATA OUTPUT WITH ML TRAINING PREPARATION**

**Multi-System Storage Architecture:**
```yaml
# Cached Search Report
filename: Knowledge/intelligence/cached_search_$(date +%Y-%m-%d_%H-%M-%S).md
frontmatter:
  type: cached_search
  timestamp: $(date -Iseconds)
  classification: search_intelligence
  ml_labels: [cache_efficiency, search_optimization, knowledge_reuse]
  success_metrics: [cache_hit_rate, response_time, api_savings]
  cross_references: [search_patterns, cache_strategies, intelligence_systems]
```

**Redundant Storage with Intelligent Classification:**
- **Primary**: `smart_memory_unified` - Unified orchestration with automatic content classification
- **Secondary**: `chroma-rag` - Vector embeddings for search pattern matching and query similarity
- **Tertiary**: `sqlite` - Structured metrics with ML training labels and effectiveness scoring
- **Quaternary**: `Knowledge/` files - Persistent markdown with consistent frontmatter metadata

**ML Training Data Structure:**
```json
{
  "cached_search_session": {
    "timestamp": "$(date -Iseconds)",
    "features": {
      "cache_hit_rate": 0.78,
      "search_optimization_score": 0.85,
      "query_complexity": 0.72,
      "knowledge_reuse_effectiveness": 0.88
    },
    "outcomes": {
      "search_efficiency": 0.87,
      "api_call_reduction": 0.80,
      "response_time_improvement": 0.75
    },
    "classification_labels": ["efficient_cache", "optimized_search", "intelligent_reuse"],
    "success_probability": 0.85
  }
}
```

**Cross-System Synchronization:**
- **chroma-rag**: Create semantic embeddings for search patterns and query optimization
- **smart_memory_unified**: Store search methodologies with automatic classification routing
- **sqlite**: Track search metrics and cache correlations for ML model training
- **Knowledge/patterns/**: Archive successful search patterns with effectiveness scoring

**EXECUTE FOR ANY SEARCH:** Use `/cached_websearch_10x` instead of `websearch` in ALL 10X commands for intelligent caching, dramatically improved performance, and ML training preparation.