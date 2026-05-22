# Eskil Steenberg Architectural Principles

Reference document for sustainable, long-lived system design.

## Core Philosophy

Software operates at multi-decade timescales. Systems must be designed to withstand 20-50 years of change, evolving requirements, platform shifts, and team turnover. Architecture and process are more important than domain knowledge.

## The Five Core Principles

### 1. Identify the Unifying Primitive

**Definition:** The primitive is the fundamental "thing" the system manipulates.

**Examples:**
- Unix: "Everything is a file"
- Video editors: "Everything is a clip on a timeline"
- Healthcare: "Everything is an event"
- Jet fighters: "State of the world"

**How to identify:**
- What does the system actually manipulate?
- What flows through the system?
- What do operations transform?

#### Primitive vs Structure: The Key Distinction

**Critical distinction:** Primitive (data type) ≠ Structure (how you process it)

- **Primitive (WHAT):** The fundamental data format flowing through the system
- **Structure (HOW):** The organizational pattern (layers, pipes, graphs, microservices)

**Key insight:** You can change structure without changing primitives, and vice versa.

**Examples:**
- Unix: text files (primitive) + command pipes (structure)
- Photoshop: bitmaps (primitive) + layers (structure)
- Nuke: bitmaps (primitive) + node graph (structure)
- Same primitive, different structures - both are valid

#### Six Characteristics of Good Primitives

A well-chosen primitive exhibits:

1. **Generality:** Represents many types without special cases
2. **Simplicity:** Easy to explain in one sentence
3. **Consistency:** Same operations work on all instances
4. **Completeness:** Represents everything in domain (no escape hatches)
5. **Implementability:** Efficient storage and processing (weekend test)
6. **Extensibility:** Plugins can add types without core changes

**Plugin validation test:** If adding a new type requires changing the core, your primitive isn't general enough.

#### The Multiple Primitives Problem

**Mathematical reality:**
- One primitive: 10 implementations × 1 primitive = 10 units of work
- Two primitives: 10 implementations × 2 primitives = 20 units of work

Every implementation must handle ALL primitives. Better to choose one and accept its limitations than support multiple and force everyone to implement both.

**Example:** "File format supports both polygons and NURBS" means everyone must implement both, even if they only need one.

#### Interaction Levels

Critical questions about your primitive:

- **Singular vs multiple:** One timeline or multiple timelines?
- **Nesting:** Can clips contain other clips? Can events reference events?
- **Relationships:** Are primitives isolated or connected?

**Balance:**
- Too few levels: Limiting, requires workarounds
- Too many levels: Complex traversal and understanding
- Just right: Natural domain representation

#### Code Examples

```python
# Healthcare: Events as the primitive
@dataclass
class Event:
    type: str
    when: datetime
    payload: dict

def schedule(events: list[Event], *, index_by="when"):
    # Structure is independent of primitive
    pass
```

```javascript
// Video editing: Clips as primitive, node-graph as structure
function blend(clipA, clipB, t) {
    // Nodes pass "clips"; structure is independent of clip internals
}
```

**Why it matters:** Choosing the wrong primitive means fighting your architecture forever.

### 2. Perfect APIs, Simple Implementations

**Principle:** Design the ideal, robust API from the start. Implementations can be simple placeholders.

**Key insights:**
- The API is a permanent contract
- The implementation is provisional
- APIs must be designed for 10+ years
- Include parameters for future features (even if unimplemented)

**Examples:**

```python
# Python: Text rendering API, simple now / rich later
def render_text(text, font="default", size=12, color=(0,0,0),
                max_width=None, encoding="utf-8"):
    return _bitmap_render(text)  # v1 simple; same signature supports richer v2
```

```java
// Java: Subset today, richer tomorrow
class TextRenderer {
    public Size render(String text, Font font, int start, int length) {
        return renderWhole(text, font); // start/length ignored for now
    }
}
```

```javascript
// JavaScript: Stable façade over evolving internals
export function getUserProfile(id, {locale="en-US"} = {}) {
    return simpleFetch(`/api/v1/users/${id}`); // same signature when v2 ships
}
```

```c
// V1 Implementation (2020): Simple bitmap font, ignores size parameter
// V2 Implementation (2025): TrueType fonts, honors size parameter
// API: Never changed, external code: Zero changes
int render_text(const char *utf8_text, int x, int y,
                FontHandle font, float size, Color color);
```

### 3. Write Code That Never Breaks

**Definition:** Code is "done" when it's permanent—you never need to look at it, modify it, or fix it again.

**Achieved through:**
- Stable API boundaries
- Proper isolation
- Black-box modules
- No shared code between modules
- No reaching into internals

**The Speed Bumps Problem:** Small breaking changes accumulate catastrophically. Each "trivial fix" forces context switching across the codebase.

**Goal:** Write five lines correctly today rather than write one line today and edit it repeatedly over decades.

### 4. Formats Are Everything

**Principle:** APIs, file formats, and protocols are the most critical, long-term contracts.

**The Weekend Test:** Can someone implement your format in a weekend?
- If NO → format is too complex
- Complexity inversely affects implementation quality

**Rules:**
- Keep formats dead simple
- Pick ONE approach (not multiple)
- Consider both producer AND consumer burden
- Version carefully
- Backward compatibility is mandatory
- Separate semantics from structure
- Don't expose storage engines in public APIs

**Why critical:** Formats outlive implementations. A format chosen today may be in use for 30+ years.

#### Semantics vs Structure: A Critical Separation

Your format has two independent aspects:

**Semantics (WHAT):** What the data means
- Domain-specific knowledge
- Example: "Healthcare events with timestamp, patient, type, data"
- Requires domain expertise to understand
- Changes rarely (core domain concepts are stable)

**Structure (HOW):** How the data is encoded
- Technical implementation detail
- Example: "JSON over REST" or "Protocol Buffers over gRPC" or "SQL queries"
- Anyone can parse with the right library
- Can change without affecting semantics

**Why separate:**
- Can change structure (JSON → Protobuf) without changing semantics
- Parsing code is reusable across domains
- Domain knowledge isolated to semantics layer
- Implementation flexibility preserved
- Technology evolution doesn't break domain model

**Bad:** Complex structure AND complex semantics (neither aspect is reusable)
**Good:** Simple structure (JSON), rich semantics (healthcare events)

#### Examples

```python
# Structure vs semantics
data = json.loads('{"temp": 23, "unit": "C"}')  # structure (JSON)
toF = lambda c: c*9/5 + 32                       # semantics (domain logic)

# Don't expose storage engines
class Events:
    def get_between(self, start, end):
        # Callers never send SQL; you can replatform freely
        pass
```

**Practical application:**
```python
# Semantics: Healthcare events (stable)
@dataclass
class HealthcareEvent:
    timestamp: datetime
    patient_id: str
    event_type: str
    data: dict

# Structure: Can evolve independently
# v1: JSON files
# v2: SQL database
# v3: Protocol Buffers over gRPC
# Semantic model never changes
```

### 5. Wrap the Core

**Principle:** Build a system that others plug into, not a system that plugs into a larger framework.

**Strategy:**
- Keep third-party platform/UI/drawing technology behind your wrappers
- You control the enduring contract
- Suppliers remain swappable
- Never call external code directly from application

**Example:**

```javascript
// http-wrapper.js - Wrap external dependencies
import * as lib from "external-http-lib";
export const get  = (url, opts) => lib.request("GET", url, opts);
export const post = (url, body)  => lib.request("POST", url, {body});
```

**Benefits:**
- Vendor independence
- Platform portability
- Technology evolution resilience
- Maintain control over your system

## Six Non-Negotiable Design Rules

### 1. WRAP THE PLATFORM

**Requirement:** Isolate OS/hardware/language dependencies behind wrappers

**Why:** Platforms change constantly
- OS APIs evolve
- Languages update
- Hardware changes
- Runtime environments shift

**How:**
- Create platform wrapper layer
- Abstract file I/O, threading, windowing, GPU access
- Application never imports platform APIs directly
- Maintain a tiny demo that uses only the wrapper; port it first when targeting new platforms to validate the layer before moving the full product

### 2. MODULES ARE BLACK BOXES

**Requirement:** Communication only via stable APIs

**Verification:**
- Can module be completely rewritten without breaking dependents?
- Do users need to understand implementation? (should be NO)
- Is internal state completely hidden?

**Examples:**

```java
// Java: Private fields + read-only view
public final class Timeline {
    private final List<Clip> clips = new ArrayList<>();
    public List<Clip> getClips() {
        return Collections.unmodifiableList(clips);
    }
}
```

```python
# Python: Opaque handle pattern
class _Conn:
    pass  # internal details

_registry = {}

def open_connection(dsn) -> str:
    h = uuid4().hex
    _registry[h] = _Conn(dsn)
    return h  # callers hold a token, not the object
```

**Benefits:**
- Developer leaves → module can be rewritten
- Code rots → module can be replaced
- Better approach discovered → module can be swapped

### 3. PERFECT APIS, SIMPLE IMPLEMENTATIONS

**Requirement:** APIs permanent, implementations provisional

**Design approach:**
- Think 10+ years forward
- Include future parameters
- Return values future callers will need
- Document contracts, not implementation
- Prefer explicit names over clever overloading
- Make invalid use impossible

**API Design: Clarity > Cleverness**

```java
// Prefer explicit names
Money multiplyByScalar(double factor);
Money elementwiseMultiply(Money other);

// Over ambiguous overloads
Money multiply(Money orScalar); // confusing
```

```python
# Searchable formatting - spaces aid grep
total_count = items_count + extras  # can grep for "total_count ="
```

**Make APIs that cannot be misused:**

```java
// Java: Fail fast in debug, handle gracefully in release
public void setRange(int start, int end) {
    if (DEBUG && start > end)
        throw new IllegalArgumentException("start > end");
    this.start = Math.min(start, end);
    this.end   = Math.max(start, end);
}
```

```python
# Python: Assert with actionable message
def resize(width, height):
    assert width > 0 and height > 0, "Dimensions must be positive"
```

### 4. LAYERED ARCHITECTURE

**Requirement:** One-way dependencies, no layer skipping

**Standard layers:**
```
Application Core
    ↓
UI Abstraction Layer
    ↓
Service Abstraction Layer
    ↓
Platform Wrapper Layer
    ↓
External Dependencies (NEVER CALLED DIRECTLY)
```

**Rules:**
- Layer N only calls layer N-1
- No circular dependencies
- Changes propagate down, never sideways

### 5. MINIMAL CORE, EXTENSIBLE VIA PLUGINS

**Requirement:** Features via plugins, not core bloat

**Plugin approach:**
- Self-describing (JSON with capabilities)
- Core generates UI/interfaces automatically
- Plugins cannot crash core
- Simple plugin format (weekend implementation test)
- Runtime discovery and dynamic linking

**Example:**

```javascript
// JavaScript: Plugin descriptor
export const colorCorrection = {
    name: "Color Correction",
    kind: "effect",
    inputs: [{name:"clip", type:"clip"}],
    params: [{name:"exposure", type:"number", default:0}],
    factory: () => ({
        process({clip}, {exposure}) {
            /* ... */
        }
    })
};
```

```python
# Python: Plugin registry
_plugins = {}

def register(name, descriptor):
    _plugins[name] = descriptor

def create(name, **kw):
    return _plugins[name]["factory"](**kw)
```

### 6. MIGRATE, DON'T "CUT OVER"

**Requirement:** Parallel operation, gradual transition

**Migration phases:**
1. Event bus / sync infrastructure
2. Glue code (shadow mode)
3. First new module
4. Verify parity
5. Gradual traffic shift (1% → 100%)
6. Soak period
7. Decommission legacy

**Glue & Migration Pattern:**
Run old and new systems side by side; build glue that mirrors writes and reads across both to enable gradual migration instead of big-bang cutovers.

**Never:** Big-bang cutover, "flag day" replacement

## Data & Memory Patterns

### 1. Don't Store Derived Data

**Principle:** If a value can be computed from source fields, compute it on demand to avoid inconsistency.

**Examples:**

```javascript
// JavaScript: Computed property
class Rectangle {
    constructor(w, h) { this.w = w; this.h = h; }
    get area() { return this.w * this.h; }
}
```

```python
# Python: Property decorator
@dataclass
class Cart:
    items: list[float]

    @property
    def total(self):
        return sum(self.items)
```

### 2. Favor Contiguous Data for Locality

**Principle:** Prefer arrays (vectors) over pointer-chasing structures for iteration performance; grow arrays by doubling or by blocks; delete by swap when order doesn't matter.

**Examples:**

```java
// Java: ArrayList vs LinkedList
var a = new ArrayList<Foo>(); // iteration is cache-friendly
// Prefer over: new LinkedList<Foo>() when iterating often
```

```python
# Python: Amortized append + swap delete
arr.append(x)                    # amortized resize
arr[i] = arr[-1]; arr.pop()      # O(1) remove without preserving order
```

### 3. Add "Stride" to Data-Processing APIs

**Principle:** Accept layout differences (e.g., RGB vs RGBA vs struct fields) by taking a stride parameter (or projection function) instead of forcing a specific layout.

**Examples:**

```python
# Python: Stride parameter
def adjust_brightness(buf: bytes, count: int, stride: int):  # stride = bytes/pixel
    for i in range(0, count*stride, stride):
        pass
```

```javascript
// JavaScript: Projection function instead of stride
function forEachPixel(items, pickRGB) {  // pickRGB maps item -> [r,g,b]
    for (const item of items) {
        const [r,g,b] = pickRGB(item);
        /* ... */
    }
}
```

### 4. Use Stable IDs Over Raw References

**Principle:** Favor indices/IDs that are easy to log/compare; choose sentinels and types that turn silent misuse into loud failures during development.

**Examples:**

```javascript
// JavaScript: ID-based lookup with validation
const objects = new Map(); // id -> object

function get(id) {
    if (!objects.has(id)) throw new Error("Invalid id");
    return objects.get(id);
}
```

```python
# Python: Index validation
def get_row(rows: list, idx: int):
    if idx < 0 or idx >= len(rows):
        raise IndexError("row out of range")
    return rows[idx]
```

**Opaque handle boundary pattern:**

```javascript
// JavaScript: Complete encapsulation
const table = new Map(); // id -> object

export const create = (data) => {
    const id = crypto.randomUUID();
    table.set(id, {...data});
    return id;
};

export const update = (id, patch) => {
    if (!table.has(id)) throw new Error("bad id");
    Object.assign(table.get(id), patch);
};
```

## Debuggability-First Engineering

### 1. Separate Debug Behavior from Release Behavior

**Principle:** Debug builds should fail fast with rich diagnostics; release builds should do the least surprising, user-friendly thing. Keep debug toggles independent from compiler settings/optimizations.

**Examples:**

```python
# Python: Environment-based debug flag
DEBUG = bool(int(os.getenv("APP_DEBUG", "0")))

def validate_timeline(tl):
    if not DEBUG: return
    assert tl.clips is not None and all(c.duration > 0 for c in tl.clips)
```

```java
// Java: System property debug flag
public static final boolean DEBUG = Boolean.getBoolean("app.debug");
```

### 2. Instrument APIs with File/Line and Validation

**Principle:** Use macros/wrappers (or language features) to log where calls happened (`__FILE__`/`__LINE__` in C; decorators/aspects elsewhere). Include validators you can call before/after operations to pinpoint corruption early.

**Examples:**

```python
# Python: Decorator for tracing
def trace(fn):
    def wrap(*a, **k):
        print(f"{fn.__name__} called")
        return fn(*a, **k)
    return wrap
```

```java
// Java: Assert with debug guards
void addClip(Clip c) {
    if (DEBUG) assert c.start >= 0 : "Negative start";
    clips.add(c);
}
```

### 3. Determinism, Recording & Playback

**Principle:** Make flows deterministic when possible; record inputs so you can replay bugs and share repros. Build small loggers, validators, visualizers; they won't ship but they unlock velocity.

**Example:**

```java
// Java: Record/playback harness
record InputEvent(String type, long t, Map<String,Object> payload) {}

class Recorder {
    void write(InputEvent e) { /* ... */ }
    List<InputEvent> read(File f) { /* ... */ }
}
```

### 4. Turn Subtle Bugs into Loud Ones

**Strategies:**
- Customize warnings (don't blanket "warnings as errors"); promote warnings that matter for your codebase
- Avoid zero-initializing in debug if it hides mistakes; prefer sentinel patterns that crash immediately on misuse
- Use guard pages/page heap to catch overruns/underruns during testing (OS tools or allocators that place no-access pages next to allocations)
- Add magic markers to serialized streams in debug builds to detect off-by-N read/write early

**Why:** Crashes with great diagnostics get fixed; silent misbehavior lingers.

### 5. Tests: Be Selective and Strategic

**Principle:** Prefer tests where usage doesn't naturally exercise code (e.g., parsers, complex algorithms) and for third-party dependencies that can break you; don't chase coverage for its own sake.

**Strategic focus areas:**
- Parsers and serializers
- Complex algorithms
- Third-party integration points
- Error handling paths
- API contract validation

## Tooling & Developer Experience

**Principle:** Invest heavily in non-shipping tools: loggers, validators, visualizers, record/playback harnesses, simulators. This often rivals product code in size and is essential for velocity and reliability.

**Critical tools to build:**
- **Loggers**: Capture file/line, stack traces, timing
- **Validators**: Call before/after operations to detect corruption
- **Visualizers**: Display internal state graphically
- **Record/playback**: Capture and replay bugs deterministically
- **Simulators**: Test under varied conditions without real hardware
- **Documentation generators**: Keep API docs synchronized
- **Single-header facades**: Present clean public surface

**Example from practice:** Using macros to wrap allocation with file/line and to add debug headers enables leak reports and bounds checks with precise call-site blame.

**Why this matters:** These tools won't ship, but they enable:
- Faster bug diagnosis
- Reproducible issues
- Confident refactoring
- Knowledge transfer when team changes
- Multi-decade maintainability

## Architectural Process (6 Steps)

### Step 1: Identify the Primitive

**Questions to answer:**
- What is the system manipulating?
- What flows through the system?
- What do operations transform?

**Process:**
1. List 3-5 alternative primitives
2. SWOT analysis for each alternative
3. Evaluate against six characteristics:
   - Generality (reduces special cases)
   - Simplicity (easy to understand/implement)
   - Consistency (same operations on all instances)
   - Completeness (represents everything needed)
   - Implementability (efficient storage/processing)
   - Extensibility (plugins without core changes)
4. Test with plugin scenarios: Can new types be added without core changes?
5. Test interaction levels: How many instances interact? Nesting? Relationships?
6. Choose ONE and commit
7. Document trade-offs accepted

**Validation example (video editor):**
```
Video editor primitives test:
- Video clip → Yes (clip)
- Audio clip → Yes (clip)
- Title → Yes (clip)
- Transition → Yes (clip)
- Effect → Yes (clip with parameters)
- Nested sequence → Yes (clip containing clips)

All cases work → "clip" is sufficiently general
```

**Critical:** Primitive (data type) ≠ Structure (how you process it)
- Unix: text files (primitive) + pipes (structure)
- Photoshop: bitmaps (primitive) + layers (structure)

**Red flags to avoid:**
- Need different APIs for different "types" of the same thing
- Special cases proliferating
- "This one works differently because..."

### Step 2: Define Core Formats & APIs
- Design data format for primitive (keep simple!)
- Design stable APIs (10+ year horizon)
- Create plugin/extension descriptor format
- Define versioning strategy
- Separate semantics from structure
- Hide storage implementation details

### Step 3: Define Layers & Wrappers
- Identify required layers
- Define platform wrapper
- Specify layer responsibilities
- Document layer interaction rules

### Step 4: Identify Modules
- List all required modules (500-5000 lines each)
- Define purpose, API, dependencies, ownership
- Verify module independence
- Create dependency graph
- One person per module

### Step 5: Define Migration & Tooling Strategy
- Plan safe migration (if replacing legacy)
- Design record/playback system
- Create format validators
- Build simulation tools
- Define debug vs release behavior

### Step 6: Ground in Examples & Reasoning
- Provide concrete examples
- Document reasoning for major decisions
- Verify against principles
- Acknowledge trade-offs

## Team & Process Practices

- **Show finished, not hacked prototypes**. Avoid teaching stakeholders unrealistic timelines; finish the underlying work before demos.
- **Fix it now**. The cost to clean code doesn't get cheaper; refactor as soon as the design wants it.
- **Module ownership**. Assign seniors to hard modules; juniors to simpler modules; one owner per module.
- **"Build the mountain."** Build reusable foundations (platform, UI, storage, networking) so future products are "small houses on a big mountain."
- **Team scalability through module sizing**: Design so one person can own and implement a module; coordinate on API design, not internals.

## Quick Decision Checklist

Before finalizing any architectural decision:

- [ ] Does it isolate volatility behind wrappers you control?
- [ ] Is the API simpler than the implementation?
- [ ] Can a module be completely rewritten without breaking dependents?
- [ ] Is the format dead simple to implement (weekend test)?
- [ ] Does it enable autonomous team ownership?
- [ ] Will this still be maintainable in 10 years?

## Primitive Evaluation Checklist

When evaluating a potential primitive for your system:

### Capability
- [ ] Can it represent all current features?
- [ ] Can it represent likely future features?
- [ ] Can plugins add new types without core changes?
- [ ] Does it naturally support the domain's operations?

### Simplicity
- [ ] Can I explain it in one sentence?
- [ ] Is it simple enough to implement correctly (weekend test)?
- [ ] Are basic operations obvious?
- [ ] Can a new team member understand it quickly?

### Cleanliness
- [ ] Does it avoid multiple competing representations?
- [ ] Is the API implementation-independent?
- [ ] Does it avoid exposing storage details?
- [ ] Is it general enough to avoid special cases?
- [ ] Does it capture the essence of the domain?
- [ ] Does it clearly separate from structure (how vs what)?

### Red Flags (Warning Signs of Bad Primitive Choice)
- ⚠️ "We support both X and Y formats"
- ⚠️ "This is a special case that works differently"
- ⚠️ "Some types have this property, others don't"
- ⚠️ "This requires converting between formats"
- ⚠️ "Only experts can implement this correctly"
- ⚠️ "We'll add a flag for that edge case"
- ⚠️ "You can access it via SQL if you need to"

### Success Indicators (Signs You Chose Well)
- ✓ New features fit naturally into existing primitive
- ✓ Plugins are easy to write
- ✓ Testing is straightforward
- ✓ Users understand the model quickly
- ✓ Documentation is concise
- ✓ Special cases are rare
- ✓ Implementation can be replaced without API changes
- ✓ Different structures can use same primitive

## Module Design Checklist

- [ ] API documented clearly (users can work from docs alone)
- [ ] API stable (designed for 10+ years)
- [ ] Implementation hidden (opaque types, internal functions static)
- [ ] No shared code with other modules
- [ ] No reaching into other module internals
- [ ] Module size reasonable (500-5000 lines)
- [ ] Single ownership assigned
- [ ] Test suite covers API contracts
- [ ] Can be rewritten without breaking external code

## Format Design Checklist

- [ ] Weekend implementation test passes
- [ ] Simple enough for human readability (if text format)
- [ ] Versioning strategy defined
- [ ] Backward compatibility plan exists
- [ ] Both producer AND consumer burden considered
- [ ] Only ONE approach supported (not multiple alternatives)
- [ ] Future extensibility considered
- [ ] Validation tools specified
- [ ] Semantics separated from structure
- [ ] Storage engines hidden from public API

## Layer Architecture Checklist

- [ ] Application core never imports external libraries directly
- [ ] Each external service has an adapter interface
- [ ] Adapters are swappable via configuration
- [ ] Platform-specific code isolated to platform wrapper
- [ ] Dependencies only flow downward (never up or sideways)
- [ ] UI components wrapped for potential framework migration
- [ ] Each adapter has at least 2 implementations (prod + dev/mock)
- [ ] Switching providers requires only config change, no code changes

## Debuggability Checklist

- [ ] Debug vs release behavior clearly separated
- [ ] APIs instrumented with file/line tracking
- [ ] Validation hooks can be called before/after operations
- [ ] Record/playback capability for reproducing bugs
- [ ] Deterministic execution where possible
- [ ] Sentinel patterns used to catch misuse early
- [ ] Custom warnings configured for project-specific issues
- [ ] Strategic tests focus on high-risk areas

## Common Anti-Patterns to Avoid

### 1. Fighting the Primitive
**Symptom:** New features require workarounds, developers frustrated
**Fix:** Reconsider primitive choice or adjust structure

### 2. Leaky Abstractions
**Symptom:** Underlying library types exposed in wrapper APIs
**Fix:** Only expose your types, never third-party types

### 3. Shared Code Between Modules
**Symptom:** Changing one module breaks another
**Fix:** Duplicate code if needed for isolation (acceptable trade-off)

### 4. Reaching Into Internals
**Symptom:** External code accessing module internal state
**Fix:** Make types opaque, provide API methods

### 5. Complex Formats
**Symptom:** Takes weeks to implement format parser
**Fix:** Simplify format (weekend test), remove optionality

### 6. Direct External Dependencies
**Symptom:** Application imports AWS SDK, Stripe SDK, React directly
**Fix:** Create adapters, wrap all external code

### 7. Big-Bang Migration
**Symptom:** Planning "cutover weekend" to replace system
**Fix:** Parallel operation, gradual traffic shift

### 8. Skipping Layers
**Symptom:** Application calling platform APIs directly
**Fix:** Enforce layered dependencies

### 9. Clever Over Explicit
**Symptom:** Overloaded operators, magic methods, implicit conversions causing confusion
**Fix:** Use explicit, searchable names; prefer clarity to brevity

### 10. Storing Derived Data
**Symptom:** Inconsistencies between source and computed values
**Fix:** Compute on demand; eliminate cached/derived state

### 11. Too Abstract Primitive
**Symptom:** Primitive provides no domain-specific power
**Example:** "Everything is an object with properties" vs "Everything is a clip with time bounds and parameters"
**Fix:** Capture what's unique about the domain; abstract enough to generalize, specific enough to be useful

### 12. Too Specific Primitive
**Symptom:** Need different systems for similar things
**Example:** Separate systems for video clips, audio clips, effect clips
**Fix:** Find generalizing abstraction that covers all cases (all are "clips")

### 13. Confusing Structure with Primitive
**Symptom:** Describing "how" not "what"
**Example:** "We use microservices" (structure) without defining data format (primitive)
**Fix:** Define both explicitly; recognize they are independent concerns

### 14. Choosing Implementation as Primitive
**Symptom:** Primitive defined by technology choice
**Example:** "Our primitive is SQL tables" instead of "Our primitive is healthcare events, implemented using SQL"
**Fix:** Define semantic primitive independent of implementation; technology is a detail

## Why These Principles Matter

**Multi-decade timescales:**
- Video editors from 1980s still in production
- Healthcare systems: 20+ year lifecycles
- Jet fighter software: 50+ year operational life

**Maintenance cost dominates:**
- Initial development: tiny fraction of total cost
- 20-50 years of maintenance: majority of cost
- Optimizing for "ship faster now" at expense of sustainability is economically irrational

**Risk accumulation:**
- Platform changes compound
- Vendor lock-in multiplies
- Personnel turnover inevitable
- Requirements evolve constantly
- Architecture must systematically eliminate or isolate risks

## Opinionated Guidance

- **Long functions are not a sin** when they make temporal/state flow easy to see (e.g., a single render loop that owns and resets state in a clear order). Use them deliberately where sequential reasoning is paramount.
- **Avoid "clever" language features** that trade a few keystrokes for days of debugging; design for readability and predictable behavior.
- **Explicit failure beats hidden recovery in development**: crashes with great diagnostics get fixed; silent misbehavior lingers.
- **Reallocation is not a code smell**: Growing arrays by doubling or blocks is a feature, not a bug. Embrace contiguous memory.

## References

- Eskil Steenberg's architectural philosophy
- Applied in: Love (procedural MMO), Quel Solaar (3D tools)
- Real-world validation: Decades of production use

---

**Usage:** Reference this document when making architectural decisions. Apply principles systematically. Design for the long term.
