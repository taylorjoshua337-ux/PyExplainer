import streamlit as st
import ast
import traceback
import sys
import io

# Page Configuration
st.set_page_config(
    page_title="PyExplain - Python Flaw & Error Explainer",
    page_icon="🐍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for UI Polish & Card Styling
st.markdown("""
<style>
    .stApp {
        background-color: #0e1117;
    }
    .flaw-card {
        background-color: #1e222d;
        border-left: 5px solid #ffa726;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 16px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.2);
    }
    .crash-card {
        background-color: #2a1b20;
        border-left: 5px solid #ef5350;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 16px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.2);
    }
    .line-badge {
        background-color: #2c3240;
        color: #64b5f6;
        padding: 4px 10px;
        border-radius: 4px;
        font-family: monospace;
        font-size: 0.9em;
    }
</style>
""", unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# Sidebar: Code Presets & Info
# ------------------------------------------------------------------------------
st.sidebar.title("⚙️ Presets & Guidance")
st.sidebar.write("Load a pre-configured code sample to test different analyzer features:")

presets = {
    "Unclosed Try Block (Syntax Error)": """def calculate_average(numbers):
    try:
        total = sum(numbers)
        return total / len(numbers)

# Missing except or finally block!
print(calculate_average([10, 20]))""",

    "Non-Pythonic Loop & Silent Bug": """def calculate_average(numbers):
    try:
        total = 0
        for i in range(len(numbers)):
            total += numbers[i]
        return total / len(numbers)
    except:
        pass

# Test with an empty list
print(calculate_average([]))""",

    "Runtime Crash (ZeroDivisionError)": """def divide_budget(amount, people):
    return amount / people

# Test dividing by 0
print(divide_budget(100, 0))""",

    "Runtime Crash (IndexError)": """items = ["apple", "banana", "cherry"]

# Loop goes past array bounds
for i in range(5):
    print(items[i])""",

    "Clean Pythonic Code": """def calculate_average(numbers):
    if not numbers:
        return 0.0
    return sum(numbers) / len(numbers)

print(f"Average: {calculate_average([10, 20, 30])}")"""
}

selected_preset = st.sidebar.selectbox("Choose Code Example:", list(presets.keys()))
st.sidebar.divider()
st.sidebar.info(
    "💡 **Tip:** PyExplain uses static Abstract Syntax Trees (AST) to catch bad coding habits "
    "before running your code safely in a sandbox environment."
)

# ------------------------------------------------------------------------------
# Helper: Detailed Syntax Error Parser
# ------------------------------------------------------------------------------
def get_syntax_error_details(msg):
    """Maps Python SyntaxError messages to detailed explanations and code solutions."""
    msg_lower = msg.lower()
    
    if "expected 'except' or 'finally'" in msg_lower or "expected an indented block after 'try'" in msg_lower:
        return {
            "explanation": "You opened a `try:` block, but every `try:` block in Python MUST be immediately followed by at least one `except:` or `finally:` block. Python needs to know what code to execute if an error occurs inside the `try:` block.",
            "analogy": "🚪 **Analogy:** Starting a sentence with 'If something goes wrong...' but forgetting to write what to do when it actually goes wrong.",
            "before": "try:\n    total = sum(numbers)\n    return total / len(numbers)\n\n# Missing except or finally block!",
            "after": "try:\n    total = sum(numbers)\n    return total / len(numbers)\nexcept ZeroDivisionError:\n    return 0.0"
        }
    elif "expected ':'" in msg_lower:
        return {
            "explanation": "Python statement headers (like `if`, `def`, `for`, `while`, `try`, `except`) require a colon `:` at the end of the line to start a code block.",
            "analogy": "✍️ **Analogy:** Forgetting a punctuation mark at the end of a sentence header.",
            "before": "def calculate_average(numbers)",
            "after": "def calculate_average(numbers):"
        }
    elif "was never closed" in msg_lower or "unmatched" in msg_lower or "closing parenthesis" in msg_lower:
        return {
            "explanation": "A parenthesis `()`, bracket `[]`, or brace `{}` was opened but missing its closing pair on or before this line.",
            "analogy": "📦 **Analogy:** Opening a box to place items inside, but forgetting to tape it shut.",
            "before": "print(calculate_average(6)",
            "after": "print(calculate_average(6))"
        }
    elif "indented block" in msg_lower:
        return {
            "explanation": "Python relies on indentation (usually 4 spaces) to define code blocks. The code directly following a colon `:` must be indented.",
            "analogy": "📐 **Analogy:** Writing sub-bullet points without indenting them under their main header.",
            "before": "def greet():\nprint('Hello')",
            "after": "def greet():\n    print('Hello')"
        }
    else:
        return {
            "explanation": f"Python encountered invalid syntax: `{msg}`. This line breaks Python's grammatical parsing rules.",
            "analogy": "🚨 **Analogy:** Using invalid sentence structure that prevents the reader from understanding the statement.",
            "before": "# Review the line for typos, unexpected symbols, or unclosed string quotes",
            "after": "# Ensure clean syntax and matching colons/brackets"
        }

# ------------------------------------------------------------------------------
# Core Analysis Engine
# ------------------------------------------------------------------------------
def analyze_ast_flaws(code_str):
    """Performs static analysis using Python AST to catch syntax errors and anti-patterns."""
    flaws = []
    try:
        tree = ast.parse(code_str)
    except SyntaxError as e:
        details = get_syntax_error_details(e.msg)
        return [{
            "type": "Syntax Error",
            "line": e.lineno,
            "message": e.msg,
            "explanation": details["explanation"],
            "analogy": details["analogy"],
            "before": details["before"],
            "after": details["after"]
        }], None

    for node in ast.walk(tree):
        # 1. Detect bare except / silent error suppression
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            flaws.append({
                "type": "Silent Error Suppression",
                "line": node.lineno,
                "message": "Using `except:` (or `except: pass`) silently hides bugs.",
                "explanation": "Your code experienced an internal error, but `except:` hid the error and returned `None` instead of fixing the underlying problem.",
                "analogy": "🙈 **Analogy:** Silencing a fire alarm when you smell smoke instead of putting out the fire.",
                "before": "except:\n    pass",
                "after": "except ZeroDivisionError:\n    return 0.0  # Explicit error handling"
            })
        
        # 2. Detect range(len(...)) loop anti-pattern
        elif isinstance(node, ast.For) and isinstance(node.iter, ast.Call):
            func = getattr(node.iter.func, 'id', None)
            if func == 'range' and len(node.iter.args) == 1:
                arg = node.iter.args[0]
                if isinstance(arg, ast.Call) and getattr(arg.func, 'id', None) == 'len':
                    flaws.append({
                        "type": "Non-Pythonic Loop",
                        "line": node.lineno,
                        "message": "Unnecessary `for i in range(len(...))` pattern.",
                        "explanation": "Iterating over index ranges manually is less readable and slower than direct element iteration in Python.",
                        "analogy": "📋 **Analogy:** Looking up page numbers in an index to read a book page-by-page, instead of just reading the pages directly.",
                        "before": "for i in range(len(items)):\n    print(items[i])",
                        "after": "for item in items:\n    print(item)"
                    })

    return flaws, tree

# ------------------------------------------------------------------------------
# Main UI Layout
# ------------------------------------------------------------------------------
st.title("🐍 PyExplain: Python Error & Flaw Explainer")
st.write("Analyze code structure, catch static anti-patterns, and view plain-English runtime explanations.")

code_input = st.text_area(
    "Source Code:", 
    height=240, 
    value=presets[selected_preset]
)

if st.button("🚀 Run & Analyze Code", type="primary"):
    code_lines = code_input.split("\n")
    
    with st.spinner("Analyzing AST structure and running sandbox..."):
        ast_flaws, parsed_tree = analyze_ast_flaws(code_input)
        
        # Sandbox Execution
        output_buffer = io.StringIO()
        sys.stdout = output_buffer
        runtime_error = None
        
        # Skip execution if Syntax Error exists
        if not (ast_flaws and ast_flaws[0]["type"] == "Syntax Error"):
            try:
                execution_scope = {}
                exec(code_input, execution_scope)
                sys.stdout = sys.__stdout__
            except Exception as exc:
                sys.stdout = sys.__stdout__
                tb = traceback.extract_tb(sys.exc_info()[2])
                error_line = tb[-1].lineno if tb else "Unknown"
                
                exc_name = type(exc).__name__
                runtime_fixes = {
                    "ZeroDivisionError": (
                        "Attempted to divide a number by zero (`0`).",
                        "🍫 **Analogy:** Trying to divide 10 cookies among 0 friends. You cannot split something into zero groups.",
                        "if denominator == 0:\n    return 0\nreturn numerator / denominator"
                    ),
                    "IndexError": (
                        "Attempted to access an index position in a list that does not exist.",
                        "📖 **Analogy:** Looking for page 50 in a book that only has 10 pages.",
                        "if index < len(my_list):\n    item = my_list[index]"
                    ),
                    "KeyError": (
                        "Attempted to access a dictionary key that does not exist.",
                        "🔑 **Analogy:** Looking inside a labeled locker for a key tag that was never placed there.",
                        "value = my_dict.get('key', 'default_value')"
                    ),
                    "TypeError": (
                        "Operation attempted on incompatible data types.",
                        "🍎 **Analogy:** Trying to multiply a number by an apple (combining incompatible types).",
                        "result = str(number) + text"
                    )
                }
                
                reasoning, analogy, fix_code = runtime_fixes.get(
                    exc_name, 
                    (f"An unexpected {exc_name} occurred: {exc}", "⚠️ **Analogy:** System operation error.", "Review variables and data types.")
                )
                
                runtime_error = {
                    "type": exc_name,
                    "line": error_line,
                    "message": str(exc),
                    "explanation": reasoning,
                    "analogy": analogy,
                    "fix": fix_code
                }

    st.toast("Analysis completed!", icon="✅")
    st.divider()

    # --------------------------------------------------------------------------
    # 1. Top Metrics Summary Row
    # --------------------------------------------------------------------------
    has_syntax_err = ast_flaws and ast_flaws[0]["type"] == "Syntax Error"
    num_ast_flaws = len(ast_flaws) if ast_flaws else 0
    
    col_m1, col_m2, col_m3 = st.columns(3)
    
    with col_m1:
        st.metric("Static AST Flaws", f"{num_ast_flaws} Found" if not has_syntax_err else "Syntax Error")
    with col_m2:
        st.metric("Runtime Status", "💥 Crashed" if runtime_error else ("❌ Syntax Blocked" if has_syntax_err else "✅ Passed"))
    with col_m3:
        if has_syntax_err or runtime_error:
            st.metric("Code Health Grade", "F (Fix Required)")
        elif num_ast_flaws > 0:
            st.metric("Code Health Grade", "B (Refactor Needed)")
        else:
            st.metric("Code Health Grade", "A+ (Clean)")

    st.divider()

    # --------------------------------------------------------------------------
    # 2. Main Output Tabs
    # --------------------------------------------------------------------------
    tab_out, tab_ast, tab_runtime = st.tabs(["🚀 Console Output", "⚠️ AST Code Analysis", "💥 Runtime Debugger"])

    # --- TAB 1: Console Output ---
    with tab_out:
        st.subheader("Execution Output")
        out_text = output_buffer.getvalue()
        
        if has_syntax_err:
            st.error("Syntax Error detected. Code execution was safely blocked.")
        elif runtime_error:
            st.error(f"Execution crashed on Line {runtime_error['line']} with `{runtime_error['type']}`.")
            st.text_area("Console log before crash:", out_text if out_text else "[No console output produced]", height=160)
        else:
            st.success("Execution completed without runtime crashes.")
            st.text_area("Output Log:", out_text if out_text else "[Code executed successfully with no print output]", height=160)

    # --- TAB 2: AST Static Analysis ---
    with tab_ast:
        st.subheader("Static Code Quality & Anti-Patterns")
        
        if not ast_flaws:
            st.success("🎉 Excellent! No static code anti-patterns or syntax errors detected.")
        else:
            for flaw in ast_flaws:
                line_str = code_lines[flaw['line'] - 1].strip() if flaw.get('line') and flaw['line'] <= len(code_lines) else ""
                
                st.markdown(f"""
                <div class="flaw-card">
                    <span class="line-badge">Line {flaw['line']}</span> <strong>{flaw['type']}:</strong> <code>{line_str}</code>
                    <p style="margin-top: 10px; margin-bottom: 5px;">{flaw['message']}</p>
                </div>
                """, unsafe_allow_html=True)

                with st.expander(f"🔍 Deep Dive & Explanation (Line {flaw['line']})", expanded=True):
                    st.write(f"**Why this is an issue:** {flaw['explanation']}")
                    if flaw.get('analogy'):
                        st.info(flaw['analogy'])
                    
                    if flaw.get('before') and flaw.get('after'):
                        c1, c2 = st.columns(2)
                        with c1:
                            st.caption("❌ Avoid (Current Code)")
                            st.code(flaw['before'], language="python")
                        with c2:
                            st.caption("✅ Recommended Fix")
                            st.code(flaw['after'], language="python")
                    elif flaw.get('fix'):
                        st.success(f"💡 **Fix Suggestion:** {flaw['fix']}")

    # --- TAB 3: Runtime Debugger ---
    with tab_runtime:
        st.subheader("Runtime Exception Analysis")
        
        if not runtime_error:
            st.info("No runtime crashes recorded during execution.")
        else:
            err_line_str = code_lines[runtime_error['line'] - 1].strip() if isinstance(runtime_error['line'], int) and runtime_error['line'] <= len(code_lines) else ""
            
            st.markdown(f"""
            <div class="crash-card">
                <span class="line-badge">Line {runtime_error['line']}</span> <strong>{runtime_error['type']}:</strong> <code>{err_line_str}</code>
                <p style="margin-top: 10px; margin-bottom: 5px;">Error message: <code>{runtime_error['message']}</code></p>
            </div>
            """, unsafe_allow_html=True)
            
            st.write(f"**Why it crashed:** {runtime_error['explanation']}")
            st.info(runtime_error['analogy'])
            
            st.caption("✅ Suggested Code Fix")
            st.code(runtime_error['fix'], language="python")
