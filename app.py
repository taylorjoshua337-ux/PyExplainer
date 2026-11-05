import streamlit as st
import ast
import traceback
import sys
import io

st.set_page_config(page_title="PyExplain - Code Flaw Finder", layout="wide")

st.title("🐍 PyExplain: Python Error & Flaw Explainer")
st.write("Paste your Python code below to analyze static AST flaws, catch runtime errors, and view suggested fixes.")

# Sample input containing both an AST anti-pattern (range(len)) and a runtime error (ZeroDivisionError)
code_input = st.text_area(
    "Source Code:", 
    height=260, 
    value="""def calculate_average(numbers):
    try:
        total = 0
        for i in range(len(numbers)):
            total += numbers[i]
        return total / len(numbers)
    except:
        pass

# Test with an empty list
print(calculate_average([]))"""
)

def analyze_ast_flaws(code_str):
    """Performs static analysis using Python AST to catch syntax errors and anti-patterns."""
    flaws = []
    try:
        tree = ast.parse(code_str)
    except SyntaxError as e:
        return [{
            "type": "SyntaxError",
            "line": e.lineno,
            "message": e.msg,
            "explanation": "Python cannot parse this code grammatically.",
            "fix": "Check for missing colons (`:`), unmatched brackets, or typos near this line."
        }], None

    for node in ast.walk(tree):
        # 1. Catch bare except clauses
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            flaws.append({
                "type": "Bare Except Clause",
                "line": node.lineno,
                "message": "Catching all exceptions indiscriminately with `except:`",
                "explanation": "Bare except clauses hide critical bugs and system interruptions (like Ctrl+C).",
                "fix": "Specify explicit exceptions, e.g., `except (ZeroDivisionError, TypeError):`."
            })
        
        # 2. Catch range(len(...)) loop anti-patterns
        elif isinstance(node, ast.For) and isinstance(node.iter, ast.Call):
            func = getattr(node.iter.func, 'id', None)
            if func == 'range' and len(node.iter.args) == 1:
                arg = node.iter.args[0]
                if isinstance(arg, ast.Call) and getattr(arg.func, 'id', None) == 'len':
                    flaws.append({
                        "type": "Non-Pythonic Loop",
                        "line": node.lineno,
                        "message": "Unnecessary `for i in range(len(...))` pattern.",
                        "explanation": "Iterating over index ranges is less readable and slower than direct iteration in Python.",
                        "fix": "Iterate directly over elements: `for item in sequence:` or use `for index, item in enumerate(sequence):`."
                    })

    return flaws, tree


if st.button("Run & Analyze Code", type="primary"):
    st.divider()
    
    ast_flaws, parsed_tree = analyze_ast_flaws(code_input)
    
    # Block execution if a SyntaxError exists
    if ast_flaws and ast_flaws[0]["type"] == "SyntaxError":
        err = ast_flaws[0]
        col1, col2 = st.columns(2)
        with col1:
            st.error(f"❌ **Syntax Error on Line {err['line']}**")
            st.code(err["message"])
        with col2:
            st.warning(f"**Why it failed:** {err['explanation']}")
            st.info(f"💡 **Suggested Fix:** {err['fix']}")
        st.stop()

    col1, col2 = st.columns(2)

    # Execute code in isolated stdout buffer
    output_buffer = io.StringIO()
    sys.stdout = output_buffer
    runtime_error = None

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
                "Add a guard clause: `if not numbers: return 0` before performing division."
            ),
            "IndexError": (
                "Attempted to access a sequence index position that does not exist.",
                "Check sequence boundaries or verify length using `if index < len(sequence):`."
            ),
            "KeyError": (
                "Attempted to access a dictionary key that does not exist.",
                "Use `dict.get('key', default_value)` or verify key existence with `if key in dict:`."
            ),
            "TypeError": (
                "Operation attempted on incompatible data types.",
                "Explicitly convert variable types using `int()`, `str()`, or `float()` before combining."
            ),
            "NameError": (
                "Referenced a variable or function name before it was defined.",
                "Ensure variables are instantiated in the current scope prior to referencing."
            )
        }
        
        reasoning, fix_suggestion = runtime_fixes.get(
            exc_name, 
            (f"An unexpected {exc_name} occurred: {exc}", "Review inputs and call stacks for type mismatches.")
        )
        
        runtime_error = {
            "type": f"Runtime Crash: {exc_name}",
            "line": error_line,
            "message": str(exc),
            "explanation": reasoning,
            "fix": fix_suggestion
        }

    # Left Column: Execution Console Output
    with col1:
        st.subheader("Console Output")
        if runtime_error:
            st.error(f"💥 **{runtime_error['type']}** (Line {runtime_error['line']})")
            st.text_area("Output before crash:", output_buffer.getvalue(), height=130)
        else:
            st.success("✅ **Execution Completed Successfully**")
            st.text_area("Output:", output_buffer.getvalue(), height=130)

    # Right Column: AST Static Flaws & Suggested Fixes
    with col2:
        st.subheader("Code Analysis & Suggested Fixes")
        
        if ast_flaws:
            st.markdown("#### ⚠️ Static AST Warnings")
            for flaw in ast_flaws:
                st.warning(f"**[{flaw['type']}] Line {flaw['line']}:** {flaw['message']}")
                st.write(f"**Why:** {flaw['explanation']}")
                st.info(f"💡 **Fix:** {flaw['fix']}")
                st.markdown("---")

        if runtime_error:
            st.markdown("#### 💥 Runtime Crash Analysis")
            st.warning(f"**Error Message:** `{runtime_error['message']}`")
            st.write(f"**Why:** {runtime_error['explanation']}")
            st.info(f"💡 **Fix:** {runtime_error['fix']}")

        if not ast_flaws and not runtime_error:
            st.info("🎉 No static AST anti-patterns or runtime crashes detected!")