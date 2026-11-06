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
    /* Dark Theme Accent Polish */
    .stApp {
        background-color: #0e1117;
    }
    
    /* Custom Flaw & Crash Containers */
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

    "Syntax Error": """def check_score(score)
    if score > 50
        print("Pass")""",

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
# Core Analysis Engine
# ------------------------------------------------------------------------------
def analyze_ast_flaws(code_str):
    """Performs static analysis using Python AST to catch syntax errors and anti-patterns."""
    flaws = []
    try:
        tree = ast.parse(code_str)
    except SyntaxError as e:
        return [{
            "type": "Syntax Error",
            "line": e.lineno,
            "message": e.msg,
            "explanation": "Python cannot parse this code grammatically because it breaks language syntax rules.",
            "analogy": "🚨 **Analogy:** Like ending a sentence mid-word without punctuation.",
            "fix": "Check for missing colons (`:`), unmatched brackets, or typos near this line."
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
            if
