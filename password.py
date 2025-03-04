import streamlit as st
import re
import random
import string

# Blacklist of common weak passwords
COMMON_PASSWORDS = {
    "password", "123456", "qwerty", "admin", "letmein", 
    "welcome", "123abc", "password123", "abc123"
}

def check_password_strength(password):
    """
    Check password strength with detailed scoring and feedback.
    
    Scoring Criteria:
    - Length (1 point)
    - Uppercase & Lowercase (1 point)
    - Digit (1 point)
    - Special Character (1 point)
    - Complexity & Non-Common Password (1 point)
    """
    score = 0
    feedback = []
    
    # Length Check (8+ characters)
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Password should be at least 8 characters long.")
    
    # Uppercase & Lowercase Check
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("❌ Include both uppercase and lowercase letters.")
    
    # Digit Check
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("❌ Add at least one number (0-9).")
    
    # Special Character Check
    if re.search(r"[!@#$%^&*]", password):
        score += 1
    else:
        feedback.append("❌ Include at least one special character (!@#$%^&*).")
    
    # Additional Complexity & Non-Common Password Check
    if (len(password) >= 12 and 
        re.search(r"[A-Z]", password) and 
        re.search(r"[a-z]", password) and 
        re.search(r"\d", password) and 
        re.search(r"[!@#$%^&*]", password) and 
        password.lower() not in COMMON_PASSWORDS):
        score += 1
    
    # Determine Strength and Adjust Scoring
    if score == 5:
        strength = "Strong 💪"
        color = "limegreen"
    elif score >= 3:
        strength = "Moderate 😐"
        color = "gold"
    else:
        strength = "Weak 😟"
        color = "crimson"
    
    return score, strength, color, feedback

def generate_strong_password():
    """Generate a cryptographically strong password."""
    # Ensure at least one character from each required category
    uppercase = random.choice(string.ascii_uppercase)
    lowercase = random.choice(string.ascii_lowercase)
    digit = random.choice(string.digits)
    special = random.choice("!@#$%^&*")
    
    # Fill remaining length with random characters
    remaining_length = 12 - 4  # 4 characters already used
    remaining_chars = ''.join(random.choices(
        string.ascii_letters + string.digits + "!@#$%^&*", 
        k=remaining_length
    ))
    
    # Combine and shuffle
    password_chars = list(uppercase + lowercase + digit + special + remaining_chars)
    random.shuffle(password_chars)
    
    return ''.join(password_chars)

def main():
    # Streamlit Page Configuration
    st.set_page_config(
        page_title="Advanced Password Strength Meter", 
        page_icon="🔐", 
        layout="centered"
    )
    
    # Title and Description
    st.title("🔐 Password Strength Analyzer")
    st.markdown("""
    ### Secure Your Passwords! 
    Check your password's strength and get personalized security tips.
    """)
    
    # Password Input
    password = st.text_input(
        "Enter your password:", 
        type="password", 
        placeholder="Type a password to check its strength..."
    )
    
    # Strength Analysis
    if password:
        score, strength, color, feedback = check_password_strength(password)
        
        # Strength Display
        st.subheader("Password Strength:")
        st.markdown(f"<h2 style='color: {color};'>{strength}</h2>", unsafe_allow_html=True)
        
        # Score Display
        st.markdown(f"### Score: {score}/5")
        
        # Progress Bar
        st.progress(score / 5)
        
        # Feedback
        if feedback:
            st.subheader("Improvement Suggestions:")
            for suggestion in feedback:
                st.warning(suggestion)
        else:
            st.success("🎉 Excellent! Your password meets all security criteria.")
    
    # Password Generator Section
    st.subheader("🔑 Generate a Secure Password")
    if st.button("Generate Strong Password"):
        strong_password = generate_strong_password()
        st.code(strong_password, language="plaintext")
        st.success("Strong password generated! Copy and keep it safe.")
    
    # Footer
    st.markdown("---")
    st.info("Enhance your online security with strong, unique passwords.")

if __name__ == "__main__":
    main()