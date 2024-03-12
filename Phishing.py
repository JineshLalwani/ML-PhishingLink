import re

suspicious_links_regex = re.compile(r'(http|https)://[^\s]+', re.IGNORECASE)

uk = {'urgent', 'immediate', 'action required'}
si_k = {'password', 'username', 'social security number', 'credit card'}

def is_phishing(entry):
    if uk.intersection(entry.lower().split()):
        return True

    if si_k.intersection(entry.lower().split()):
        return True

    if suspicious_links_regex.search(entry):
        return True

    return False

d = [
    "Urgent! Your account needs immediate action.",
    "Please provide your password to proceed.",
    "Click here to claim your prize: https://notaphishinglink.com",
    "This is a legitimate message.",
    "Your account has been compromised. Click the link to reset your password.",
    "Your credit card information needs verification. Reply with your details.",
    "URGENT: Immediate action required to prevent account suspension.",
    "Congratulations! You've won a free trip. Click the link to claim your prize.",
    "Verify your account by clicking on the link in this email.",
    "Important: Your account will be locked if you don't update your password.",
    "Please confirm your identity by providing your social security number.",
    "Claim your reward now! Reply with your email and password.",
    "Your account has been suspended. Provide your credentials to reactivate.",
    "Action required: Update your payment information to continue using our service.",
    "You've been selected for a special offer. Click the link to redeem.",
    "Respond urgently to secure your account.",
    "Your account is at risk. Click the link to secure it now.",
    "Please ignore any emails asking for your personal information.",
    "Immediate attention required: Your account has been accessed from a new device.",
    "Activate two-factor authentication to enhance your account security."
]

for e in d:
    if is_phishing(e):
        print("Potential phishing attempt:", e)
    else:
        print("Not a phishing attempt:", e)
