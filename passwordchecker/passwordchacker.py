import argparse
import getpass
import re
import math
import sys
from colorama import Fore, Style
import colorama # For colored terminal output

class PasswordStrengthAssessor:
    
    def __init__(self):
        self.min_length = 8
        self.special_chars = r'[!@#$%^&*()_+\-=\[\]{}|;:\'",./<>?]'
    
    def check_criteria(self, password):

        if not password:
            return {
                'has_length': False,
                'length': 0,
                'has_upper': False,
                'has_lower': False,
                'has_number': False,
                'has_special': False,
                'suggestions': ['Password cannot be empty.']
            }
        
        criteria = {
            'has_length': len(password) >= self.min_length,
            'length': len(password),
            'has_upper': bool(re.search(r'[A-Z]', password)),
            'has_lower': bool(re.search(r'[a-z]', password)),
            'has_number': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(self.special_chars, password)),
            'suggestions': []
        }
        
        # Generate suggestions
        if not criteria['has_length']:
            criteria['suggestions'].append(f"Use at least {self.min_length} characters.")
        if len(password) < 12:
            criteria['suggestions'].append("Consider 12+ characters for better strength.")
        if not criteria['has_upper']:
            criteria['suggestions'].append("Include at least one uppercase letter (A-Z).")
        if not criteria['has_lower']:
            criteria['suggestions'].append("Include at least one lowercase letter (a-z).")
        if not criteria['has_number']:
            criteria['suggestions'].append("Include at least one number (0-9).")
        if not criteria['has_special']:
            criteria['suggestions'].append("Include at least one special character (e.g., !@#$%).")
        
        if not criteria['suggestions']:
            criteria['suggestions'].append("Great! Your password meets all basic criteria.")
        
        return criteria
    
    def calculate_score(self, criteria):

        score = 0
        
        # Length scoring
        length = criteria['length']
        if length >= 12:
            score += 30
        elif length >= 8:
            score += 20
        elif length >= 6:
            score += 10
        # Shorter than 6 gets 0 for length
        
        # Variety scoring (4 categories, max 70 points)
        variety_count = sum([
            criteria['has_upper'],
            criteria['has_lower'],
            criteria['has_number'],
            criteria['has_special']
        ])
        score += variety_count * 17.5
        
        return min(int(score), 100)  # Cap at 100
    
    def calculate_entropy(self, password):

        if not password:
            return 0.0

        charset_sizes = {
            'lower': 26,
            'upper': 26,
            'digits': 10,
            'special': 32  # Approximate for common specials
        }

        # Detect used charsets
        used_charsets = set()
        if re.search(r'[a-z]', password):
            used_charsets.add('lower')
        if re.search(r'[A-Z]', password):
            used_charsets.add('upper')
        if re.search(r'\d', password):
            used_charsets.add('digits')
        if re.search(self.special_chars, password):
            used_charsets.add('special')

        if not used_charsets:
            return 0.0

        # Effective charset size (product of sizes, but simplified to average for estimation)
        effective_size = math.prod([charset_sizes[cs] for cs in used_charsets]) ** (1 / len(used_charsets))
        entropy = len(password) * math.log2(effective_size)

        return round(entropy, 2)

    def calculate_cracking_time(self, entropy):
        """
        Estimate the time to crack the password via brute-force.
        Assumes 10^10 guesses per second (high-end GPU/ASIC).
        Returns a human-readable string.
        """
        if entropy == 0:
            return "Instantly (no entropy)"

        guesses = 2 ** entropy
        guesses_per_second = 10**10  # Adjustable: e.g., 10^9 for CPU, 10^12 for supercomputer
        time_seconds = guesses / guesses_per_second

        # Convert to human-readable time
        seconds_in_year = 365.25 * 24 * 3600
        seconds_in_day = 24 * 3600
        seconds_in_hour = 3600
        seconds_in_minute = 60

        if time_seconds < seconds_in_minute:
            return f"{time_seconds:.2f} seconds"
        elif time_seconds < seconds_in_hour:
            minutes = time_seconds / seconds_in_minute
            return f"{minutes:.2f} minutes"
        elif time_seconds < seconds_in_day:
            hours = time_seconds / seconds_in_hour
            return f"{hours:.2f} hours"
        elif time_seconds < seconds_in_year:
            days = time_seconds / seconds_in_day
            return f"{days:.2f} days"
        else:
            years = time_seconds / seconds_in_year
            return f"{years:.2f} years"
    
    def get_strength_level(self, score):
        
        if score >= 90:
            return "Very Strong", "Excellent password! Highly resistant to brute-force attacks."
        elif score >= 70:
            return "Strong", "Good password. Meets most security recommendations."
        elif score >= 40:
            return "Medium", "Moderate strength. Consider improvements for better security."
        else:
            return "Weak", "Weak password. Vulnerable to common attacks—please strengthen it."
    
    def assess(self, password):

        criteria = self.check_criteria(password)
        score = self.calculate_score(criteria)
        entropy = self.calculate_entropy(password)
        cracking_time = self.calculate_cracking_time(entropy)
        level, description = self.get_strength_level(score)

        return {
            'password_length': len(password),
            'score': score,
            'entropy_bits': entropy,
            'estimated_cracking_time': cracking_time,
            'level': level,
            'description': description,
            'criteria': criteria,
            'meets_all_criteria': all([
                criteria['has_length'],
                criteria['has_upper'],
                criteria['has_lower'],
                criteria['has_number'],
                criteria['has_special']
            ])
        }


def print_assessment(assessment):
    colorama.init(autoreset=True)
    print(Fore.LIGHTYELLOW_EX + "\n" + "="*60)
    print(Fore.RED + "       PASSWORD STRENGTH ASSESSMENT REPORT" + Style.RESET_ALL)
    print(Fore.LIGHTYELLOW_EX + "="*60)
    
    print(Fore.YELLOW + f"Password Length: {assessment['password_length']} characters" + Style.DIM)
    print(Fore.CYAN + f"Score: {assessment['score']}/100")
    print(Fore.LIGHTRED_EX + f"Estimated Entropy: {assessment['entropy_bits']} bits")
    print(Fore.MAGENTA + f"Estimated Cracking Time (Brute-Force): {assessment['estimated_cracking_time']}")
    print(Fore.LIGHTGREEN_EX + f"Strength Level: {assessment['level']}")
    print(Fore.LIGHTBLUE_EX + f"Description: {assessment['description']}")
    
    print(Fore.LIGHTMAGENTA_EX + "\nCriteria Check:" + Style.DIM)
    print(Fore.GREEN + f"  - Length (>= {PasswordStrengthAssessor().min_length}): {'✅' if assessment['criteria']['has_length'] else '❌'}" + Style.BRIGHT)
    print(Fore.GREEN + f"  - Uppercase Letters: {'✅' if assessment['criteria']['has_upper'] else '❌'}" + Style.BRIGHT)
    print(Fore.GREEN + f"  - Lowercase Letters: {'✅' if assessment['criteria']['has_lower'] else '❌'}" + Style.BRIGHT)
    print(Fore.GREEN + f"  - Numbers: {'✅' if assessment['criteria']['has_number'] else '❌'}" + Style.BRIGHT)
    print(Fore.GREEN + f"  - Special Characters: {'✅' if assessment['criteria']['has_special'] else '❌'}" + Style.BRIGHT)
    
    all_met = assessment['meets_all_criteria']
    print(Fore.CYAN + f"\nAll Basic Criteria Met: {'Yes' if all_met else 'No'}" + Style.DIM)
    
    print(Fore.YELLOW + "\nSuggestions for Improvement:" + Style.BRIGHT)
    for suggestion in assessment['criteria']['suggestions']:
        print(Fore.BLUE + f"  - {suggestion}" + Style.NORMAL)
    
    print(Fore.LIGHTYELLOW_EX + "\n" + "="*60 + Style.DIM)
    print("Tip: Use a password manager for complex, unique passwords per account.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Professional Password Strength Assessor",
        epilog="Run in interactive mode for secure password input (hidden from screen)."
    )
    parser.add_argument(
        '--password', '-p',
        help="Password to assess (visible in command line—use interactive mode for privacy)"
    )
    parser.add_argument(
        '--interactive', '-i', action='store_true',
        help="Interactive mode: Prompts for password (hidden input)"
    )
    
    args = parser.parse_args()
    
    # Determine password input method
    password = None
    if args.password:
        password = args.password
    elif args.interactive:
        try:
            password = getpass.getpass("Enter password to assess (hidden): ")
        except KeyboardInterrupt:
            print("\nAssessment cancelled.", file=sys.stderr)
            sys.exit(1)
    else:
        # Default to interactive if no args provided
        print("No password provided. Starting interactive mode...")
        try:
            password = getpass.getpass("Enter password to assess (hidden): ")
        except KeyboardInterrupt:
            print("\nAssessment cancelled.", file=sys.stderr)
            sys.exit(1)
    
    if not password:
        print("Error: No password provided.", file=sys.stderr)
        sys.exit(1)
    
    # Perform assessment
    assessor = PasswordStrengthAssessor()
    assessment = assessor.assess(password)
    
    # Output results
    print_assessment(assessment)


if __name__ == "__main__":
    main()
