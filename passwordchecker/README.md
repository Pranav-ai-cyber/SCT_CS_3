# Professional Password Strength Assessor

This tool evaluates the strength of a password based on multiple criteria:

- Length (minimum 8 characters recommended)
- Presence of uppercase letters (A-Z)
- Presence of lowercase letters (a-z)
- Presence of numbers (0-9)
- Presence of special characters (e.g., !@#$%^&*()_+-=[]{}|;':",./<>?)
- Overall score and entropy estimation for advanced feedback

## Strength Levels

- **Weak**: Score < 40 (basic criteria not met)
- **Medium**: Score 40-69 (meets some criteria but lacks variety or length)
- **Strong**: Score 70-89 (good length and variety)
- **Very Strong**: Score 90+ (excellent length, full variety, high entropy)

## Usage

Run from command line:

```
python passwordchacker.py --password "yourpassword"   # CLI mode
python passwordchacker.py --interactive                # Interactive mode (prompts for password)
```

## Features

- **Secure Input**: Password entry hidden in interactive mode using getpass
- **Detailed Feedback**: Specific suggestions for improving password strength
- **Entropy Estimation**: Calculates password entropy in bits for scientific strength measure
- **CLI Friendly**: Command-line options with argparse

## Requirements

- Python 3.x
- External package: `colorama` (for colored terminal output)

Install dependencies by running:

```
pip install -r requirements.txt
```

## Sample Output

![Sample Password Strength Report](sample-report/passwordcheck.jpg)

## Author

Pranav Suryawanshi

## Version

1.0

## License

This project is licensed under the MIT License - see the LICENSE file for details.
