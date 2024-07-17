import random

def generate_password(words, symbols):
    # Select a word that starts with an uppercase letter
    uppercase_words = [word for word in words if word[0].isupper()]
    if not uppercase_words:
        raise ValueError("No words with an uppercase initial letter available")
    majuscule_word = random.choice(uppercase_words)

    # Generate a random number, e.g., four digits
    number = str(random.randint(1000, 9999))

    # Select a random symbol
    symbol = random.choice(symbols)

    # Concatenate the parts in the specified format
    password = majuscule_word + number + symbol

    return password

def main():
    words = ["OWASP", "Shop", "Juice", "team", "password", "Support", "login", "admin", "original"]
    symbols = "!@#$%^&*()_+"
    
    generated_passwords = set()
    num_passwords = 10000000

    with open("generated_passwords.txt", "w") as file:
        for i in range(num_passwords):
            password = generate_password(words, symbols)

            while password in generated_passwords:
                password = generate_password(words, symbols)
            
            generated_passwords.add(password)
            file.write(f"{password}\n")
            print(f"Password {i+1} generated")

    print("Passwords generated and saved to 'generated_passwords.txt'")

if __name__ == "__main__":
    main()
