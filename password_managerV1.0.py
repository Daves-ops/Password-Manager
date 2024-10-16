# Get the filename from the user
filename = input("Name the file something secret so that nobody knows this is for your passwords! (e.g., 'example.txt'): ")

# Open the file in write mode
with open(filename, 'w') as file:
    pwords = {}  # Create an empty dictionary to store passwords

    while True:
        # Prompt the user to enter the name of the service or 'exit' to stop
        key = input("Enter the name of the service where you use this password (e.g., BrightSpace, Chase Bank, etc.) or type 'exit' to stop: ")
        
        if key.lower() == 'exit':
            break  # Exit the loop when the user types 'exit'
        
        value = input(f"Enter the password for '{key}': ")
        pwords[key] = value  # Add the key-value pair to the dictionary

    # Write the passwords (key-value pairs) to the file, one per line
    for key, value in pwords.items():
        file.write(f"{key}: {value}\n")  # Save the service and password in the file

print(f"Passwords have been saved to {filename}.")

# Ask the user if they want to display the passwords
check = input('Would you like to display all your passwords? (yes/no): ').lower()

if check == 'yes':
    # Open the file in read mode and display its contents
    with open(filename, 'r') as file:
        print("\nHere are your saved passwords:")
        print(file.read())
elif check == 'no':
    # Prompt the user for the specific service
    search_key = input('Enter the name of the service you want the password for: ').strip()
    
    # Open the file in read mode to search for the specific key
    with open(filename, 'r') as file:
        found = False
        for line in file:
            # Split the line into key and value
            key, value = line.strip().split(': ', 1)
            
            # Check if the current key matches the user's search
            if key.strip().lower() == search_key.lower():
                print(f"The password for '{search_key}' is: {value.strip()}")
                found = True
                break
        
        if not found:
            print(f"No password found for '{search_key}'.")
else:
    print("Invalid input. Exiting the program.")
