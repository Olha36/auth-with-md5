using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        var users = new Dictionary<string, string>(); // store user login and hashed password
        bool running = true;

        while (running)
        {
            Console.WriteLine("Select an option: ");
            Console.WriteLine("1. Create new user");
            Console.WriteLine("2. Authenticate user");
            Console.WriteLine("3. See saved passwords");
            Console.WriteLine("4. Exit");
            string option = Console.ReadLine();

            switch (option)
            {
                case "1":
                    Console.WriteLine("Enter login: ");
                    string login = Console.ReadLine();
                    if (!login.Contains("@gmail.com"))
                    {
                        Console.WriteLine("Invalid login: Login must contain @gmail.com");
                        break;
                    }
                    Console.WriteLine("Enter password: ");
                    string password = GetPasswordFromConsole();
                    string hashedPassword = GetMd5Hash(password);
                    users[login] = hashedPassword;
                    Console.WriteLine("User created successfully");
                    break;

                case "2":
                    Console.WriteLine("Enter login: ");
                    string authLogin = Console.ReadLine();
                    if (!authLogin.Contains("@gmail.com"))
                    {
                        Console.WriteLine("Invalid login: Login must contain @gmail.com");
                        break;
                    }
                    Console.WriteLine("Enter password: ");
                    string authPassword = GetPasswordFromConsole();
                    if (users.ContainsKey(authLogin))
                    {
                        if (VerifyMd5Hash(authPassword, users[authLogin]))
                        {
                            Console.WriteLine("User authenticated successfully");
                        }
                        else
                        {
                            Console.WriteLine("Incorrect password");
                        }
                    }
                    else
                    {
                        Console.WriteLine("Incorrect login");
                    }
                    break;

                case "3":
                    Console.WriteLine("Saved passwords:");
                    foreach (var user in users)
                    {
                        Console.WriteLine("{0}: {1}", user.Key, user.Value);
                    }
                    break;

                case "4":
                    running = false;
                    break;

                default:
                    Console.WriteLine("Invalid option");
                    break;
            }
        }
    }

    // Compute the MD5 hash of a string
    static string GetMd5Hash(string input)
    {
        using (MD5 md5Hash = MD5.Create())
        {
            // Convert the input string to a byte array and compute the hash.
            byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));

            // Create a new StringBuilder to collect the bytes
            // and create a string.
            StringBuilder builder = new StringBuilder();

            // Loop through each byte of the hashed data 
            // and format each one as a hexadecimal string.
            for (int i = 0; i < data.Length; i++)
            {
                builder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string.
            return builder.ToString();
        }
    }

    // Verify a string against a hash
    static bool VerifyMd5Hash(string input, string hash)
    {
        // Hash the input.
        string hashOfInput = GetMd5Hash(input);

        // Compare the hash with the given hash.
        StringComparer comparer = StringComparer.OrdinalIgnoreCase;

        if (0 == comparer.Compare(hashOfInput, hash))
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    // Get the password from the console input
    static string GetPasswordFromConsole()
    {
        StringBuilder sb = new StringBuilder();
        ConsoleKeyInfo key;

        do
        {
            key = Console.ReadKey(true);

            if (key.Key != ConsoleKey.Enter)
            {
                sb.Append(key.KeyChar);
                Console.Write("*");
            }
        } while (key.Key != ConsoleKey.Enter);

        Console.WriteLine();
        return sb.ToString();
    }
}