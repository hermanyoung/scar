using System;
using System.Collections.Generic;

namespace CleanApp
{
    /// <summary>Represents an authenticated user.</summary>
    public sealed class User
    {
        public string Name { get; }
        public string Email { get; }

        public User(string name, string email)
        {
            Name = name;
            Email = email;
        }

        /// <summary>Returns the formatted display name.</summary>
        public string DisplayName()
        {
            return $"{Name} <{Email}>";
        }

        /// <summary>Checks whether an email has a valid format.</summary>
        public bool HasValidEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                return false;
            }
            return email.Contains("@");
        }
    }
}
