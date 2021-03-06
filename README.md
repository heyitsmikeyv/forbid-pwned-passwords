# Forbid Pwned Passwords
## forbid-pwned-passwords

Protect your WordPress site's users from using breached passwords!

With Forbid Pwned Passwords, your site's users will receive errors if they attempt to set their password to one found in a known breach, forcing them to choose a new one.
This can help to mitigate [credential stuffing attacks](https://www.owasp.org/index.php/Credential_stuffing) against your site and its users.

This plugin makes use of Troy Hunt's **Have I Been Pwned?** API. Using k-anonymity methods, only a partial SHA-1 hash of the password
is sent to the API in order to produce a list of hashes for local testing. This means **no passwords are ever sent to third parties**.

You can learn more about the Have I Been Pwned API [here](https://haveibeenpwned.com/API/v2).
