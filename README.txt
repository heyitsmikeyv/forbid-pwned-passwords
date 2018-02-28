=== Forbid Pwned Passwords ===
Contributors: heyitsmikeyv
Donate link: https://paypal.me/heyitsmikeyv
Tags: security, passwords, pwned, breach, haveibeenpwned
Requires at least: 3.5
Tested up to: 4.9
Stable tag: trunk
Requires PHP: 5.2.4
License: GPLv3
License URI: https://www.gnu.org/licenses/gpl-3.0.html

Disallow usage of passwords found in the Have I Been Pwned breached password database.

== Description ==

Protect your WordPress site's users from using breached passwords!

With Forbid Pwned Passwords, your site's users will receive errors if they attempt to set their password to one found in a known breach, forcing them to choose a new one.
This can help to mitigate [credential stuffing attacks](https://www.owasp.org/index.php/Credential_stuffing) against your site and its users.

This plugin makes use of Troy Hunt's **Have I Been Pwned?** API. Using k-anonymity methods, only a partial SHA-1 hash of the password
is sent to the API in order to produce a list of hashes for local testing. This means **no passwords are ever sent to third parties**.

You can learn more about the Have I Been Pwned API [here](https://haveibeenpwned.com/API/v2).
