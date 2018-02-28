<?php
/*
Plugin Name:  Forbid Pwned Passwords
Plugin URI:   https://github.com/heyitsmikeyv/forbid-pwned-passwords
Description:  Disallow usage of passwords found in the Have I Been Pwned breached password database.
Version:      0.1.0
Author:       Michael Veenstra
Author URI:   https://michaelveenstra.com/
License:      GPL3
License URI:  https://www.gnu.org/licenses/gpl-3.0.en.html
Text Domain:  forbid_pwned_passwords
Domain Path:  /languages
*/

// Prevent direct access
defined('ABSPATH') or die("Nothing to see here.");

/**
 * Add password checker to WordPress hooks
 */
add_action('validate_password_reset', 'fpp_checkpass');
add_action("user_profile_update_errors", 'fpp_checkpass');

/**
 * Function to be hooked to WordPress password reset actions.
 *
 * Checks if 'pass1' has been POSTed, and will perform an API check
 * of the password if given. Adds an error to the WP Errors object
 * provided if the password matches a breach, preventing the user update.
 *
 * NOTE: I'm not a fan of how this currently accesses the password input.
 *       If there's a safer way to get passed both the $errors object and
 *       the password, please reach out or submit a pull request.
 *
 * @since	0.0.1
 * @param	WP_Error $errors
 * @return	None
 */
function fpp_checkpass($errors) {
  if (isset($_POST['pass1']) && !empty($_POST['pass1'])) {

    $fpp_pwn_count = fpp_hibp_check($_POST['pass1']);
    if ($fpp_pwn_count > 0) {
	$errors->add( 'pass', __(
	    "<strong>ERROR</strong>: The password you've provided has been identified in <strong>" .
	    $fpp_pwn_count .
      "</strong> known sets of breached credentials.<br />
      The site administrator has applied restrictions preventing the use of such passwords.<br />
      <strong>Please choose a different password</strong>. <a href='" .
      esc_url("https://haveibeenpwned.com/Passwords") .
      "'>Learn More</a>.",
      'forbid_pwned_passwords'  ) );
    }
  }
}

/**
 * Check a given password against the Have I Been Pwned password API.
 *
 * This uses the HIBP API's k-Anonymity functionality, meaning that no actual
 * password strings will ever be sent over the network. The first five characters
 * of the password's SHA-1 hash are sent, and the API returns a full list of
 * potentially matching hashes to be checked locally.
 *
 * The function returns a count of breach instances returned from HIBP.
 *
 * See https://haveibeenpwned.com/Passwords for more information.
 *
 * @since	0.0.1
 * @param	str $pwd
 * @return	int
*/
function fpp_hibp_check($pwd) {
  $api = 'https://api.pwnedpasswords.com/range/';
  $hash = sha1($pwd);
  $prefix = substr($hash, 0, 5);
  $suffix = substr($hash, 5);
  $response = wp_remote_get($api . $prefix);

  // Check response to see if there's a match.
  // If so, catch an instance count from the response.
  // If not, return 0.
  $regex = "/" . $suffix . ":(\d+)/i";
  if ( preg_match($regex, $response["body"], $matches)) {
    return intval($matches[1]);
  } else {
    return 0;
  }

}
