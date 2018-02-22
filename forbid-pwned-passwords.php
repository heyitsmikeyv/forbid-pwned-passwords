<?php
/*
Plugin Name:  Forbid Pwned Passwords
Plugin URI:   https://github.com/heyitsmikeyv/forbid-pwned-passwords
Description:  Disallow usage of passwords found in the Have I Been Pwned breached password database.
Version:      0.0.2
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
 * of the password if given. Will add an error to the WP Errors object
 * provided if the password matches a breach, preventing the user update.
 * 
 * @since	0.0.1
 * @uses	fpp_hibp_check
 * @uses	WP_Error->add() 
 * @param	WP_Error $errors 
 * @return	None
 */
function fpp_checkpass($errors) {
  if (isset($_POST['pass1']) && !empty($_POST['pass1'])) {
    $fpp_pwn_count = fpp_hibp_check($_POST['pass1']);
    if ($fpp_pwn_count > 0) {	
	$errors->add( 'pass', __( 
	"<strong>ERROR</strong>: Provided password was identified in <strong>" . 
	$fpp_pwn_count . 
        "</strong> known sets of breached credentials." . 
	" <a href='https://haveibeenpwned.com/Passwords'>Learn More</a>.", 'forbid_pwned_passwords'  ) );
    }
  }
}

/**
 * Check a given password against the Have I Been Pwned password API
 * 
 * Returns a count of breach instances returned from HIBP. If zero are found,
 * the API will return a 404 instead of a count. This function will return
 * the integer 0 in this case. 
 * 
 * See https://haveibeenpwned.com/Passwords for more information.
 * 
 * @since	0.0.1
 * @uses	curl
 * @param	str $password 
 * @return	int
*/
function fpp_hibp_check($password) {
  $api = 'https://api.pwnedpasswords.com/pwnedpassword/';
  $ch = curl_init($api . $password);
  curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
  curl_setopt($ch,CURLOPT_TIMEOUT,10);
  $output = curl_exec($ch);
  $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  curl_close($ch);

  if ($httpcode == "200") {
    return intval(remove_utf8_bom($output));
  } else {
    return 0;
  }

}

/** 
 * Removes the UTF-8 byte order mark (BOM) 
 * 
 * The HIBP password API returns a count of hits against a given password, 
 * but includes a three-byte BOM at the beginning of the response body. 
 * 
 * This gets rid of that so we can properly get the count as an integer.
 * 
 * @since 0.0.2
 * @param str $text Text string with BOM to strip
 * @return str 
 */
function remove_utf8_bom($text)
{
    $bom = pack('H*','EFBBBF');
    $text = preg_replace("/^$bom/", '', $text);
    return $text;
}


