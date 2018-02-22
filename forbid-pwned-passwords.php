<?php
/*
Plugin Name:  Forbid Pwned Passwords
Plugin URI:   https://developer.wordpress.org/plugins/the-basics/
Description:  Disallow usage of passwords found in the Have I Been Pwned breached password database.
Version:      0.0.1
Author:       Michael Veenstra
Author URI:   https://michaelveenstra.com/
License:      GPL2
License URI:  https://www.gnu.org/licenses/gpl-2.0.html
Text Domain:  forbid_pwned_passwords
Domain Path:  /languages
*/


add_action('validate_password_reset', 'fpp_checkpass');
add_action("user_profile_update_errors", 'fpp_checkpass');

function fpp_passreset($errors, $user=false) {
  if (isset($_POST['pass1']) && !empty($_POST['pass1']) && fpp_hibp_check($_POST['pass1'])) {
		$errors->add( 'pass', __( '<strong>ERROR</strong>: Password exists in the Have I Been Pwned database.', 'forbid_pwned_passwords'  ), "data?" );
  }
}

function fpp_checkpass($errors) {
  if (isset($_POST['pass1']) && !empty($_POST['pass1']) && fpp_hibp_check($_POST['pass1'])) {
    $errors->add( 'pass', __( '<strong>ERROR</strong>: Password exists in the Have I Been Pwned database.', 'forbid_pwned_passwords'  ), "data?" );
  }
}

function fpp_hibp_check($password) {
  $api = 'https://api.pwnedpasswords.com/pwnedpassword/';
  $ch = curl_init($api . $password);
  curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
  curl_setopt($ch,CURLOPT_TIMEOUT,10);
  curl_setopt($ch, CURLOPT_HEADER, true);
  curl_setopt($ch, CURLOPT_NOBODY, true);
  $output = curl_exec($ch);
  $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  curl_close($ch);

  if ($httpcode == "200") {
    return True;
  } else {
    return False;
  }

}

