<?php

namespace EE\LastPass;

use EE\Addons\Extension\BaseExtension;

/**
 * LastPass Extension.
 *
 * @category    ExpressioneEngine Addon
 * @author      Jerry Price
 * @link        https://github.com/jjpmann
 */

class Extension extends BaseExtension
{

    public $settings = array();
    public $description = LP_DESCRIPTION;
    public $docs_url = '';
    public $name = LP_NAME;
    public $settings_exist = 'n';
    public $version = LP_VERSION;

    protected $hooks = [
        'core_boot' => 'core_boot_hook'
    ];
    
    /**
     * Constructor.
     *
     * @param   mixed   Settings array or empty string if none exist.
     */
    // public function __construct($settings = '')
    // {
    //     $this->settings = $settings;
    // }

    /**
     * Settings Form.
     *
     * If you wish for ExpressionEngine to automatically create your settings
     * page, work in this method.  If you wish to have fine-grained control
     * over your form, use the settings_form() and save_settings() methods
     * instead, and delete this one.
     *
     * @see http://expressionengine.com/user_guide/development/extensions.html#settings
     */
    public function settings()
    {
        return array();
    }

    /**
     *  Helper function to show display the error
     *
     * @param $error string
     *
     * @return string (HTML)
     */
    public function showError($error = false)
    {
        if (!$error) {
            $error = lang('not_authorized');
        }

        return ee()->output->show_user_error('submission', $error);
    }

    /**
     *  Kick off login process using friendly URL
     */
    public function init()
    {        
        echo "<pre>".__FILE__.'<br>'.__METHOD__.' : '.__LINE__."<br><br>"; var_dump( 'init' ); exit;
        
        if (ee()->uri->uri_string == 'lastpass_login') {
            $this->processLogin();
        }
    }

    /**
     * Lastpass user login handler
     */
    protected function processLogin()
    {

        $site_id = ee()->config->item('site_id');
        $config = ee()->db->get_where('lastpass_config', array('site_id' => $site_id));

        if ($config->num_rows() != 1) {
            die('error');
        }

        $settings = $config->row_array();

        if (empty($_POST["SAMLResponse"])) {
            lp_AuthnRequest($settings);
        } else {
            
            $email = lp_saml_auth($settings, $_POST["SAMLResponse"]);

            echo "<pre>".__FILE__.'<br>'.__METHOD__.' : '.__LINE__."<br><br>"; var_dump( $_POST, $email ); exit;
            ;

            $username = preg_replace("/@.*/", "", $email);

            if (empty($username)) {
                watchdog('lastpass_login', 'LastPass SAML: SAMLReponse check failed -- is your certificate correct?');
                drupal_set_message('Login failed.', 'error');
                drupal_goto('/');
            }

            echo "<pre>".__FILE__.'<br>'.__METHOD__.' : '.__LINE__."<br><br>"; var_dump( $email ); exit;
            
            // Get User from DB

            if (!$user && variable_get('lastpass_create_user') === 1) {
                // create account
                $user = user_save('', array(
                    'name' => $username,
                    'mail' => $email,
                    'pass' => user_password(16),
                    'status' => 1,
                    'init' => $email,
                    'roles' => variable_set('lastpass_user_roles')
                ));
            }

            if (!$user) {
                watchdog('lastpass_login', 'Not able to get or create new user - ' . $email);
                drupal_set_message('Login failed.', 'error');
                drupal_goto('/');
            }

            watchdog('user', 'Session opened for %name.', array('%name' => $user->name));
            watchdog('cmsship', 'User %name logged in via CMSShip with IP of %ip.', array('%name' => $user->name, '%ip' => ip_address()));
            // Update the user table timestamp noting user has logged in.
            // This is also used to invalidate one-time login links.
            $user->login = REQUEST_TIME;
            db_update('users')
            ->fields(array('login' => $user->login))
            ->condition('uid', $user->uid)
            ->execute();

            // Regenerate the session ID to prevent against session fixation attacks.
            // This is called before hook_user in case one of those functions fails
            // or incorrectly does a redirect which would leave the old session in place.
            
        }
        
    }

}
