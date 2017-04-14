<?php

/**
 * LastPass Extension.
 *
 * @category    ExpressioneEngine Addon
 * @author      Jerry Price
 * @link        https://github.com/jjpmann
 */

class Lastpass_ext
{
    public $settings = array();
    public $description = LP_DESCRIPTION;
    public $docs_url = '';
    public $name = LP_NAME;
    public $settings_exist = 'n';
    public $version = LP_VERSION;

    
    /**
     * Constructor.
     *
     * @param   mixed   Settings array or empty string if none exist.
     */
    public function __construct($settings = '')
    {
        $this->settings = $settings;

        require_once PATH_THIRD.'lastpass/lib/lastpass_lib.php';
        
    }

    public static function isLoaded()
    {
        $qry = ee()->db
                ->from('extensions')
                ->where(array('class' => __CLASS__, 'enabled' => 'y'))
                ->get();

        if ($qry->num_rows() > 0) {
            return true;
        }
        return false;
    }

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
    public function core_boot_hook()
    {        
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



    /**
     * Activate Extension.
     *
     * This function enters the extension into the exp_extensions table
     *
     * @see http://codeigniter.com/user_guide/database/index.html for
     * more information on the db class.
     */
    public function activate_extension()
    {
        // Setup custom settings in this array.
        $this->settings = array();

        $hooks = array(
            'core_boot'         => 'core_boot_hook',
        );

        foreach ($hooks as $hook => $method) {
            $data = array(
                'class' => __CLASS__,
                'method' => $method,
                'hook' => $hook,
                'settings' => serialize($this->settings),
                'version' => $this->version,
                'enabled' => 'y',
            );

            ee()->db->insert('extensions', $data);
        }
    }

    /**
     * Disable Extension.
     *
     * This method removes information from the exp_extensions table
     */
    public function disable_extension()
    {
        ee()->db->where('class', __CLASS__);
        ee()->db->delete('extensions');
    }

    /**
     * Update Extension.
     *
     * This function performs any necessary db updates when the extension
     * page is visited
     *
     * @return mixed void on update / false if none
     */
    public function update_extension($current = '')
    {
        if ($current == '' or $current == $this->version) {
            return false;
        }
    }
}
