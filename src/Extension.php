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
        'core_boot' => 'init'
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

    public function core_boot_hook()
    {
        $this->init();
    }

    /**
     *  Kick off login process using friendly URL
     */
    public function init()
    {        
        if (ee()->uri->uri_string == 'lastpass_login') {
            $this->processLogin();
        }
    }


    /**
     * Log member in using EE login process (copied from mod.member_auth.php and Auth.php)
     * 
     * @param string $email
     * @return void
     */
    private function login($member)
    {
    
        ee()->load->library('auth');
        ee()->lang->loadfile('login');

        $incoming = new \Auth_result($member->row());
        $incoming->start_session();

        // $login_state = random_string('md5');
        // ee()->db->update(
        //     'sessions',
        //     array('login_state' => $login_state),
        //     array('session_id' => ee()->session->userdata('session_id'))
        // );

        // Build success message
        $site_name = (ee()->config->item('site_name') == '') ? lang('back') : stripslashes(ee()->config->item('site_name'));

        $return = reduce_double_slashes(ee()->functions->form_backtrack());

        // Build success message
        $data = array(
            'title'     => lang('mbr_login'),
            'heading'   => lang('thank_you'),
            'content'   => lang('mbr_you_are_logged_in'),
            'redirect'  => $return,
            'link'      => array($return, $site_name)
        );

        ee()->output->show_message($data);
        exit;
    
    }

    /**
     * create a new member using email
     * 
     * @param string $email
     * @return void
     */
    protected function createMember($email)
    {

    }

    /**
     * Lastpass user login handler
     *
     * @return void
     */
    protected function processLogin()
    {

        if (ee()->session->userdata('member_id') !== 0) {
            return ee()->functions->redirect(ee()->functions->fetch_site_index());
        }

        $config = ee()->db->get_where('lastpass_config', 
            array('site_id' => ee()->config->item('site_id')));

        if ($config->num_rows() != 1) {
            die('error');
        }

        $settings = $config->row_array();

        if (empty($_POST["SAMLResponse"])) {
            
            lp_AuthnRequest($settings);

        } else {
            
            $email = lp_saml_auth($settings, $_POST["SAMLResponse"]);

            $member = ee()->db->get_where('members', array('email' => $email));

            if ($member->num_rows() != 1) {
                // can we make the member?
                if (false) {
                    $this->createMember();
                }
            }

            return $this->login($member);

        }
        
    }

}
