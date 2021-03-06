<?php

namespace EE\LastPass;

use EE\Addons\Module\BaseModuleControlPanel;

/**
 * LastPass Extension.
 *
 * @category    ExpressioneEngine Addon
 * @author      Jerry Price
 * @link        https://github.com/jjpmann
 */

class ModuleControlPanel extends BaseModuleControlPanel 
{

    protected $base = 'addons/settings/lastpass';          // the base url for this module         
    protected $form_base;     // base url for forms

    public $module_name = LP_SHORT_NAME;

    function __construct( $switch = TRUE )
    {

        // uncomment this if you want navigation buttons at the top
        ee()->cp->set_right_nav(array(
            'settings'    => $this->base,
            'docs'        => '',
        ));

        //  Onward!
        ee()->load->library('table');
        ee()->load->library('javascript');
        ee()->load->helper('form');

    }

    public function index() 
    {

        $vars = [];
        $site_id = ee()->config->item('site_id');
        $config = ee()->db->get_where('lastpass_config', array('site_id' => $site_id));


        $settings = [
            'login'     => '',
            'logout'    => '',
            'cert'      => '',
            'url'       => '',
            'redirect'  => '',
        ];

        if ($config->num_rows() == 1) {
            $settings = array_merge($settings, $config->row_array());
        }
        
        $vars['sections'] =[
            [
                [
                    'title' => 'Login URL',
                    'fields' => [
                        'lp_login' => [
                            'type' => 'text',
                            'value' => $settings['login'],
                            'required' => TRUE
                        ]
                    ]
                ],
                [
                    'title' => 'Logout URL',
                    'fields' =>[
                        'lp_logout' =>[
                            'type' => 'text',
                            'value' => $settings['logout'],
                            'required' => TRUE
                        ]
                    ]
                ],
                [
                    'title' => 'SAML Certificate',
                    'fields' =>[
                        'lp_saml_cert' =>[
                            'type' => 'textarea',
                            'value' => $settings['cert'],
                            'required' => TRUE
                        ]
                    ]
                ],
                [
                    'title' => 'LastPass Entity ID',
                    'fields' =>[
                        'lp_entity_id' => [
                            'type' => 'text',
                            'value' => lastpass_get_entity_id(),
                            'disabled' => true
                            // 'required' => TRUE
                        ],
                    // 'attrs' => ['readonly' => 'readyonly'],
                    ]
                ],
                [
                    'title' => 'EE Lastpass Login URL',
                    'fields' => [
                        'lp_process' => [
                            'type' => 'text',
                            'value' => $settings['url'],
                            'required' => TRUE
                        ]
                    ]
                ],
                [
                    'title' => 'EE Redirect after Login',
                    'fields' => [
                        'lp_redirect' => [
                            'type' => 'text',
                            'value' => $settings['redirect'],
                            'required' => TRUE
                        ]
                    ]
                ],
            ]
        ];

        $vars += [
            'base_url' => ee('CP/URL', $this->base . '/save_settings'),
            'cp_page_title' => 'LastPass SAML Settings',
            'save_btn_text' => 'btn_save_settings',
            'save_btn_text_working' => 'btn_saving',
        ];

        return ee('View')->make('lastpass:form')->render($vars);
    }
    
    public function save_settings()
    {
        
        $rules = array(
          'lp_login' => 'required|minLength[5]',
          'lp_logout' => 'required|minLength[5]',
          'lp_saml_cert' => 'required|minLength[500]',
          'lp_process' => 'required|minLength[5]',
          'lp_redirect' => 'required|minLength[5]',
        );

        $result = ee('Validation')->make($rules)->validate($_POST);

        if ($result->isValid()) {

            $site_id = ee()->config->item('site_id');
            $config = ee()->db->get_where('lastpass_config', array('site_id' => $site_id));

            $data = [
                'login' => trim(ee()->input->post('lp_login')),
                'logout' => trim(ee()->input->post('lp_logout')),
                'cert' => trim(ee()->input->post('lp_saml_cert')),
                'url' => trim(ee()->input->post('lp_process')),
                'redirect' => trim(ee()->input->post('lp_redirect')),
            ];

            if($config->num_rows() == 0) {
                $data['site_id'] = $site_id;
                ee()->db->insert('lastpass_config', $data);
            } else {
                ee()->db->where('site_id', $site_id);
                ee()->db->update('lastpass_config', $data);
            }

            ee('CP/Alert')->makeStandard('lastpass-settings-saved')
                ->asSuccess()
                ->withTitle('Saved!')
                ->addToBody('Lastpass settings saved.')
                ->defer();

            ee()->functions->redirect(ee('CP/URL', 'addons/settings/lastpass')); 
        }

         ee('CP/Alert')->makeStandard('lastpass-settings-saved')
                ->asIssue()
                ->withTitle('Error!')
                ->addToBody('Lastpass settings were not saved.')
                ->defer();

        ee()->functions->redirect(ee('CP/URL', 'addons/settings/lastpass'));
        
    }

}

/* End of file mcp.seo_lite.php */ 
/* Location: ./system/expressionengine/third_party/seo_lite/mcp.seo_lite.php */ 