<?php

namespace EE\LastPass;

use EE\Addons\Module\BaseModuleUpdate;

/**
 * LastPass Extension.
 *
 * @category    ExpressioneEngine Addon
 * @author      Jerry Price
 * @link        https://github.com/jjpmann
 */

class ModuleUpdate extends BaseModuleUpdate {
        
    public $version        = LP_VERSION;
    public $module_name    = LP_SHORT_NAME;

    function __construct($switch = TRUE)
    { 

    } 

    /**
     * Installer for the module
     */
    public function install() 
    {               
        $site_id = ee()->config->item('site_id');
        if ($site_id == 0) {
            $site_id = 1;
        }
        
        $data = [
            'module_name'           => $this->module_name,
            'module_version'        => $this->version,
            'has_cp_backend'        => 'y',
            'has_publish_fields'    => 'y'            
        ];

        ee()->db->insert('modules', $data);

        ee()->load->dbforge();

        $config_fields = [
            'lastpass_config_id' => [
                'type' => 'int',
                'constraint' => '10',
                'unsigned' => TRUE,
                'auto_increment' => TRUE
            ],
            'site_id' => [
                'type' => 'int',
                'constraint' => '10',
                'unsigned' => TRUE,
            ],
            'login' => [
                'type' => 'varchar',
                'constraint' => '250',
                'null' => FALSE
            ],
            'logout' => [
                'type' => 'varchar',
                'constraint' => '250',
                'null' => FALSE
            ],
            'cert' => [
                'type' => 'varchar',
                'constraint' => '2048',
                'null' => FALSE
            ]
        ];

        ee()->dbforge->add_field($config_fields);
        ee()->dbforge->add_key('lastpass_config_id', TRUE);
        ee()->dbforge->create_table('lastpass_config');
        

        return TRUE;
    }

   
    /**
     * Uninstall the module
     */
    public function uninstall() 
    {               

        ee()->db->select('module_id');
        $query = ee()->db->get_where('modules', array('module_name' => $this->module_name));
        
        ee()->db->where('module_id', $query->row('module_id'));
        ee()->db->delete('module_member_groups');
        
        ee()->db->where('module_name', $this->module_name);
        ee()->db->delete('modules');
        
        ee()->db->where('class', $this->module_name);
        ee()->db->delete('actions');
        
        ee()->db->where('class', $this->module_name.'_mcp');
        ee()->db->delete('actions');

        ee()->load->dbforge();
        ee()->dbforge->drop_table('lastpass_config');

        return TRUE;
    }
    
    /**
     * Update the module
     * 
     * @param $current current version number
     * @return boolean indicating whether or not the module was updated 
     */
    public function update ($current = '')
    {
        if ($current == $this->version)
        {
            return FALSE;
        }

        return TRUE;
    }

}

/* End of file upd.seo_lite.php */
/* Location: ./system/expressionengine/third_party/seo_lite/upd.seo_lite.php */
