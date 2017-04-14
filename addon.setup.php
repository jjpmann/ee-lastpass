<?php

// Global Contants
if ( ! defined('LP_NAME')) define('LP_NAME', 'LastPass SAML');
if ( ! defined('LP_SHORT_NAME')) define('LP_SHORT_NAME', 'lastpass');
if ( ! defined('LP_DESCRIPTION')) define('LP_DESCRIPTION', 'Allows you to use Lastpass SAML to login via ExpressionEngine');
if ( ! defined('LP_VERSION')) define('LP_VERSION', '0.0.1');
if ( ! defined('LP_DOCS')) define('LP_DOCS', '');

return array(
    'author'      => 'Jerry Price',
    'author_url'  => 'https://github.com/jjpmann',
    'name'        => LP_NAME,
    'description' => LP_DESCRIPTION,
    'version'     => LP_VERSION,
    'namespace'   => 'EE\LastPass',
    'settings_exist' => TRUE
);
