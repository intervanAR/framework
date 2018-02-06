<?php

class caso_base  extends toba_test_selenium
{
	protected $session;
	
	function cargar_operacion_usuarios()
	{
		$this->session = basics_proyecto::abrir_browser('chrome');		
		basics_proyecto::login($this->session);
		//$url = toba_http::get_url_actual() .toba::vinculador()->get_url(utilidades_testing::get_proyecto_id(), 3432);
		$url = utilidades_testing::get_url_item(3432);
		$this->session->get($url);
		$titulo = $this->session->getTitle();
		$this->assertTrue($titulo == 'Toba - Usuarios - Mantenimiento de usuarios',"Login was unsuccessful");	
		return $this->session;
	}
	
}
?>