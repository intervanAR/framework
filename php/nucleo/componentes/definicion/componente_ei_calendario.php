<?php
/**
 * @package Componentes
 * @subpackage Eis
 */
require_once("componente_ei.php");

/**
 * Calendario para visualizar contenidos diarios y seleccionar d�as o semanas.
 * @package Componentes
 * @subpackage Eis
 */
class componente_ei_calendario extends componente_ei
{
	static function get_tipo_abreviado()
	{
		return "Calendario";		
	}
}
?>