<?php
require_once('info_ei.php');

class info_ei_esquema extends info_ei
{
	//------------------------------------------------------------------------
	//------ METACLASE -------------------------------------------------------
	//------------------------------------------------------------------------

	function get_molde_subclase()
	{
		return $this->get_molde_vacio();
	}
}
?>