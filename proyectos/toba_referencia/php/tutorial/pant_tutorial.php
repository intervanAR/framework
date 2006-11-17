<?php

class pant_tutorial extends toba_ei_pantalla 
{
	function generar_html_contenido()
	{
		$i = 0;
		foreach ($this->lista_tabs as $id => $pantalla) {
			if ($id == $this->id_en_controlador) {
				break;
			}
			$i++;
		}		
		$this->set_etiqueta("$i. ".$this->get_etiqueta());
		echo "<span style='float: right'>";
		$this->generar_botones_eventos();
		echo "</span>";
		parent::generar_html_contenido();		
	}
}

class pant_agenda extends toba_ei_pantalla 
{
	function generar_layout()
	{
		echo "<ol class='tutorial-agenda'>";
		foreach ($this->lista_tabs as $id => $pantalla) {
			if ($id != $this->id_en_controlador) {
				$this->registrar_evento_cambio_tab($id);
				echo "<li>";
				echo "<a href='#' onclick='{$this->objeto_js}.ir_a_pantalla(\"$id\")'>";
				echo $pantalla->get_etiqueta();
				echo "</a>";
				echo "</li>";
			}
		}	
		echo "</ol>";
	}
}

?>