<?php
require_once('info_ei.php');

class info_ei_formulario extends info_ei
{
	//---------------------------------------------------------------------	
	//-- EVENTOS
	//---------------------------------------------------------------------

	function get_plan_construccion_metodos($multilinea=false)
	{
		$plan = array();
		//***************** JAVASCRIPT *****************
		$plan['javascript']['desc'] = 'JAVASCRIPT';
		//-- Validacion general
		$plan['javascript']['bloque'][0]['desc'] = 'Eventos';
		$plan['javascript']['bloque'][0]['metodos']['evt__validar_datos']['parametros'] = array();
		//-- Eventos
		if (count($this->eventos_predefinidos()) > 0) {
			$plan['javascript']['bloque'][1]['desc'] = 'Eventos';
			$plan['javascript']['bloque'][1]['metodos'] = $this->get_plan_construccion_eventos_js();
		}
		if(count($this->datos['info_formulario_ef'])) {
			//-- Procesamiento de EFs
			$plan['javascript']['bloque'][2]['desc'] = 'Procesamiento de EFs';
			foreach ($this->datos['info_formulario_ef'] as $ef => $info) {
				$m = 'evt__' . $info['identificador'] . '__procesar';
				$parametros = array('es_inicial');
				if($multilinea) $parametros[] = 'fila';
				$plan['javascript']['bloque'][2]['metodos'][$m]['parametros'] = $parametros;
			}
			//-- Validacion de EFs
			$plan['javascript']['bloque'][3]['desc'] = 'Validacion de EFs';
			foreach ($this->datos['info_formulario_ef'] as $ef => $info) {
				$m = 'evt__' . $info['identificador'] . '__validar';
				$parametros = $multilinea ? array('fila') : array();
				$plan['javascript']['bloque'][3]['metodos'][$m]['parametros'] = $parametros;
			}
		}
		return $plan;
	}

	function get_comentario_carga()
	{
		return "El formato del retorno debe ser array('id_ef' => \$valor, ...)";
	}

	//-- Generacion de metadatos

	static function get_modelos_evento()
	{
		$modelo[0]['id'] = 'basico';
		$modelo[0]['nombre'] = 'Basico';
		$modelo[1]['id'] = 'abm';
		$modelo[1]['nombre'] = 'ABM';
		return $modelo;
	}

	static function get_lista_eventos_estandar($modelo)
	{
		$evento = array();
		switch($modelo){
			case 'basico':
				$evento[0]['identificador'] = "modificacion";
				$evento[0]['etiqueta'] = "&Modificar";
				$evento[0]['maneja_datos'] = 1;
				$evento[0]['implicito'] = true;
				$evento[0]['orden'] = 3;
				$evento[0]['en_botonera'] = 0;		
				break;
			case 'abm':
				$evento[0]['identificador'] = "alta";
				$evento[0]['etiqueta'] = "&Agregar";
				$evento[0]['maneja_datos'] = 1;
				$evento[0]['estilo'] = "ei-boton-alta";
				$evento[0]['orden'] = 1;
				$evento[0]['en_botonera'] = 1;		
				$evento[0]['grupo'] = 'no_cargado';

				$evento[1]['identificador'] = "baja";
				$evento[1]['etiqueta'] = "&Eliminar";
				$evento[1]['estilo'] = "ei-boton-baja";
				$evento[1]['imagen_recurso_origen'] = 'apex';
				$evento[1]['imagen'] = 'borrar.gif';
				$evento[1]['confirmacion'] = "�Desea ELIMINAR el registro?";
				$evento[1]['orden'] = 2;
				$evento[1]['en_botonera'] = 1;		
				$evento[1]['grupo'] = 'cargado';

				$evento[2]['identificador'] = "modificacion";
				$evento[2]['etiqueta'] = "&Modificar";
				$evento[2]['maneja_datos'] = 1;
				$evento[2]['estilo'] = "ei-boton-mod";
				$evento[2]['orden'] = 3;
				$evento[2]['en_botonera'] = 1;		
				$evento[2]['grupo'] = 'cargado';
				
				$evento[3]['identificador'] = "cancelar";
				$evento[3]['maneja_datos'] = 0;
				$evento[3]['etiqueta'] = "Ca&ncelar";
				$evento[3]['estilo'] = "ei-boton-canc";		
				$evento[3]['orden'] = 4;		
				$evento[3]['en_botonera'] = 1;		
				$evento[3]['grupo'] = 'cargado';
				break;
		}
		return $evento;
	}
}
?>