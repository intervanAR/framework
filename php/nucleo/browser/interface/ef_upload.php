<?php
  
class ef_upload extends ef
{

	function __construct($padre, $nombre_formulario, $id, $etiqueta, $descripcion, $dato, $obligatorio, $parametros)
	{
		// Controlar las extensiones v�lidas...
		if (isset($parametros['extensiones_validas'])) {
			$this->extensiones_validas = explode(',', $parametros['extensiones_validas']);
			foreach ($this->extensiones_validas as $clave => $valor)
				$this->extensiones_validas[$clave] = strtolower(trim($valor));
		}
		parent :: __construct($padre, $nombre_formulario, $id, $etiqueta, $descripcion, $dato, $obligatorio,$parametros);
	}
    
	static function get_parametros()
	{
		$parametros = ef::get_parametros();
		$parametros['extensiones_validas']['descripcion'] = 'Tipos de archivo permitidos';
		$parametros['extensiones_validas']['opcional'] = 1;	
		$parametros['extensiones_validas']['etiqueta'] = 'Extensiones v�lidas';
		return $parametros;
	}
	
	function obtener_info()
	{
		if($this->activado()){
			return "{$this->etiqueta}: {$this->estado}";
		}
	}
    
	function obtener_input()
	{
		$estado = $this->obtener_estado_input();
		if (is_array($estado))
			$nombre_archivo = isset($estado['name']) ? $estado['name'] : current($estado);
		else
			$nombre_archivo = $estado;
			
		$salida = "";
		if (! $this->solo_lectura) {
			if (isset($nombre_archivo)) {
				$salida .= "<script  type='text/javascript' language='javascript'>
							function cambiar(){
								if (document.getElementById('{$this->id_form}_check').checked == true) {
									//Lo va a cambiar
									document.getElementById('{$this->id_form}_desicion').style.display = 'none';
									document.getElementById('{$this->id_form}').style.display = '';
								} else {
									document.getElementById('{$this->id_form}_desicion').style.display = '';
									document.getElementById('{$this->id_form}').style.display = 'none';
								}	
							}
							</script>\n";
				$salida .= form::archivo($this->id_form, null, "ef-input-upload", "style='display:none'");
				$salida .= 	"<div id='{$this->id_form}_desicion' class='ef-upload-desc'>". $nombre_archivo . "</div>";
				$salida .= 	"<span style='white-space:nowrap'><input name='{$this->id_form}_check' id='{$this->id_form}_check'
							onclick='cambiar()' type='checkbox' value='1' class='ef-checkbox'>
							<label for='{$this->id_form}_check' style='font-weight:normal'>Cambiar el Archivo</span></label>";
			} else {
				$salida = form::archivo($this->id_form);
				$salida .= form::hidden($this->id_form."_check", 1);
			}
		} else { // En modo s�lo lectura
			if (isset($nombre_archivo))
				$salida = "<div class='ef-upload-desc'>". $nombre_archivo ."</div>";
			else
				$salida = form::archivo($this->id_form, null, "ef-input-upload", "disabled='disabled'");
		}

		return $salida;
	}
	
	function obtener_estado_input()
	{
        if (isset($this->estado)) {
            return $this->estado;
        }else{
            return null;
        }
	}
	
	function cargar_estado($estado=null)
	//Carga el estado interno
	{
		if(isset($estado)){								
			$this->estado=$estado;
			return true;
		}
		elseif(isset($_FILES[$this->id_form]))
		{
			if (isset($_POST[$this->id_form."_check"])) {
				$this->controlar_estado($_FILES[$this->id_form]['error']);
				if (! $this->es_archivo_vacio()) 
					$this->estado = $_FILES[$this->id_form];
				return true;
			}
		}
		return false;
	}

	function es_archivo_vacio()
	{
		return $_FILES[$this->id_form]["error"] == UPLOAD_ERR_NO_FILE;
	}
	
	function controlar_estado($id)
	{
		switch($id){
			case UPLOAD_ERR_NO_FILE:
				if (isset($this->obligatorio) AND $this->obligatorio == 1)
					throw new excepcion_toba("No se envio un archivo");
				break;
			case UPLOAD_ERR_INI_SIZE:
				throw new excepcion_toba("Se supero el limite seteado en PHP.INI");
				break;
			case UPLOAD_ERR_FORM_SIZE:
				throw new excepcion_toba("Se supero el limite expresado en el FORM");
				break;
			case UPLOAD_ERR_PARTIAL:
				throw new excepcion_toba("Ha ocurrido un error cargando el archivo");
				break;
		}
		if (isset($this->extensiones_validas)) {
			$rep = $_FILES[$this->id_form]['name'];
			$ext = substr($rep, strrpos($rep, '.') + 1);
			if (! in_array(strtolower($ext), $this->extensiones_validas))
				throw new excepcion_toba('Este tipo de archivos no est� permitido.');
		}
	}
	
	function obtener_consumo_javascript()
	{
		$consumos = array('interface/ef','interface/ef_upload');
		return $consumos;
	}
	
	function crear_objeto_js()
	{
		return "new ef_upload({$this->parametros_js()})";
	}	
	
}

?>
