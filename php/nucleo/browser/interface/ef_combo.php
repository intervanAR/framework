<?php
include_once("nucleo/browser/interface/ef.php");// Elementos de interface
/*
*	ef <abstracta>
*	|
*	+----> ef_combo <abstracta> (recibe un ARRAY) 
*				|		FALTA: poder decir cual es el valor por defecto cuando no hay estado!!!
*				|
*				+----> ef_combo_lista (recibe los elementos en un STRING separado por ",")
*				|
*				+----> ef_combo_lista_c (recibe los elementos en un STRING separado por "/"
*				|							y su clave-valor separado por ",")
*				|
*				+----> ef_combo_db (recibe un SQL)
*			       	   	|
*			   	        +----> ef_combo_proyecto (recibe un SQL, agrega un WHERE para el proyecto [+toba?]
*					|							Este EF tendria que ser el hijo (usar una ventana de 
*					|							reescritura de SQL) de un multiclave generico...
*	        		        +----> ef_combo_db_ayuda (recibe un SQL con tres columnas : id, valor del combo, ayuda)
*/

class ef_combo extends ef
//PARAMETROS ADICIONALES:
// "valores": Array con valores a mostrar en el combo
// "no_seteado": Nombre del valor NULO
{
	var $valores;				//Array con valores de la lista
	var $predeterminado;		//Si el combo tiene predeterminados, tengo que inicializarlo
	var $no_seteado;

	
	function ef_combo($padre,$nombre_formulario, $id,$etiqueta,$descripcion,$dato,$obligatorio,$parametros)
	{
        $this->valores = array();
		//Manejo del valor NO SETEADO
		if(isset($parametros["no_seteado"])){
    		if($parametros["no_seteado"]!=""){
	    		$this->no_seteado = $parametros["no_seteado"];
	    		$this->estado = apex_ef_no_seteado;
		    	$this->valores[apex_ef_no_seteado] = $parametros["no_seteado"];
    		}else{
    			$this->no_seteado = null;
    		}
        }else{
   			$this->no_seteado = null;
    	}
		//Esto se hace de esta manera para que el valor NO SETEADO se vea primero
		if(isset($parametros["valores"])){
			if(is_array($parametros["valores"])){
				$this->valores = $this->valores + $parametros["valores"];
			}
		}
		//Manejo de VALORES predeterminados
		$this->predeterminado = null;
		if(isset($parametros["predeterminado"])){
    		if($parametros["predeterminado"]!=""){
	    		$this->estado = $parametros["predeterminado"];
   			$this->predeterminado = $parametros["predeterminado"];
    		}
		}
		parent::ef($padre,$nombre_formulario, $id,$etiqueta,$descripcion,$dato,$obligatorio,$parametros);
	}

	function cargar_datos($datos)
	{
		$this->valores = $datos;
	}

	function establecer_solo_lectura()
	{
		//Elimino los valores distintos al seleccionado
		if(isset($this->estado)){
			foreach(array_keys($this->valores) as $valor){
				if($valor != $this->estado){
					unset($this->valores[$valor]);
				}	
			}
		}
        $this->solo_lectura = true;
	}

	function obtener_info()
	{
		//Seguridad: Si NO existe un elemento con este indice en el ARRAY toquetearon el FORM???
		if($this->activado()){
			return "{$this->etiqueta}: {$this->valores[$this->estado]}";
		}
	}

	//-----------------------------------------------
	//-------------- DEPENDENCIAS -------------------
	//-----------------------------------------------
	
	function javascript_slave_recargar_datos()
	{
		return "
		function recargar_slave_{$this->id_form}(datos)
		{
			s_ = document.{$this->nombre_formulario}.{$this->id_form};
			s_.options.length = 0;//Borro las opciones que existan
			//Creo los OPTIONS recuperados
			var hay_datos = false
			for (id in datos){
				if (id !=  '".apex_ef_no_seteado."')
					hay_datos = true;
				s_.options[s_.options.length] = new Option(datos[id], id);
			}
			if (hay_datos)
				s_.focus();
			document.body.style.cursor = '';
			atender_proxima_consulta();
		}
		";	
	}
	//-----------------------------------------------

	function javascript_slave_reset()
	{		
		$js = "
		function reset_{$this->id_form}()
		{
			s_ = document.{$this->nombre_formulario}.{$this->id_form};
			s_.options.length = 0;\n";
		if(isset($this->no_seteado)){
			$js .= "s_.options[0] = new Option('{$this->no_seteado}', '".apex_ef_no_seteado."');\n";
		}else{
			$js .= "s_.options[0] = new Option('', 'x');\n";
		}
		//Reseteo las dependencias	
		if(isset($this->dependientes)){
			foreach($this->dependientes as $dependiente){
				$js .= " reset_{$dependiente}();\n";
			}
		}
		$js .= "}\n";
		//Hay que resetear a los DEPENDIENTES
		return $js;
	}
	//-----------------------------------------------
	//-----------------------------------------------
	//-----------------------------------------------	

	function obtener_input()
	{
		//ei_arbol($this->valores);
        if (isset($this->estado)) {
            $estado = $this->estado;
        }else{
            $estado = "";
        }
        if ($this->solo_lectura)
        {
				if (count($this->valores) > 0){
					$valores = $this->valores;
				}else{
					$valores = array($this->no_seteado);
				}
	        	$input = form::select("",$estado, $valores, "ef-combo", "disabled");	
				if ($estado == "")
					$estado = apex_ef_no_seteado;
				$input .= form::hidden($this->id_form, $estado);
            return $input;
        }else{
				$html = $this->obtener_javascript_general() . "\n\n";
				$html .= form::select($this->id_form, $estado ,$this->valores, 'ef-combo', $this->obtener_javascript_input() );
				return $html;
        }
	}

	function resetear_estado()
	//Devuelve el estado interno
	{
		if($this->activado()){
			if(isset($this->predeterminado)){
				$this->estado = $this->predeterminado;
			}else{
				unset($this->estado);
			}
		}
	}

    function validar_estado()
    //Si el campo es obligatorio, el combo no puede tener el valor no_seteado
    {
        if($this->obligatorio){
            if( $this->activado() ){
				$this->validacion = true;
                return array(true,"");
            }else{
				$this->validacion = false;
                return array(false,"El campo es obligatorio!");
            }
        }else{
			$this->validacion = true;
			return array(true,"");
		}
    }
    
    function obtener_javascript()
    {
    //Si el campo es obligatorio, el combo no puede tener el valor no_seteado
        if($this->obligatorio){
            $no_seteado = apex_ef_no_seteado;
            return "
    if (formulario.". $this->id_form .".value == '$no_seteado')
    {
    	alert(\"El campo '". $this->etiqueta ."' es obligatorio.\");            
    	formulario.". $this->id_form .".focus();
        return false;
    }
            ";
        }
    }
}
//########################################################################################################
//########################################################################################################

class ef_combo_dao extends ef_combo
{
	private $dao;
	private $include;
	private $clase;

	function ef_combo_dao($padre,$nombre_formulario, $id,$etiqueta,$descripcion,$dato,$obligatorio,$parametros)
	{
		$parametros['valores'] = array();
		if(isset($parametros["dao"])){
			$this->dao = $parametros["dao"];
		}
		if(isset($parametros["include"])){
			$this->include = $parametros["include"];
		}
		if(isset($parametros["clase"])){
			$this->clase = $parametros["clase"];
		}
		if(isset($this->include) && isset($this->clase) )
		{
			//Desabilito el consumo por CN
			//Busco los datos
			include_once($this->include);
			$sentencia = "\$datos = " .  $this->clase . "::" . $this->dao ."();";
			eval($sentencia);//echo $sentencia;
		$parametros['valores'] = $datos;
			$this->dao = null;
		}
		unset($parametros["dao"]);//Este valor no significa nada para el padre
		parent::ef_combo($padre,$nombre_formulario, $id,$etiqueta,$descripcion,$dato,$obligatorio,$parametros);
	}
	
	function obtener_dao()
	/*
		SI no se especifican CLASE e INCLUDE, se solicita la funcion al CN asociado,
		si, esos parametros existen, se consulta al DAO directamente ACA
	*/
	{
		return $this->dao;	
	}
}
//########################################################################################################
//########################################################################################################

class ef_combo_lista extends ef_combo
//PARAMETROS ADICIONALES:
// "lista": La lista representada como un STRING con los elementos separados por COMAS
// "no_seteado": Valor que representa el estado de NO activado
{
	function ef_combo_lista($padre,$nombre_formulario, $id,$etiqueta,$descripcion,$dato,$obligatorio,$parametros)
	{
		if(isset($parametros["lista"])){
			$temp = explode(",",$parametros["lista"]);
			foreach($temp as $t){
				$parametros["valores"][$t] = $t;
			}
		}else{
			$parametros["valores"] = array();
		}
		 unset($parametros["lista"]);//Este valor no significa nada para el padre
		parent::ef_combo($padre,$nombre_formulario, $id,$etiqueta,$descripcion,$dato,$obligatorio,$parametros);
	}
}

//########################################################################################################
//########################################################################################################

class ef_combo_lista_c extends ef_combo
//PARAMETROS ADICIONALES:
// "lista": La lista representada como un STRING con los elementos separados por "/" y
// 			la clave y el valor separados por ","
// "no_seteado": Valor que representa el estado de NO activado
{
	function ef_combo_lista_c($padre,$nombre_formulario, $id,$etiqueta,$descripcion,$dato,$obligatorio,$parametros)
	{
		$elementos = explode("/",$parametros["lista"]);
		foreach($elementos as $elemento){
			$opcion = explode(",",$elemento);
			$parametros["valores"][trim($opcion[0])] = trim($opcion[1]);
		}
         unset($parametros["lista"]);//Este valor no significa nada para el padre
		parent::ef_combo($padre,$nombre_formulario, $id,$etiqueta,$descripcion,$dato,$obligatorio,$parametros);
	}
}

//########################################################################################################
//########################################################################################################

class ef_combo_db extends ef_combo
// Este elemento de formulario consiste en una lista extraida de una tabla.
//PARAMETROS ADICIONALES:
// "sql": SQL que genera la lista (EL sql debe devolver dos columnas: clave, descripcion)
// "no_seteado": Valor que representa el estado de NO activado
{
	var $sql;
	var $fuente;

	function ef_combo_db($padre,$nombre_formulario, $id,$etiqueta,$descripcion,$dato,$obligatorio,$parametros)
	{
		if(!($this->sql = stripslashes($parametros["sql"]) )){
			monitor::evento("bug","COMBO DB: SQL Vacio.");
		}
        if((isset($parametros["fuente"]))&&(trim($parametros["fuente"])!="")){
    		$this->fuente = $parametros["fuente"];
            unset($parametros["fuente"]);
        }else{
            $this->fuente = "instancia"; //La instancia por defecto es la CENTRAL
        }
//		echo $this->sql . "<br>";
//     	echo $this->fuente;
        unset($parametros["sql"]);

		parent::ef_combo($padre,$nombre_formulario, $id,$etiqueta,$descripcion,$dato,$obligatorio,$parametros);
		//Si hay dependencias... no?
		if(is_array($this->dependencias)){
			$this->valores = array();
		}else{
			$this->cargar_datos_db();
		}
	}

	function cargar_datos_db()
	{
		$this->valores = array();//Limpio la lista de valores
		if(isset($this->no_seteado)){
    		if(trim($this->estado)==""){
    			$this->estado = apex_ef_no_seteado;
	   		}
	    	$this->valores[apex_ef_no_seteado] = $this->no_seteado;
        }
		global $ADODB_FETCH_MODE, $db;
		$ADODB_FETCH_MODE = ADODB_FETCH_NUM;
		$rs = $db[$this->fuente][apex_db_con]->Execute($this->sql);
		if(!$rs){
			monitor::evento("bug","COMBO DB: No se genero el recordset. ". $db[$this->fuente][apex_db_con]->ErrorMsg()." -- SQL: {$this->sql} -- ");
		}
		if($rs->EOF){
			//echo ei_mensaje("EF etiquetado '$etiqueta'<br> No se obtuvieron registros: ". $this->sql);
		}
		$temp = $this->preparar_valores($rs->getArray());
		if(is_array($temp)){
			$this->valores = $this->valores + $temp;
		}
		//echo $this->sql. "<br>";
		//ei_arbol($this->valores);
	}

    function preparar_valores($datos_recordset)
    {
		$valores = null;
		foreach ($datos_recordset as $fila){
            $valores[$fila[0]] = $fila[1];
		}
        return $valores;
    }
}
//########################################################################################################
//########################################################################################################
//Este elemento es COMPLEJO (maneja mas de una columna)
/* Los elementos complejos manejan mas de un DATO de la tabla que su padre (el ABM) administra
* por eso la propiedad $this->dato es un ARRAY que indica cuales son los subelementos que se manejan
*/

class ef_combo_db_proyecto extends ef_combo_db
//Este elemento de formulario restringe los registros mostrados a los del PROYECTO ACTUAL o
//PARAMETROS ADICIONALES:
//"sql":    1) usuar %w% para ver donde se concatena el WHERE
//          2) El QUERY tiene que devolver 3 columnas: $this->dato[0], $this->dato[1] y descripcion.
//          Es ABSOLUTANMENTE NECESARIO que orden de estas columnas y el de %this->dato coincidan
//"columna_proyecto": Que columna de la tabla consulatada indica el proyecto al que pertenecen los registros?
//"incluir_toba": Hay que incluir el proyecto TOBA?
//"no_seteado":
{
   var $opcion_seleccionada;
	var $estado_nulo;
	
	function ef_combo_db_proyecto($padre,$nombre_formulario, $id,$etiqueta,$descripcion,$dato,$obligatorio,$parametros)
	{
        global $solicitud;
        //Armo la sentencia que limita al proyecto
        $sql_where =  $parametros["columna_proyecto"] . " = '".$solicitud->hilo->obtener_proyecto()."' ";
		if(isset($parametros["incluir_toba"])){
	        if($parametros["incluir_toba"]) $sql_where .= " OR ".$parametros["columna_proyecto"]." = 'toba'";
		}
        $where[] = "(" . $sql_where .")";
        $parametros["sql"] =  stripslashes(sql_agregar_clausulas_where($parametros["sql"],$where));
        //echo $parametros["sql"] . "<br>";
		//parent::ef_combo_db($padre,$nombre_formulario, $id,$etiqueta,$descripcion,$sql_modificado,$fuente,$no_seteado);
        unset($parametros["columna_proyecto"]);
        unset($parametros["incluir_toba"]);
		//------> ATENCION!! el manejo de NULOS no funciona!! 
		//unset($parametros["no_seteado"]);//----------> ARREGLAR!!!
		parent::ef_combo_db($padre,$nombre_formulario, $id,$etiqueta,$descripcion,$dato,$obligatorio,$parametros);
		if(count($dato)<>2){
			echo ei_mensaje("ef_combo_proyecto: Error en el elemento '{$this->id}'. El elemento debe manejar 2 datos!");
		}else{
			//Array que representa el estado NULO. 'null' para cada dato.
			foreach($this->dato as $dato){
				$this->estado_nulo[$dato] = 'NULL';
			}
		}
		//Si existe un valor no seteado, es el valor por defecto
        if(isset($parametros["no_seteado"])){
    		if($parametros["no_seteado"]!=""){
				$this->opcion_seleccionada = apex_ef_no_seteado;
				$this->estado = $this->estado_nulo;
    		}
        }
		//SI existe un valor predeterminado, lo utilizo
		if(isset($parametros["predeterminado"])){
    		if($parametros["predeterminado"]!=""){


	    		//Seteo el estado
	    		$estado = explode(",",$parametros["predeterminado"]);
	    		//ei_arbol($estado);
				$x = 0;
				unset($this->estado);
				foreach($this->dato as $dato){
					$estado_ok[$dato] = trim($estado[$x]);
					$x++;
				}
				//$this->estado = $estado_ok;
				$this->predeterminado = $estado_ok;

				//Seteo la opcion seleccionada
				$opcion = "";
    	        foreach($this->dato as $dato){//Sigo el orden de las columnas
        	        $opcion .= $estado_ok[$dato] . apex_ef_separador;
	            }
    	        //Saca el ultimo apex_ef_separador
				$this->opcion_seleccionada = substr($opcion,0,strlen($opcion)-strlen(apex_ef_separador));

    		}
    		//ei_arbol($this->estado);
      }
	}

	function establecer_solo_lectura()
	{
		//Elimino los valores distintos al seleccionado
		if(isset($this->estado)){
			foreach(array_keys($this->valores) as $valor){
				if($valor != $this->opcion_seleccionada){
					unset($this->valores[$valor]);
				}	
			}
		}
	}

    function preparar_valores($recordset)
    {
		$valores = array();
		foreach ($recordset as $fila){
            $valores[$fila[0].apex_ef_separador.$fila[1]] = $fila[2];
		}
        return $valores;
    }

	function activado()
	{
		//Devuelve TRUE si el elemento esta seteado y FALSE en el caso contrario
		return isset($this->estado) && ($this->estado !==  $this->estado_nulo);
	}

	function cargar_estado($estado=null)
	//Carga el estado interno. Es un array asociativo del tipo dato:valor
	{
   		if(isset($estado)){								
			//El estado tiene el formato adecuado?
			if(count($estado)<>2){
				echo ei_mensaje("ef_combo_proyecto: Error en el elemento '{$this->id}'. Se esperaba un array con 2 subindices!");
				return false;
			}
			//Si el estado es nulo tengo que manejarlo de una forma especial
			$valores = "";
			foreach($estado as $valor){
				$valores .= $valor;
			}
			if(trim($valor)==""){									//Valor NULO
				$this->estado = $this->estado_nulo;
				$this->opcion_seleccionada = apex_ef_no_seteado;
			}else{													//Valor seteado
	    		$this->estado=$estado;
				//Deduzco la opcion seleccionada del estado
				$opcion = "";
    	        foreach($this->dato as $dato){//Sigo el orden de las columnas
        	        $opcion .= $this->estado[$dato] . apex_ef_separador;
	            }
    	        //Saca el ultimo apex_ef_separador
				$this->opcion_seleccionada = substr($opcion,0,strlen($opcion)-strlen(apex_ef_separador));
			}
			return true;
		}elseif(isset($_POST[$this->id_form])){
            //Deduzco el estado de la opcion seleccionada
   			$this->opcion_seleccionada=$_POST[$this->id_form];
			//echo $this->id . " - " . $this->opcion_seleccionada. "<br>";
			if($this->opcion_seleccionada == apex_ef_no_seteado){	//Valor nulo
				$this->estado = $this->estado_nulo;
			}else{													//Valor seteado
	            $temp = explode(apex_ef_separador, $this->opcion_seleccionada);
    	        $temp_ind = 0;
				unset($this->estado);
        	    foreach($this->dato as $dato){//Sigo el orden de las columnas
            	    $this->estado[$dato] = $temp[$temp_ind];
                	$temp_ind++;
	            }
			}
			//ei_arbol($this->estado,$this->id);
			return true;
    	}
		return false;
	}

	function obtener_estado()
	//Devuelve el estado interno
	{
		if($this->activado()){
			return $this->estado;
		}else{
			return $this->estado_nulo;
		}
	}
    
	function obtener_input()
    //COmo este es un elemento complejo, su estado no es el valor del ID del select
	{
		return form::select($this->id_form,$this->opcion_seleccionada,$this->valores);	
	}

}

//SEGUIR ACA!!!!!!!!!!!!!
// Este elemento de formulario consiste en un conjunto de combos relacionales, su contenido proviene de recordsets
//PARAMETROS ADICIONALES:
// "sql": SQL que genera la lista (EL sql debe devolver dos columnas: clave, descripcion)
// "no_seteado": Valor que representa el estado de NO activado
/*
class ef_combo_db_cascada extends ef_combo_db
{
}
*/

//########################################################################################################
//########################################################################################################

class ef_combo_db_ayuda extends ef_combo_db
// Este elemento de formulario consiste en una lista extraida de una tabla con una ayuda por elemento.
//PARAMETROS ADICIONALES:
// "sql": SQL que genera la lista (EL sql debe devolver tres columnas: clave, descripcion, ayuda)
// "no_seteado": Valor que representa el estado de NO activado
{
	var $sql;
	var $fuente;
	var $ayuda;

	function ef_combo_db_ayuda($padre,$nombre_formulario, $id,$etiqueta,$descripcion,$dato,$obligatorio,$parametros)
	{
		parent::ef_combo_db($padre,$nombre_formulario, $id,$etiqueta,$descripcion,$dato,$obligatorio,$parametros);
	}

    function preparar_valores($recordset)
    {
		$valores = null;
		foreach ($recordset as $fila){
            //Guardo valor del combo y ayuda
			$valores[$fila[0]] = $fila[1];
			$this->ayuda[$fila[0]] = $fila[2];
		}
        return $valores;
    }

	function obtener_estado()
	//Devuelve el estado interno
	{
		if($this->activado()){
			return $this->estado;
		}else{
			return $this->estado_nulo;
		}
	}
	
	function cargar_estado($estado=null)
	//Carga el estado interno
	{
   		if(isset($estado)){								
    		$this->estado=$estado;
			return true;
	    }elseif(isset($_POST[$this->id_form])){
				if(get_magic_quotes_gpc()){
					$this->estado = stripslashes($_POST[$this->id_form]);
				}else{
	   				$this->estado = $_POST[$this->id_form];
				}
			return true;
    	}
		return false;
	}
    
	function obtener_input()
    //Como este es un elemento complejo, su estado no es el valor del ID del select
	{
		$html = "<script language='javascript'>
				function mostrar_ayuda_{$this->id_form}(){
				ef = document.{$this->nombre_formulario}.{$this->id_form}.value;
				switch(ef){\n";
					foreach ($this->ayuda as $proy=>$ayuda){
						$html .= "\t\tcase '$proy':\n\t\t\talert('".addslashes($ayuda)."');\n\t\t\tbreak;\n";
					}			
		$html .= "		}
				}
				</script>\n";		
		$html .= "<table class='tabla-0'>\n";
		$html .= "<tr><td>\n";
        $html .= parent::obtener_input();
    	$html .= "</td><td>\n";
		$html .= "<a href='#' onclick='javascript:mostrar_ayuda_{$this->id_form}();return false'>". recurso::imagen_apl("ayuda.jpg",true,null,null,"Descripcion del ELEMENTO") ."</a>";
		$html .= "</td></tr>\n";
		$html .= "</table>\n";
		return $html;
	}
}
//########################################################################################################
//########################################################################################################
?>