<?php
/**
 * Representa una estructura tabular tipo tabla o RecordSet en memoria
 *
 * - Utiliza un administrador de persistencia para obtener y sincronizar los datos con un medio de persistencia.
 * - Una vez en memoria existen primitivas para trabajar sobre estos datos.
 * - Los datos y sus modificaciones son mantenidos autom�ticamente en sesi�n entre los distintos pedidos de p�gina.
 * - Una vez terminada la edici�n se hace la sincronizaci�n con el medio de persistencia marcando el final de la transacci�n de negocios.
 *
 * @package Componentes
 * @subpackage Persistencia
 * @todo Control de FK y PK
 */
class toba_datos_tabla extends toba_componente 
{
	protected $_info_estructura;
	protected $_info_columnas;
	protected $_info_externas;
	protected $_info_externas_col;
	protected $_persistidor;						// Mantiene el persistidor del OBJETO
	// Definicion asociada a la TABLA
	protected $_clave;							// Columnas que constituyen la clave de la tabla
	protected $_columnas;
	protected $_posee_columnas_ext = false;		// Indica si la tabla posee columnas externas (cargadas a travez de un mecanismo especial)
	//Constraints
	protected $_no_duplicado;					// Combinaciones de columnas que no pueden duplicarse
	// Definicion general
	protected $_tope_max_filas;					// Cantidad de maxima de datos permitida.
	protected $_tope_min_filas;					// Cantidad de minima de datos permitida.
	protected $_es_unico_registro=true;		//La tabla tiene com maximo un registro?
	// ESTADO
	protected $_cambios = array();				// Cambios realizados sobre los datos
	protected $_datos = array();					// Datos cargados en el db_filas
	protected $_datos_originales = array();		// Datos tal cual salieron de la DB (Control de SINCRO)
	protected $_proxima_fila = 0;				// Posicion del proximo registro en el array de datos
	protected $_cursor;							// Puntero a una fila espec�fica
	protected $_cursor_original;					// Backup del cursor que se usa para deshacer un seteo
	protected $_cargada = false;
	protected $_from;
	protected $_where;
	// Relaciones con el exterior
	protected $_relaciones_con_padres = array();			// ARRAY con un objeto RELACION por cada PADRE de la tabla
	protected $_relaciones_con_hijos = array();			// ARRAY con un objeto RELACION por cada HIJO de la tabla

	
	function __construct($id)
	{
		$propiedades = array();
		$propiedades[] = "_cambios";
		$propiedades[] = "_datos";
		$propiedades[] = "_proxima_fila";
		$propiedades[] = "_cursor";
		$propiedades[] = "_cargada";		
		$this->set_propiedades_sesion($propiedades);		
		parent::__construct($id);
		for($a=0; $a<count($this->_info_columnas);$a++){
			//Armo una propiedad "columnas" para acceder a la definicion mas facil
			$this->_columnas[ $this->_info_columnas[$a]['columna'] ] =& $this->_info_columnas[$a];
			if($this->_info_columnas[$a]['pk']==1){
				$this->_clave[] = $this->_info_columnas[$a]['columna'];
			}
			if($this->_info_columnas[$a]['externa']==1){
				$this->_posee_columnas_ext = true;
			}
		}
		$this->activar_cargas_externas();
		$this->activar_control_valores_unicos();
	}

	/**
	 * @ignore 
	 */
	protected function activar_cargas_externas()
	{
		//--- Se recorren las cargas externas, el lugar ideal seria hacer esto en el ap, pero aca es mas simple y eficiente
		if ($this->_posee_columnas_ext) {
			foreach($this->_info_externas as $externa) {
				$parametros = array();
				$resultados = array();
				//-- Se identifican las columnas de esta carga
				foreach($this->_info_externas_col as $ext_col) {
					if ($ext_col['externa_id'] == $externa['externa_id']) {
						if ($ext_col['es_resultado'] == 1) {
							$resultados[] = $ext_col['columna'];
						} else {
							$parametros[] = $ext_col['columna'];
						}	
					}					
				}
				if ($externa['sql'] != '') {
					//---Caso SQL
					$this->get_persistidor()->activar_proceso_carga_externa_sql(
							$externa['sql'], $parametros, $resultados, $externa['sincro_continua']);
				} else {
					//---Caso DAO
					$this->get_persistidor()->activar_proceso_carga_externa_dao(
							$externa['metodo'], $externa['clase'], $externa['include'],
							$parametros, $resultados, $externa['sincro_continua']);					
				}
			}
		}		
	}

	/**
	 * @ignore 
	 */
	protected function activar_control_valores_unicos()
	{
		foreach( $this->_info_valores_unicos as $regla ) {
			if(isset($regla['columnas'])) {
				$columnas = explode(',',$regla['columnas']);
				$columnas = array_map('trim', $columnas);
				$this->set_no_duplicado( $columnas );
			}
		}
	}
	
	/**
	 * Reserva un id interno y lo retorna
	 */
	function reservar_id_fila()
	{
		$actual = $this->_proxima_fila;
		$this->_proxima_fila++;
		return $actual;
	}

	/**
	 * Retorna el proximo id interno a ser utilizado
	 */
	function get_proximo_id()
	{
		return $this->_proxima_fila;	
	}
		
	//-------------------------------------------------------------------------------
	//--  Relacion con otros ELEMENTOS
	//-------------------------------------------------------------------------------

	/**
	 * Informa a la tabla que existe una tabla padre
	 * @param toba_relacion_entre_tablas $relacion
	 * @ignore 
	 */
	function agregar_relacion_con_padre($relacion, $id_padre)
	{
		$this->_relaciones_con_padres[$id_padre] = $relacion;
	}
	
	/**
	 * Retorna las relaciones con las tablas padre
	 * @return array de {@link toba_relacion_entre_tablas toba_relacion_entre_tablas}
	 * @ignore 
	 */
	function get_relaciones_con_padres()
	{
		return $this->_relaciones_con_padres;
	}

	/**
	 * Retorna la relaci�n con una tabla padre
	 * @return {@link toba_relacion_entre_tablas toba_relacion_entre_tablas}
	 * @ignore 
	 */	
	function get_relacion_con_padre($id_tabla_padre)
	{
		return $this->_relaciones_con_padres[$id_tabla_padre];	
	}
	
	/**
	 * Informa a la tabla que existe una tabla hija de la actual
	 * @param toba_relacion_entre_tablas $relacion
	 * @ignore 
	 */	
	function agregar_relacion_con_hijo($relacion, $id_hijo)
	{
		$this->_relaciones_con_hijos[$id_hijo] = $relacion;
	}

	/*
		***  Notificaciones  ***
	*/

	private function notificar_contenedor($evento, $param1=null, $param2=null)
	{
		if(isset($this->controlador)){
			//$this->_contenedor->registrar_evento($this->_id, $evento, $param1, $param2);
		}
	}

	/**
	 * Aviso a las relacion padres que el componente HIJO se CARGO
	 * @ignore 
	 */
	function notificar_padres_carga($reg_hijos=null)
	{
		if(isset($this->_relaciones_con_padres)){
			foreach ($this->_relaciones_con_padres as $relacion) {
				$relacion->evt__carga_hijo($reg_hijos);
			}
		}
	}

	/**
	 * Aviso a las relaciones hijas que el componente PADRE sincrozo sus actualizaciones
	 * @ignore 
	 */
	function notificar_hijos_sincronizacion()
	{
		if(isset($this->_relaciones_con_hijos)){
			foreach ($this->_relaciones_con_hijos as $relacion) {
				$relacion->evt__sincronizacion_padre();
			}
		}
	}


	/**
	 * Retorna la {@link toba_datos_relacion relacion} que contiene a esta tabla, si existe
	 * @return toba_datos_relacion
	 */
	function get_relacion()
	{
		if (isset($this->controlador)) {
			return $this->controlador;		
		}
	}

	/**
	 * Retorna un objeto en el cual se puede realizar busquedas complejas de registros en memoria
	 * @return toba_datos_busqueda
	 */
	function nueva_busqueda()
	{
		return new toba_datos_busqueda($this->controlador, $this);		
	}

	//-------------------------------------------------------------------------------
	//-- Preguntas BASICAS
	//-------------------------------------------------------------------------------

	/**
	 *	Retorna las columnas que son claves en la tabla
	 */
	function get_clave()
	{
		return $this->_clave;
	}
	
	/**
	 * Retorna el valor de la clave para un fila dada
	 * @param mixed $id_fila Id. interno de la fila
	 * @return array Valores de las claves para esta fila, en formato RecordSet
	 */
	function get_clave_valor($id_fila)
	{
		foreach( $this->_clave as $columna ){
			$temp[$columna] = $this->get_fila_columna($id_fila, $columna);
		}	
		return $temp;
	}

	/**
	 * Retorna la cantidad maxima de filas que puede contener la tabla (si existe tal restriccion)
	 * @return integer, 0 si no hay tope
	 */
	function get_tope_max_filas()
	{
		return $this->_tope_max_filas;	
	}


	/**
	 * Retorna la cantidad minima de fila que debe contener la tabla (si existe tal restriccion)
	 * @return integer, 0 si no hay tope
	 */	
	function get_tope_min_filas()
	{
		return $this->_tope_min_filas;	
	}

	/**
	 * Retorna la cantidad de filas que sufrieron cambios desde la carga, y por lo tanto se van a sincronizar
	 * @return integer 
	 */
	function get_cantidad_filas_a_sincronizar()
	{
		$cantidad = 0;
		foreach(array_keys($this->_cambios) as $fila){
			if( ($this->_cambios[$fila]['estado'] == "d") ||
				($this->_cambios[$fila]['estado'] == "i") ||
				($this->_cambios[$fila]['estado'] == "u") ){
				$cantidad++;
			}
		}
		return $cantidad;
	}

	/**
	 * Retorna lasfilas que sufrieron cambios desde la carga
	 * @param array $cambios Combinaci�n de tipos de cambio a buscar: d, i o u  (por defecto los tres)
	 * @return array Ids. internos
	 */
	function get_id_filas_a_sincronizar( $cambios=array("d","i","u") )
	{
		$ids = array();
		foreach(array_keys($this->_cambios) as $fila){
			if( in_array($this->_cambios[$fila]['estado'], $cambios) ){
				$ids[] = $fila;
			}
		}
		return $ids;
	}

	//-------------------------------------------------------------------------------
	//-- Configuracion
	//-------------------------------------------------------------------------------

	/**
	 * Cambia la cantidad maxima de filas que puede contener la tabla
	 * @param integer $cantidad 0 si no hay tope
	 */	
	function set_tope_max_filas($cantidad)
	{
		if ($cantidad == '')
			$cantidad = 0;		
		if(is_numeric($cantidad) && $cantidad >= 0){
			$this->_tope_max_filas = $cantidad;	
			if ($cantidad != 1) {
				$this->set_es_unico_registro(false);	
			}
		}else{
			throw new toba_error("El valor especificado en el TOPE MAXIMO de registros es incorrecto");
		}
	}

	/**
	 * Cambia la cantidad m�nima de filas que debe contener la tabla
	 * @param integer $cantidad 0 si no hay tope
	 */		
	function set_tope_min_filas($cantidad)
	{
		if ($cantidad == '')
			$cantidad = 0;
		if(is_numeric($cantidad) && $cantidad >= 0){
			$this->_tope_min_filas = $cantidad;
		}else{
			throw new toba_error("El valor especificado en el TOPE MINIMO de registros es incorrecto");
		}
	}

	/**
	 * Indica una combinacion de columnas cuyos valores no deben duplicarse (similar a un unique de sql)
	 */
	function set_no_duplicado( $columnas )
	{
		$this->_no_duplicado[] = $columnas;
	}

	function set_es_unico_registro($unico)
	{
		$this->_es_unico_registro = $unico;	
	}
	
	//-------------------------------------------------------------------------------
	//-- MANEJO DEL CURSOR INTERNO---------------------------------------------------
	//-------------------------------------------------------------------------------
	
	/**
	 * Fija el cursor en una fila dada
	 * Cuando la tabla tiene un cursor muchas de sus operaciones empiezan a tratar a esta fila como la �nica 
	 * y sus tablas padres e hijas tambi�n. Por ejemplo al pedir las filas de la tabla hija solo retorna aquellas filas hijas del registro cursor de la tabla padre.
	 * @param mixed $id Id. interno de la fila
	 */
	function set_cursor($id)
	{
		$id = $this->normalizar_id($id);
		if( $this->existe_fila($id) ){
			$this->_cursor_original = isset($this->_cursor) ? $this->_cursor : null;
			$this->_cursor = $id;	
			$this->log("Nuevo cursor '{$this->_cursor}' en reemplazo del anterior '{$this->_cursor_original}'");
		}else{
			throw new toba_error($this->get_txt() . "La fila '$id' no es valida");
		}
	}	
	
	/**
	 * Deshace el ultimo seteo de cursor
	 */
	function restaurar_cursor()
	{
		$this->_cursor = $this->_cursor_original;
		$this->log("Se restaura el cursor '{$this->_cursor_original}'");		
	}

	
	/**
	 * Asegura que el cursor no se encuentre posicionado en ninguna fila espec�fica
	 */
	function resetear_cursor()
	{
		unset($this->_cursor);
		$this->log("Se resetea el cursor");				
	}
	
	/**
	 * Retorna el Id. interno de la fila donde se encuentra actualmente el cursor de la tabla
	 * @return mixed
	 */
	function get_cursor()
	{
		if(isset($this->_cursor)){
			return $this->_cursor;
		}	
	}

	/**
	 * Hay una fila seleccionada por el cursor?
	 */
	function hay_cursor()
	{
		return isset($this->_cursor);
	}
	
	//-------------------------------------------------------------------------------
	//-- ACCESO a FILAS   -----------------------------------------------------------
	//-------------------------------------------------------------------------------

	/**
	 * Retorna el conjunto de filas que respeta las condiciones dadas
	 * Por defecto la b�squeda es afectada por la presencia de cursores en las tablas padres.
	 * @param array $condiciones Se utiliza este arreglo campo=>valor y se retornan los registros que cumplen (con condicion de igualdad) con estas restricciones
	 * @param boolean $usar_id_fila Hace que las claves del array resultante sean las claves internas del datos_tabla. Sino se usa una clave posicional y la clave viaja en la columna apex_datos_clave_fila
	 * @param boolean $usar_cursores Este conjunto de filas es afectado por la presencia de cursores en las tablas padres
	 * @return array Formato tipo RecordSet
	 */
	function get_filas($condiciones=null, $usar_id_fila=false, $usar_cursores=true)
	{
		$datos = array();
		$a = 0;
		foreach( $this->get_id_fila_condicion($condiciones, $usar_cursores) as $id_fila )
		{
			if($usar_id_fila){
				$datos[$id_fila] = $this->_datos[$id_fila];
			}else{
				$datos[$a] = $this->_datos[$id_fila];
				//esta columna indica cual fue la clave del registro
				$datos[$a][apex_datos_clave_fila] = $id_fila;
			}
			$a++;
		}
		return $datos;
	}
	
	/**
	 * Retorna los ids de todas las filas (sin eliminar) de esta tabla
	 * @param boolean $usar_cursores Este conjunto de filas es afectado por la presencia de cursores en las tablas padres
	 * @return array()
	 * @todo Se podr�a optimizar este m�todo para no recaer en tantos recorridos
	 */
	function get_id_filas($usar_cursores=true)
	{
		$coincidencias = array();
		foreach(array_keys($this->_cambios) as $id_fila){
			if($this->_cambios[$id_fila]['estado']!="d"){
				$coincidencias[] = $id_fila;
			}
		}
		if ($usar_cursores) {
			//Si alg�n padre tiene un cursor posicionado, 
			//se restringe a solo las filas que son hijas de esos cursores
			foreach ($this->_relaciones_con_padres as $id => $rel_padre) {
				$coincidencias = $rel_padre->filtrar_filas_hijas($coincidencias);
			}
		}
		return $coincidencias;		
	}
	
	/**
	 * Retorna los padres de un conjunto de registros especificos
	 */
	function get_id_padres($ids_propios, $tabla_padre)
	{
		$salida = array();
		foreach ($ids_propios as $id_propio) {
			$id_padre = $this->get_id_fila_padre($tabla_padre, $id_propio);
			if ($id_padre !== null) {
				$salida[] = $id_padre;	
			}
		}
		return array_unique($salida);
	}
	
	/**
	* Busca en una tabla padre el id de fila padre que corresponde a la fila hija especificada
	*/
	function get_id_fila_padre($tabla_padre, $id_fila)
	{
		$id_fila = $this->normalizar_id($id_fila);
		if(!isset($this->_relaciones_con_padres[$tabla_padre])) {
			throw new toba_error("La tabla padre '$tabla_padre' no existe");	
		}
		return $this->_relaciones_con_padres[$tabla_padre]->get_id_padre($id_fila);
	}
	
	
	/**
	 * Busca los registros en memoria que cumplen una condicion.
	 * Solo se chequea la condicion de igualdad. No se chequean tipos
	 * @param array $condiciones Asociativo de campo => valor.
	 *  			Para condiciones m�s complejas (no solo igualdad) puede ser array($columna, $condicion, $valor), 
	 * 				por ejemplo array(array('id_persona','>=',10),...)
	 * @param boolean $usar_cursores Este conjunto de filas es afectado por la presencia de cursores en las tablas padres* 
	 * @return array Ids. internos de las filas, pueden no estar numerado correlativamente
	 */	
	function get_id_fila_condicion($condiciones=null, $usar_cursores=true)
	{	
		//En principio las coincidencias son todas las filas
		$coincidencias = $this->get_id_filas($usar_cursores);
		//Si hay condiciones, se filtran estas filas
		if(isset($condiciones)){
			//Controlo que todas los campos que se utilizan para el filtrado existan
			foreach( array_keys($condiciones) as $columna){

			}
			foreach($coincidencias as $pos => $id_fila){
				//Verifico las condiciones
				foreach( array_keys($condiciones) as $campo){
					if (is_array($condiciones[$campo])) {
						list($columna, $operador, $valor) = $condiciones[$campo];
					} else {
						$columna = $campo;
						$operador = '==';						
						$valor = $condiciones[$campo];
					}					
					if( !isset($this->_columnas[$columna]) ){
						throw new toba_error("El campo '$columna' no existe. No es posible filtrar por dicho campo");
					}
					if (! comparar($this->_datos[$id_fila][$columna], $operador, $valor)) {
						//Se filtra la fila porque no cumple las condiciones
						unset($coincidencias[$pos]);
						break;
					}
				}
			}
		}
		return array_values( $coincidencias );
	}

	/**
	 * Retorna el contenido de una fila, a partir de su clave interna
	 * @param mixed $id Id. interno de la fila en memoria
	 * @return array columna => valor. En caso de no existir la fila retorna NULL
	 */
	function get_fila($id)
	{
		$id = $this->normalizar_id($id);
		if(isset($this->_datos[$id])){
			$temp = $this->_datos[$id];
			$temp[apex_datos_clave_fila] = $id;	//incorporo el ID del dbr
			return $temp;
		}else{
			return null;
			//throw new toba_error("Se solicito un registro incorrecto");
		}
	}

	/**
	 * Retorna el valor de una columna en una fila dada
	 * @param mixed $id Id. interno de la fila
	 * @param string $columna Nombre de la columna
	 * @return mixed En caso de no existir, retorna NULL
	 */
	function get_fila_columna($id, $columna)
	{
		$id = $this->normalizar_id($id);
		if(isset($this->_datos[$id][$columna])){
			return  $this->_datos[$id][$columna];
		}else{
			return null;
		}
	}
	
	/**
	 * Retorna los valores de una columna espec�fica
	 * El conjunto de filas utilizado es afectado por la presencia de cursores en las tablas padres
	 * @param string $columna Nombre del campo o columna
	 * @return array Arreglo plano de valores
	 */
	function get_valores_columna($columna)
	{
		$temp = array();
		foreach($this->get_id_filas() as $fila){
			$temp[] = $this->_datos[$fila][$columna];
		}
		return $temp;
	}
	
	/**
	 * Retorna el valor de la columna de la fila actualmente seleccionada como cursor
	 * @param string $columna Id. de la columna que contiene el valor a retornar
	 * @return mixed NULL si no cursor o no hay filas
	 */	
	function get_columna($columna)
	{
		if ($this->get_cantidad_filas() == 0) {
			return null;
		} elseif ($this->hay_cursor()) {
			return $this->get_fila_columna($this->get_cursor(), $columna);
		} else {
			throw new toba_error("No hay posicionado un cursor en la tabla, no es posible determinar la fila actual");
		}		
	}
	
	/**
	 * Cantidad de filas que tiene la tabla en memoria
	 * El conjunto de filas utilizado es afectado por la presencia de cursores en las tablas padres
	 * @return integer
	 */
	function get_cantidad_filas()
	{
		return count($this->get_id_filas());
	}
	
	/**
	 * Existe una determina fila? (la fila puede estar marcada como para borrar)
	 * @param mixed $id Id. interno de la fila
	 * @return boolean
	 */
	function existe_fila($id)
	{
		$id = $this->normalizar_id($id);
		if(! isset($this->_datos[$id]) ){
			return false;			
		}
		if($this->_cambios[$id]['estado']=="d"){
			return false;
		}
		return true;
	}

	/**
	 * Valida un id interno y a la vez permite aceptarlo como parte de un arreglo en
	 * la columna apex_datos_clave_fila
	 * @ignore 
	 */
	protected function normalizar_id($id)
	{
		if(!is_array($id)){
			return $id;	
		}else{
			if(isset($id[apex_datos_clave_fila])){
				return $id[apex_datos_clave_fila];
			}
		}
		throw new toba_error($this->get_txt() . ' La clave tiene un formato incorrecto.');
	}

	//-------------------------------------------------------------------------------
	//-- ALTERACION de FILAS  ------------------------------------------------------
	//-------------------------------------------------------------------------------

	/**
	 * Crea una nueva fila en la tabla en memoria
	 *
	 * @param array $fila Asociativo campo=>valor a insertar
	 * @param mixed $ids_padres Asociativo padre =>id de las filas padres de esta nueva fila, 
	 * 						  en caso de que no se brinde, se utilizan los cursores actuales en estas tablas padres
	 * @param integer $id_nuevo Opcional. Id interno de la nueva fila, si no se especifica (recomendado)
	 * 								Se utiliza el proximo id interno.
	 * @return mixed Id. interno de la fila creada
	 */
	function nueva_fila($fila=array(), $ids_padres=null, $id_nuevo=null)
	{
		if( $this->_tope_max_filas != 0){
			$this->control_tope_maximo_filas($this->get_cantidad_filas() + 1);
		}
		$this->notificar_contenedor("ins", $fila);
		//Saco el campo que indica la posicion del registro
		if(isset($fila[apex_datos_clave_fila])) unset($fila[apex_datos_clave_fila]);
		$this->validar_fila($fila);
		//SI existen columnas externas, completo la fila con las mismas
		if($this->_posee_columnas_ext){
			$campos_externos = $this->get_persistidor()->completar_campos_externos_fila($fila,"ins");
			foreach($campos_externos as $id => $valor) {
				$fila[$id] = $valor;
			}
		}
		
		//---Se le asigna un id a la fila
		if (!isset($id_nuevo) || $id_nuevo < $this->_proxima_fila) {
			$id_nuevo = $this->_proxima_fila;
		}
		$this->_proxima_fila = $id_nuevo + 1;
				
		//Se notifica a las relaciones del alta
		foreach ($this->_relaciones_con_padres as $padre => $relacion) {
			$id_padre = null;
			if (isset($ids_padres[$padre])) {
				$id_padre = $ids_padres[$padre];
			}
			$relacion->asociar_fila_con_padre($id_nuevo, $id_padre);							
		}
		
		//Se agrega la fila
		$this->_datos[$id_nuevo] = $fila;
		$this->registrar_cambio($id_nuevo,"i");
		
		return $id_nuevo;
	}

	/**
	 * Modifica los valores de una fila de la tabla en memoria
	 * Solo se modifican los valores de las columnas enviadas y que realmente cambien el valor de la fila.
	 * @param mixed $id Id. interno de la fila a modificar
	 * @param array $fila Contenido de la fila, en formato columna=>valor, puede ser incompleto
	 * @param array $nuevos_padres Arreglo (id_tabla_padre => $id_fila_padre, ....), solo se cambian los padres que se pasan por par�metros
	 * 				El resto de los padres sigue con la asociaci�n anterior
	 * @return mixed Id. interno de la fila modificada
	 */
	function modificar_fila($id, $fila, $nuevos_padres=null)
	{
		$id = $this->normalizar_id($id);
		if (!$this->existe_fila($id)){
			$mensaje = $this->get_txt() . " MODIFICAR. No existe un registro con el INDICE indicado ($id)";
			toba::logger()->error($mensaje);
			throw new toba_error($mensaje);
		}
		//Saco el campo que indica la posicion del registro
		if(isset($fila[apex_datos_clave_fila])) unset($fila[apex_datos_clave_fila]);
		$this->validar_fila($fila, $id);
		$this->notificar_contenedor("pre_modificar", $fila, $id);
		
		//Actualizo los valores
		$alguno_modificado = false;
		$fila_anterior = $this->_datos[$id];
		foreach(array_keys($fila) as $clave){
			if (isset($this->_datos[$id][$clave])) {
				//--- Comparacion por igualdad estricta con un cast a string
				$modificar = ((string) $this->_datos[$id][$clave] !== (string) $fila[$clave]);
			} else {
				//--- Si antes era null, se modifica si ahora no es null!
				$modificar = isset($fila[$clave]);
			}
			if ($modificar) {
				$alguno_modificado = true;
				$this->_datos[$id][$clave] = $fila[$clave];
			}
		}
		//--- Esto evita propagar cambios que en realidad no sucedieron
		if ($alguno_modificado) {
			if($this->_cambios[$id]['estado']!="i"){
				$this->registrar_cambio($id,"u");
			}
			
			/*
				Como los campos externos pueden necesitar una campo que no entrego la
				interface, primero actualizo los valores y despues tomo la fila y la
				proceso con la actualizacion de campos externos
			*/
			//Si la tabla posee campos externos, le pido la nueva fila al persistidor
			if($this->_posee_columnas_ext){
				$campos_externos = $this->get_persistidor()->completar_campos_externos_fila($this->_datos[$id],"upd");
				foreach($campos_externos as $clave => $valor){
					$this->_datos[$id][$clave] = $valor;
				}
			}
		}
		$this->notificar_contenedor("post_modificar", $fila, $id);
		if (isset($nuevos_padres)) {
			$this->cambiar_padre_fila($id, $nuevos_padres);
		}
		return $id;
	}

	/**
	 * Cambia los padres de una fila
	 * @param mixed $id_fila 
	 * @param array $nuevos_padres Arreglo (id_tabla_padre => $id_fila_padre, ....), solo se cambian los padres que se pasan por par�metros
	 * 				El resto de los padres sigue con la asociaci�n anterior
	 */
	function cambiar_padre_fila($id_fila, $nuevos_padres)
	{
		$id = $this->normalizar_id($id_fila);		
		if (!$this->existe_fila($id)){
			$mensaje = $this->get_txt() . " CAMBIAR PADRE. No existe un registro con el INDICE indicado ($id)";
			toba::logger()->error($mensaje);
			throw new toba_error($mensaje);
		}
		$cambio_padre = false;
		foreach ($nuevos_padres as $tabla_padre => $id_padre) {
			if (!isset($this->_relaciones_con_padres[$tabla_padre])) {
				$mensaje = $this->get_txt() . " CAMBIAR PADRE. No existe una relaci�n padre $tabla_padre.";
				throw new toba_error($mensaje);
			}
			if ($this->_relaciones_con_padres[$tabla_padre]->set_padre($id_fila, $id_padre)) {
				$cambio_padre = true;	
			}
		}
		//-- Si algun padre efectivamente cambio, tengo que marcar al registro como actualizado
		if ($cambio_padre) {
			if($this->_cambios[$id_fila]['estado']!="i"){
				$this->registrar_cambio($id_fila,"u");
			}
		}
	}
	
	/**
	 * Elimina una fila de la tabla en memoria
	 * En caso de que la fila sea el cursor actual de la tabla, este ultimo se resetea
	 * @param mixed $id Id. interno de la fila a eliminar
	 * @return Id. interno de la fila eliminada
	 */
	function eliminar_fila($id)
	{
		$id = $this->normalizar_id($id);
		if (!$this->existe_fila($id)) {
			$mensaje = $this->get_txt() . " ELIMINAR. No existe un registro con el INDICE indicado ($id)";
			toba::logger()->error($mensaje);
			throw new toba_error($mensaje);
		}
		if ( $this->get_cursor() == $id ) { 
 			$this->resetear_cursor();        
		}
 		$this->notificar_contenedor("pre_eliminar", $id);
		//Se notifica la eliminaci�n a las relaciones
		foreach ($this->_relaciones_con_hijos as $rel) {
			$rel->evt__eliminacion_fila_padre($id);
		}
		foreach ( $this->_relaciones_con_padres as $rel) {
			$rel->evt__eliminacion_fila_hijo($id);			
		}
		if($this->_cambios[$id]['estado']=="i"){
			unset($this->_cambios[$id]);
			unset($this->_datos[$id]);
		}else{
			$this->registrar_cambio($id,"d");
		}
		$this->notificar_contenedor("post_eliminar", $id);
		return $id;
	}

	/**
	 * Elimina todas las filas de la tabla en memoria
	 * @param boolean $con_cursores Tiene en cuenta los cursores del padre para afectar solo sus filas hijas, por defecto utiliza cursores. 
	 */
	function eliminar_filas($con_cursores = true)
	{
		foreach($this->get_id_filas($con_cursores) as $fila) {
			$this->eliminar_fila($fila);
		}
	}

	/**
	 * Cambia el valor de una columna de una fila especifica
	 *
	 * @param mixed $id Id. interno de la fila de la tabla en memoria
	 * @param string $columna Columna o campo de la fila
	 * @param mixed $valor Nuevo valor
	 */
	function set_fila_columna_valor($id, $columna, $valor)
	{
		$id = $this->normalizar_id($id);
		if( $this->existe_fila($id) ){
			if( isset($this->_columnas[$columna]) ){
				$this->modificar_fila($id, array($columna => $valor));
			}else{
				throw new toba_error("La columna '$columna' no es valida");
			}
		}else{
			throw new toba_error("La fila '$id' no es valida");
		}
	}

	/**
	 * Cambia el valor de una columna en todas las filas
	 * 
	 * @param string $columna Nombre de la columna a modificar
	 * @param mixed $valor Nuevo valor comun a toda la columna
	 * @param boolean $con_cursores Tiene en cuenta los cursores del padre para afectar sus filas hijas, por defecto no
	 */
	function set_columna_valor($columna, $valor, $con_cursores=false)
	{
		if(! isset($this->_columnas[$columna]) ) { 
			throw new toba_error("La columna '$columna' no es valida");
		}
		foreach($this->get_id_filas($con_cursores) as $fila) {
			$this->modificar_fila($fila, array($columna => $valor));
		}		
	}

	/**
	 * Procesa los cambios masivos de filas
	 * 
	 * El id de la fila se asume que la key del registro o la columna apex_datos_clave_fila
	 * Para procesar es necesario indicar el estado de cada fila utilizando una columna referenciada con la constante 'apex_ei_analisis_fila' los valores pueden ser:
	 *  - 'A': Alta
	 *  - 'B': Baja
	 *  - 'M': Modificacion
	 *
	 * @param array $filas Filas en formato RecordSet, cada registro debe contener un valor para la constante apex_ei_analisis_fila
	 */
	function procesar_filas($filas)
	{
		toba_asercion::es_array($filas,"toba_datos_tabla - El parametro no es un array.");
		//--- Controlo estructura
		foreach(array_keys($filas) as $id){
			if(!isset($filas[$id][apex_ei_analisis_fila])){
				throw new toba_error("Para procesar un conjunto de registros es necesario indicar el estado ".
									"de cada uno utilizando una columna referenciada con la constante 'apex_ei_analisis_fila'.
									Si los datos provienen de un ML, active la opci�n de analizar filas.");
			}
		}
		//--- El id de la fila se asume que la key del registro o la columna apex_datos_clave_fila
		foreach ($filas as $id => $fila) {
			$id_explicito = false;
			if (isset($fila[apex_datos_clave_fila])) {
				$id = $fila[apex_datos_clave_fila];
				$id_explicito = true;
			}	
			$accion = $fila[apex_ei_analisis_fila];
			unset($fila[apex_ei_analisis_fila]);
			switch($accion){
				case "A":
					//--- Si el ML notifico explicitamente el id, este es el id de la nueva fila, sino usa el mecanismo interno
					$nuevo_id = ($id_explicito) ? $id : null;
					$this->nueva_fila($fila,null, $nuevo_id);
					break;	
				case "B":
					$this->eliminar_fila($id);
					break;	
				case "M":
					$this->modificar_fila($id, $fila);
					break;	
			}
		}
	}

	//-------------------------------------------------------------------------------
	//-- Simplificaci�n sobre una sola l�nea
	//-------------------------------------------------------------------------------

	/**
	 * Cambia el contenido de la fila donde se encuentra el cursor interno
	 * Si la tabla se definio admitiendo a lo sumo un registro, este cursor se posiciona autom�ticamente en la carga, sino se debe explicitar con el m�todo set_cursor
	 * En caso que no existan filas, se crea una nueva y se posiciona el cursor en ella
	 * Si la fila es null, se borra la fila actual
	 *
	 * @param array $fila Contenido total o parcial de la fila a crear o modificar (si es null borra la fila actual)
	 */
	function set($fila)
	{
		if($this->hay_cursor()){
			if (isset($fila)) {
				$this->modificar_fila($this->get_cursor(), $fila);
			} else {
				$this->eliminar_fila($this->get_cursor());
			}
		} else {
			if (isset($fila)) {
				$id = $this->nueva_fila($fila);
				$this->set_cursor($id);
			}
		}
	}
	
	/**
	 * Retorna el contenido de la fila donde se encuentra posicionado el cursor interno
	 * Si la tabla se definio admitiendo a lo sumo un registro, este cursor se posiciona autom�ticamente en la carga, sino se debe explicitar con el m�todo set_cursor
	 * En caso de que no haya registros retorna NULL
	 */
	function get()
	{
		if ($this->get_cantidad_filas() == 0) {
			return null;
		} elseif ($this->hay_cursor()) {
			return $this->get_fila($this->get_cursor());
		} else {
			throw new toba_error("No hay posicionado un cursor en la tabla, no es posible determinar la fila actual");
		}
	}

	//-------------------------------------------------------------------------------
	//-- VALIDACION en LINEA
	//-------------------------------------------------------------------------------

	/**
	 * Valida un registro durante el procesamiento
	 */
	private function validar_fila($fila, $id=null)
	{
		if(!is_array($fila)){
			throw new toba_error($this->get_txt() . ' La fila debe ser una array');	
		}
		$this->evt__validar_ingreso($fila, $id);
		$this->control_estructura_fila($fila);
		$this->control_valores_unicos_fila($fila, $id);
	}

	/**
	 * Ventana de validacion que se invoca cuando se crea o modifica una fila en memoria
	 * @param array $fila Datos de la fila
	 * @param mixed $id Id. interno de la fila, si tiene (en el caso modificacion de la fila)
	 * 
	 * @ventana
	 */
	protected function evt__validar_ingreso($fila, $id=null){}

	//-------------------------------------------------------------------------------

	/**
	 * Controla que los campos del registro existan
	 * @ignore 
	 */
	protected function control_estructura_fila($fila)
	{
		foreach($fila as $campo => $valor){
			//SI el registro no esta en la lista de manipulables o en las secuencias...
			if( !(isset($this->_columnas[$campo]))  ){
				$mensaje = $this->get_txt() . get_class($this)." El registro tiene una estructura incorrecta: El campo '$campo' ". 
						" no forma parte de la DEFINICION.";
				toba::logger()->warning($mensaje);
			}
		}
	}
	//-------------------------------------------------------------------------------

	/**
	 * Controla que un registro no duplique los valores existentes
	 */
	private function control_valores_unicos_fila($fila, $id=null)
	//Controla que un registro no duplique los valores existentes
	{
		if(isset($this->_no_duplicado))	
		{	//La iteracion de afuera es por cada constraint, 
			//si hay muchos es ineficiente, pero en teoria hay pocos (en general 1)
			foreach($this->_no_duplicado as $columnas){
				foreach(array_keys($this->_cambios) as $id_fila)	{
					//a) La operacion es una modificacion y estoy comparando con el registro contra su original
					if( isset($id) && ($id_fila == $id)) continue; //Sigo con el proximo
					//b) Comparo contra otro registro, que no este eliminado
					if($this->_cambios[$id_fila]['estado']!="d"){
						$combinacion_existente = true;
						foreach($columnas as $columna)
						{
							if(!isset($fila[$columna])){
								//Si las columnas del constraint no estan completas, fuera
								return;
							}else{
								if($fila[$columna] != $this->_datos[$id_fila][$columna]){
									$combinacion_existente = false;
								}
							}
						}
						if($combinacion_existente){
							throw new toba_error($this->get_txt().": Error de valores repetidos en columna '$columna'");
						}
					}
				}				
			}
		}
	}
	
	//-------------------------------------------------------------------------------
	//-- VALIDACION global
	//-------------------------------------------------------------------------------

	/**
	 * Validacion de toda la tabla necesaria previa a la sincronizaci�n
	 */
	function validar()
	{
		$ids = $this->get_id_filas_a_sincronizar( array("u","i") );
		if(isset($ids)){
			foreach($ids as $id){
				//$this->control_nulos($fila);
				$this->evt__validar_fila( $this->_datos[$id] );
			}
		}
		$this->control_tope_minimo_filas();
	}
	
	/**
	 * Ventana para hacer validaciones particulares previo a la sincronizaci�n
	 * El proceso puede ser abortado con un toba_error, el mensaje se muestra al usuario
	 * @param array $fila Asociativo clave-valor de la fila a validar
	 * 
	 * @ventana
	 */
	function evt__validar_fila($fila){}

	/*
		Controles previos a la sincronizacion
		Esto va a aca o en el AP??
	*/
/*
	private function control_nulos($fila)
	//Controla que un registro posea los valores OBLIGATORIOS
	{
		$mensaje_usuario = "El elemento posee valores incompletos";
		$mensaje_programador = $this->get_txt() . " Es necesario especificar un valor para el campo: ";
		if(isset($this->_campos_no_nulo)){
			foreach($this->_campos_no_nulo as $campo){
				if(isset($fila[$campo])){
					if((trim($fila[$campo])=="")||(trim($fila[$campo])=='NULL')){
						toba::logger()->error($mensaje_programador . $campo);
						throw new toba_error($mensaje_usuario . " ('$campo' se encuentra vacio)");
					}
				}else{
						toba::logger()->error($mensaje_programador . $campo);
						throw new toba_error($mensaje_usuario . " ('$campo' se encuentra vacio)");
				}
			}
		}
	}
*/
	/**
	 * Valida que la cantidad de filas supere el m�nimo establecido
	 */
	protected function control_tope_minimo_filas()
	{
		$control_tope_minimo=true;
		if($control_tope_minimo){
			if( $this->_tope_min_filas != 0){
				if( ( $this->get_cantidad_filas() < $this->_tope_min_filas) ){
					$this->log("No se cumplio con el tope minimo de registros necesarios" );
					throw new toba_error("La tabla <em>{$this->_id_en_controlador}</em> requiere ingresar al menos {$this->_tope_min_filas} registro/s (se encontraron
					s�lo {$this->get_cantidad_filas()}).");
				}
			}
		}
	}

	/**
	 * Valida que la cantidad de filas a crear no supere el maximo establecido
	 */	
	protected function control_tope_maximo_filas($cantidad)
	{
		if ($cantidad > $this->_tope_max_filas) {
			throw new toba_error("No est� permitido ingresar m�s de {$this->_tope_max_filas} registros
									en la tabla <em>{$this->_id_en_controlador}</em> (se encontraron $cantidad).");
		}
	}
	

	//-------------------------------------------------------------------------------
	//-- PERSISTENCIA  -------------------------------------------------------------
	//-------------------------------------------------------------------------------

	/**
	 * Retorna el admin. de persistencia que asiste a este objeto durante la sincronizaci�n
	 * @return toba_ap_tabla_db
	 */
	function get_persistidor()
	{
		if(!isset($this->_persistidor)){
			if($this->_info_estructura['ap']=='0'){
				$clase = $this->_info_estructura['ap_sub_clase'];
				$include = $this->_info_estructura['ap_sub_clase_archivo'];
				if( (trim($clase) == '' ) ){
					throw new toba_error( $this->get_txt() . "Error en la definicion");
				}
			}else{
				$clase = 'toba_'.$this->_info_estructura['ap_clase'];
				$include = $this->_info_estructura['ap_clase_archivo'];
			}
			if( ! class_exists($clase) ) {
				require_once($include);
			}			
			$this->_persistidor = new $clase( $this );
			if($this->_info_estructura['ap_modificar_claves']){
				$this->_persistidor->activar_modificacion_clave();
			}
		}
		return $this->_persistidor;
	}
	


	/**
	 * Carga la tabla restringiendo POR valores especificos de campos
	 * Si los datos contienen una unica fila, esta se pone como cursor de la tabla
	 */
	function cargar($clave=array())
	{
		return $this->get_persistidor()->cargar_por_clave($clave);
	}
	
	/**
	 * La tabla esta cargada con datos?
	 * @return boolean
	 */
	function esta_cargada()
	{
		return $this->_cargada;
	}

	/**
	 * Carga la tabla en memoria con un nuevo set de datos (se borra todo estado anterior)
	 * Si los datos contienen una unica fila, esta se pone como cursor de la tabla
	 * @param array $datos en formato RecordSet
	 */
	function cargar_con_datos($datos)
	{
		$this->log("Carga de datos");
		$this->_datos = null;
		//Controlo que no se haya excedido el tope de registros
		if( $this->_tope_max_filas != 0) {
			$this->control_tope_maximo_filas(count($datos));
		}
		$this->_datos = $datos;		
		if(false){	// Hay que pensar este esquema...
			$this->_datos_originales = $this->_datos;
		}
		//Genero la estructura de control de cambios
		$this->generar_estructura_cambios();
		//Actualizo la posicion en que hay que incorporar al proximo registro
		$this->_proxima_fila = count($this->_datos);
		//Marco la tabla como cargada
		$this->_cargada = true;
		//Si es una unica fila se pone como cursor de la tabla
		if (count($datos) == 1 && $this->_es_unico_registro) {
			$this->_cursor = 0;
		}
		//Disparo la actulizacion de los mapeos con las tablas padres
		$this->notificar_padres_carga();
	}

	/**
	 * Agrega a la tabla en memoria un nuevo set de datos (conservando el estado anterior). 
	 * Se asume que el set de datos llega desde el mecanismo de persistencia.
	 * 
	 * @param array $datos en formato RecordSet
	 * @param boolean $usar_cursores Los datos cargados se marcan como hijos de los cursores actuales en las tablas padre, sino son hijos del padre que tenia en la base 
	 */
	function anexar_datos($datos, $usar_cursores=true)
	{
		$this->log("Anexado de datos [" . count($datos) . "]");
		//Controlo que no se haya excedido el tope de registros
		if ($this->_tope_max_filas != 0) {
			$this->control_tope_maximo_filas(count($this->get_id_filas(false)) + count($datos));
		}
		//Agrego las filas
		$hijos = array();
		foreach( $datos as $fila ) {
			$this->_datos[$this->_proxima_fila] = $fila;
			$this->_cambios[$this->_proxima_fila]['estado']="db";
			$this->_cambios[$this->_proxima_fila]['clave']= $this->get_clave_valor($this->_proxima_fila);			
			if ($usar_cursores) {
				//Se notifica a las relaciones a los padres.
				foreach ($this->_relaciones_con_padres as $padre => $relacion) {
					$relacion->asociar_fila_con_padre($this->_proxima_fila, null);
	            }
			}
			$hijos[] = $this->_proxima_fila;
			$this->_proxima_fila++;            
		}
		//Marco la tabla como cargada
		$this->_cargada = true;
		if (! $usar_cursores) {
			//Disparo la actulizacion de los mapeos con las tablas padres
			$this->notificar_padres_carga($hijos);
		}
	}
		
	/**
	 * Sincroniza la tabla en memoria con el medio f�sico a trav�z del administrador de persistencia.
	 *
	 * @return integer Cantidad de registros modificados en el medio
	 */
	function sincronizar()
	{
		$this->validar();
		$modif = $this->get_persistidor()->sincronizar();
		return $modif;
	}

	/**
	 * Elimina todas las filas de la tabla en memoria y sincroniza con el medio de persistencia
	 */
	function eliminar_todo()
	{
		//Me elimino a mi
		$this->eliminar_filas();
		//Sincronizo con la base
		$this->get_persistidor()->sincronizar_eliminados();
		$this->resetear();
	}
	
	/**
	 * @deprecated Desde 0.8.4, usar eliminar_todo()
	 */
	function eliminar()
	{
		toba::logger()->obsoleto(__CLASS__, __METHOD__, "0.8.4", "Usar eliminar_todo");
		$this->eliminar_todo();	
	}

	/**
	 * Deja la tabla sin carga alguna, se pierden todos los cambios realizados desde la carga
	 */
	function resetear()
	{
		$this->log("RESET!!");
		$this->_datos = array();
		$this->_datos_originales = array();
		$this->_cambios = array();
		$this->_proxima_fila = 0;
		$this->_where = null;
		$this->_from = null;
		foreach ($this->_relaciones_con_hijos as $rel_hijo) {
			$rel_hijo->resetear();	
		}
		$this->resetear_cursor();
	}

	//-------------------------------------------------------------------------------
	//-- Comunicacion con el Administrador de Persistencia
	//-------------------------------------------------------------------------------

	/*--- Del AP a mi ---*/

	/**
	 * El AP avisa que termin�la sincronizaci�n
	 * @ignore 
	 */
	function notificar_fin_sincronizacion()
	{
		$this->regenerar_estructura_cambios();
	}

	/*--- De mi al AP ---*/

	/**
	 * @ignore 
	 */
	function get_conjunto_datos_interno()
	{
		return $this->_datos;
	}

	/**
	 * Retorna la estructura interna que mantiene registro de las modificaciones/altas/bajas producidas en memoria
	 * @ignore 
	 */
	function get_cambios()
	{
		return $this->_cambios;	
	}

	/**
	 * Retorna el nombre de las columnas de esta tabla
	 */
	function get_columnas()
	{
		return $this->_columnas;
	}
	
	/**
	 * Retorna el nombre de la {@link toba_fuente_datos fuente de datos} utilizado por este componente
	 * @return string
	 */
	function get_fuente()
	{
		return $this->_info["fuente"];
	}

	/**
	 * Nombre de la tabla que se representa en memoria
	 */
	function get_tabla()
	{
		return $this->_info_estructura['tabla'];
	}

	/**
	 * Retorna el alias utilizado para desambiguar la tabla en uniones tales como JOINs
	 * Se toma el primero seteado de: el alias definido, el rol en la relaci�n o el nombre de la tabla
	 * @return string
	 */
	function get_alias()
	{
		if (isset($this->_info_estructura['alias'])) {
			return $this->_info_estructura['alias'];	
		} elseif (isset($this->_id_en_controlador)) {
			return $this->_id_en_controlador;
		} else {
			return $this->get_tabla();
		}
	}

	/**
	 * La tabla posee alguna columna marcada como de 'carga externa'
	 * Una columna externa no participa en la sincronizaci�n posterior, pero por necesidades casi siempre est�ticas
	 * necesitan mantenerse junto al conjunto de datos.
	 * @return boolean
	 */
	function posee_columnas_externas()
	{
		return $this->_posee_columnas_ext;
	}

	//-------------------------------------------------------------------------------
	//-- Manejo de la estructura de cambios
	//-------------------------------------------------------------------------------

	/**
	 * @ignore 
	 */
	protected function generar_estructura_cambios()
	{
		//Genero la estructura de control
		$this->_cambios = array();
		foreach(array_keys($this->_datos) as $dato){
			$this->_cambios[$dato]['estado']="db";
			$this->_cambios[$dato]['clave']= $this->get_clave_valor($dato);
		}
	}
	
	/**
	 * @ignore 
	 */
	protected function regenerar_estructura_cambios()
	{
		//BORRO los datos eliminados
		foreach(array_keys($this->_cambios) as $cambio){
			if($this->_cambios[$cambio]['estado']=='d'){
				unset($this->_datos[$cambio]);
			}
		}
		$this->generar_estructura_cambios();
	}

	/**
	*	Determina que todas las filas de la tabla son nuevas
	*/
	function forzar_insercion()
	{
		foreach(array_keys($this->_cambios) as $fila) {
			$this->registrar_cambio($fila, "i");
		}
	}

	/**
	 * Fuerza una cambio directo a la estructura interna que mantiene registro de los cambios
	 * @param mixed $fila Id. interno de la fila
	 * @param string $estado
	 */
	protected function registrar_cambio($fila, $estado)
	{
		$this->_cambios[$fila]['estado'] = $estado;
	}
}

?>
