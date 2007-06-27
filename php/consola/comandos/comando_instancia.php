<?php
require_once('comando_toba.php');
/**
*	Publica los servicios de la clase INSTANCIA a la consola toba
*/
class comando_instancia extends comando_toba
{
	static function get_info()
	{
		return 'Administracion de INSTANCIAS';
	}

	function mostrar_observaciones()
	{
		$this->consola->mensaje("INVOCACION: toba instancia OPCION [-i id_instancia]");
		$this->consola->enter();
		$this->get_info_parametro_instancia();
		$this->consola->enter();
	}

	function get_info_extra()
	{
		$i = $this->get_instancia();
		try {
			$salida = "Versión: ".$i->get_version_actual()->__toString();
		} catch (toba_error_db $e) {
			$salida = $e->getMessage();
		}
		$db = $i->get_parametros_db();
		$salida .= "\nBase: {$db['profile']} / {$db['base']}";
		return $salida;
	}
		
	
	//-------------------------------------------------------------
	// Opciones
	//-------------------------------------------------------------


	/**
	* Crea una instancia NUEVA. 
	* @consola_parametros [-t mini] se crea una instancia reducida, útil para ejecutar proyectos compilados
	* @gtk_icono nucleo/agregar.gif 
	* @gtk_no_mostrar 1
	*/
	function opcion__crear($datos=null)
	{
		if (isset($datos)) {
			list($id_instancia, $tipo, $base, $proyectos, $usuario) = $datos;
		} else {
			$id_instancia = $this->get_id_instancia_actual();			
			$tipo = $this->get_tipo_instancia();
					
		}
		$instalacion = $this->get_instalacion();
		if ( toba_modelo_instancia::existe_carpeta_instancia($id_instancia) ) {
			throw new toba_error("Ya existe una INSTANCIA con el nombre '$id_instancia'");
		}
		if ( ! $instalacion->hay_bases() ) {
			throw new toba_error("Para crear una INSTANCIA, es necesario definir al menos una BASE. Utilice el comando 'toba instalacion agregar_db'");
		}
		$this->consola->titulo("Creando la INSTANCIA: $id_instancia TIPO: $tipo");

		//---- A: Creo la definicion de la instancia
		$this->consola->enter();
		if (!isset($base)) {
			$base = $this->seleccionar_base();
		}
		if (!isset($proyectos)) {
			$proyectos = $this->seleccionar_proyectos();
		}
		toba_modelo_instancia::crear_instancia( $id_instancia, $base, $proyectos, $tipo );

		//---- B: Cargo la INSTANCIA en la BASE
		$instancia = $this->get_instancia($id_instancia);
		if($tipo == 'mini') {
			$metodo_carga = 'cargar_tablas_minimas';
		} else {
			$metodo_carga = 'cargar';
		}
		try {
			$instancia->$metodo_carga();
		} catch ( toba_error_modelo_preexiste $e ) {
			$this->consola->error( 'ATENCION: Ya existe una instancia en la base de datos seleccionada' );
			$this->consola->lista( $instancia->get_parametros_db(), 'BASE' );
			if ( $this->consola->dialogo_simple('Desea ELIMINAR la instancia y luego CARGARLA (La informacion local previa se perdera!)?') ) {
				$instancia->$metodo_carga( true );
			} else {
				return;	
			}
		} catch ( toba_error $e ) {
			$this->consola->error( 'Ha ocurrido un error durante la importacion de la instancia.' );
			$this->consola->error( $e->getMessage() );
		}

		//---- C: Actualizo la versión, Creo un USUARIO y lo asigno a los proyectos
		$instancia->set_version( toba_modelo_instalacion::get_version_actual());
		$this->opcion__crear_usuario($usuario, false, $id_instancia);

		if($tipo != 'mini') {
			//---- D: Exporto la informacion LOCAL
			$instancia->exportar_local();
			//-- Agregar los alias
			$this->consola->enter();		
			$crear_alias = $this->consola->dialogo_simple("Desea crear automáticamente los alias de apache en el archivo toba.conf?", true);
			if ($crear_alias) {
				$instancia->crear_alias_proyectos();
			}
		}
	}

	/**
	* Brinda informacion sobre la instancia.
	* @gtk_icono info_chico.gif 
	* @gtk_no_mostrar 1
	*/
	function opcion__info()
	{
		$i = $this->get_instancia();
		$param = $this->get_parametros();
		$this->consola->titulo( 'INSTANCIA: ' . $i->get_id() );
		if ( isset( $param['-u'] ) ) {
			// Lista de USUARIOS
			$this->consola->subtitulo('Listado de USUARIOS');
			$this->consola->tabla( $i->get_lista_usuarios(), array( 'Usuario', 'Nombre') );
		} else {										
			// Informacion BASICA
			$this->consola->subtitulo('Informacion BASICA');
			//VERSION
			$this->consola->lista(array($i->get_version_actual()->__toString()), "VERSION");
			$this->consola->lista_asociativa( $i->get_parametros_db() , array('Parametros Conexion', 'Valores') );
			$this->consola->lista( $i->get_lista_proyectos_vinculados(), 'Proyectos Vinculados' );
			$this->consola->enter();
			$this->consola->subtitulo('Reportes');
			$subopciones = array( '-u' => 'Listado de usuarios' ) ;
			$this->consola->coleccion( $subopciones );			
		}
	}
	
	/**
	* Crea un nuevo proyecto asociado a la instancia
	* @consola_no_mostrar 1 
	* @gtk_icono nucleo/agregar.gif
	*/	
	function opcion__crear_proyecto()
	{
		//------ESTO ES UN ALIAS DE PROYECTO::CREAR
		require_once('comando_proyecto.php');
		$comando = new comando_proyecto($this->consola);
		$comando->set_id_instancia_actual($this->get_id_instancia_actual());
		$comando->opcion__crear();
	}
	
	/**
	* Crea un nuevo proyecto asociado a la instancia
	* @consola_no_mostrar 1 
	* @gtk_icono nucleo/proyecto.gif
	*/	
	function opcion__cargar_proyecto()
	{
		//------ESTO ES UN ALIAS DE PROYECTO::CARGAR
		require_once('comando_proyecto.php');
		$comando = new comando_proyecto($this->consola);
		$comando->set_id_instancia_actual($this->get_id_instancia_actual());
		$comando->opcion__cargar();		
	}	
	
	/**
	* Exporta la instancia completa incluyendo METADATOS propios y de proyectos contenidos.
	* @gtk_icono exportar.png 
	* @gtk_separador 1
	*/
	function opcion__exportar()
	{
		$this->get_instancia()->exportar();
	}

	/**
	 * Exporta los METADATOS propios de la instancia de la DB (exclusivamente la información local).
	 * @gtk_icono exportar.png	 
	 */
	function opcion__exportar_local()
	{
		$this->get_instancia()->exportar_local();
	}

	/**
	 * Elimina la instancia y la vuelve a cargar.
	 * @gtk_icono importar.png
	 */
	function opcion__regenerar()
	{
		if ($this->get_instancia()->existe_modelo()) {
			if ( $this->consola->dialogo_simple('Desea EXPORTAR antes la información local de la INSTANCIA?') ) {
				$this->opcion__exportar_local();
			}
		}
		$this->consola->enter();
		$this->opcion__eliminar();
		$this->get_instancia()->cargar();
	}

	
	/**
	* Carga una instancia en la DB referenciada, partiendo de los METADATOS en el sistema de archivos.
	* @gtk_icono importar.png 
	*/
	function opcion__cargar()
	{
		try {
			$this->get_instancia()->cargar();
		} catch ( toba_error_modelo_preexiste $e ) {
			$this->consola->error( 'Ya existe una instancia en la base de datos' );
			$this->consola->lista( $this->get_instancia()->get_parametros_db(), 'BASE' );
			if ( $this->consola->dialogo_simple('Desea ELIMINAR la instancia y luego CARGARLA?') ) {
				$this->get_instancia()->cargar( true );
			}
		} catch ( toba_error $e ) {
			$this->consola->error( 'Ha ocurrido un error durante la importacion de la instancia.' );
			$this->consola->error( $e->getMessage() );
		}
	}
	
	
	/**
	* Elimina la instancia.
	* @gtk_icono borrar.png
	*/
	function opcion__eliminar()
	{
		$i = $this->get_instancia();
		$this->consola->lista( $i->get_parametros_db(), 'BASE' );
		if ( $this->consola->dialogo_simple('Desea eliminar los datos de la INSTANCIA?') ) {
			$i->eliminar_base();
		}
		if ( $this->consola->dialogo_simple('Desea eliminar la carpeta de datos y configuración de la INSTANCIA?') ) {
			$i->eliminar_archivos();
		}		
	}

	/**
	 * Crea un usuario administrador y lo asigna a los proyectos
	 * @gtk_icono usuarios/usuario_nuevo.gif
	 * @gtk_param_extra crear_usuario
	 */
	function opcion__crear_usuario($datos=null, $asociar_previsualizacion_admin=true, $id_instancia=null)
	{
		$instancia = $this->get_instancia($id_instancia);
		if (!isset($datos)) {
			$datos = $this->definir_usuario( "Crear USUARIO" );
		}
		$instancia->agregar_usuario( $datos['usuario'], $datos['nombre'], $datos['clave'] );
		foreach( $instancia->get_lista_proyectos_vinculados() as $id_proyecto ) {
			$proyecto = $instancia->get_proyecto($id_proyecto);
			$grupo_acceso = $this->seleccionar_grupo_acceso( $proyecto );
			$proyecto->vincular_usuario( $datos['usuario'], $grupo_acceso, null, $asociar_previsualizacion_admin );
		}		
	}
	
	/**
	 * Permite cambiar los grupos de acceso de un usuario 
	 * @consola_parametros [-u usuario]
	 * @gtk_icono usuarios/grupo.gif
	 */
	function opcion__editar_acceso()
	{
		$instancia = $this->get_instancia();
		$param = $this->get_parametros();
		if ( isset($param['-u']) &&  (trim($param['-u']) != '') ) {
			$usuario = $param['-u'];
		} else {
			$usuarios = $instancia->get_lista_usuarios();
			$usuarios = rs_convertir_asociativo($usuarios, array('usuario'),'nombre');
			$usuario = $this->consola->dialogo_lista_opciones( $usuarios, 'Seleccionar Usuario', false, 'Nombre de usuario', 
														true);			
		}
		if (! isset($usuario)) {
			throw new toba_error("Es necesario indicar el usuario con '-u'");			
		}
		foreach( $instancia->get_lista_proyectos_vinculados() as $id_proyecto ) {
			$this->consola->enter();			
			$proyecto = $instancia->get_proyecto($id_proyecto);
			$grupos = $proyecto->get_lista_grupos_acceso();
			$grupos = rs_convertir_asociativo($grupos, array('id'), 'nombre');
			$grupos['ninguno'] = 'No vincular al proyecto';
			$grupo_acceso = $this->consola->dialogo_lista_opciones($grupos, "Proyecto $id_proyecto", false, 'Descripción');
			$proyecto->desvincular_usuario($usuario);
			if ($grupo_acceso != 'ninguno') {
				$proyecto->vincular_usuario( $usuario, $grupo_acceso );
			}
		}
	}
	
	/**
	 * Limpia la tabla de ips bloqueadas
	 * @gtk_icono desbloquear.png
	 */
	function opcion__desbloquear_ips()
	{
		$instancia = $this->get_instancia();
		$instancia->desbloquear_ips();
	}
	
	/**
	*	Crea una instancia en base a la informacion del sistema de archivos de otra 
	*	(La instancia 'origen' se especifica con el parametro '-o')
	*/
	function falta_opcion__duplicar()
	{
		$param = $this->get_parametros();
		if ( isset($param['-o']) &&  (trim($param['-o']) != '') ) {
			return $param['-o'];
		} else {
			throw new toba_error("Es necesario indicar el la instancia original '-o'");
		}		
	}

	/**
	 * Migra un instancia entre dos versiones toba.
	 * @consola_parametros Opcionales: [-d 'desde']  [-h 'hasta'] [-R 0|1] 
	 * @gtk_icono convertir.png
	 */
	function opcion__migrar()
	{
		$instancia = $this->get_instancia();
		//--- Parametros
		$param = $this->get_parametros();
		$desde = isset($param['-d']) ? new toba_version($param['-d']) : $instancia->get_version_actual();
		$hasta = isset($param['-h']) ? new toba_version($param['-h']) : toba_modelo_instalacion::get_version_actual();
		$recursivo = (!isset($param['-R']) || $param['-R'] == 1);
		
		if ($recursivo) {
			$texto_recursivo = " y proyectos contenidos";
		}
		$desde_texto = $desde->__toString();
		$hasta_texto = $hasta->__toString();
		$this->consola->titulo("Migración de la instancia '{$instancia->get_id()}'".$texto_recursivo." desde la versión $desde_texto hacia la $hasta_texto.");

		$versiones = $desde->get_secuencia_migraciones($hasta);
		if (empty($versiones)) {
			$this->consola->mensaje("No es necesario ejecutar una migración entre estas versiones para la instancia '{$instancia->get_id()}'");
			return ;
		}

		$instancia->migrar_rango_versiones($desde, $hasta, $recursivo);
	}

	function get_tipo_instancia()
	{
		$tipo = 'normal';
		$param = $this->get_parametros();
		if ( isset($param['-t'] ) && ( trim( $param['-t'] ) == 'mini') ) {
			$tipo = 'mini';
		}		
		return $tipo;
	}
		
	/**
	*	Genera un archivo con la lista de registros por cada tabla de la instancia
	function opcion__dump_info_tablas()
	{
		$this->get_instancia()->dump_info_tablas();
	}
	*/	
}
?>