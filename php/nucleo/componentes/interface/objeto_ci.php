<?php
require_once('objeto_ei_pantalla.php');
require_once("nucleo/componentes/interface/objeto_ei_formulario.php");
require_once("nucleo/componentes/interface/objeto_ei_cuadro.php");
require_once("nucleo/lib/interface/form.php");
require_once('nucleo/lib/parser_ayuda.php');

/**
 * Controla un flujo de pantallas
 * @package Objetos
 * @subpackage Ei
 */
class objeto_ci extends objeto_ei
{
	// General
	protected $cn=null;								// Controlador de negocio asociado
	protected $dependencias_ci_globales = array();	// Lista de todas las dependencias CI instanciadas desde el momento 0
	protected $dependencias_ci = array();			// Lista de dependencias CI utilizadas en el REQUEST
	protected $dependencias_gi = array();			// Dependencias utilizadas para la generacion de la interface
	protected $dependencias_inicializadas = array();// Lista de dependencias inicializadas
	protected $eventos;								// Lista de eventos que expone el CI
	protected $evento_actual;						// Evento propio recuperado de la interaccion
	protected $evento_actual_param;					// Parametros del evento actual
	protected $posicion_botonera;					// Posicion de la botonera en la interface
	protected $gi = false;							// Indica si el CI se utiliza para la generacion de interface
	protected $objeto_js;							// Nombre del objeto js asociado
	// Pantalla
	protected $pantalla_id_eventos;					// Id de la pantalla que se atienden eventos
	protected $pantalla_id_servicio;				// Id de la pantalla a mostrar en el servicio
	protected $pantalla_servicio;					// Comp. pantalla que se muestra en el servicio 

	function __construct($id)
	{
		$propiedades = array();
		$propiedades[] = "dependencias_ci_globales";
		$this->set_propiedades_sesion($propiedades);
		parent::__construct($id);
		$this->submit = "CI_" . $this->id[1] . "_submit";
		$this->nombre_formulario = "formulario_toba" ;//Cargo el nombre del <form>	
	}

	function destruir()
	{
		if( isset($this->pantalla_servicio) ){
			//Guardo INFO sobre la interface generada
			$this->memoria['pantalla_dep'] = $this->pantalla_servicio->get_lista_dependencias();
			$this->memoria['pantalla_servicio'] = $this->pantalla_id_servicio;
			$this->memoria['tabs'] = array_keys($this->pantalla_servicio->get_lista_tabs());
		}
		//Armo la lista GLOBAL de dependencias de tipo CI
		if(isset($this->dependencias_ci_globales)){
			$this->dependencias_ci_globales = array_merge($this->dependencias_ci_globales, $this->dependencias_ci);
		}
		parent::destruir();
	}

	function inicializar($parametro=null)
	{
		if(isset($parametro)){
			$this->nombre_formulario = $parametro["nombre_formulario"];
		}
		$this->evt__inicializar();
	}

	function evt__inicializar()
	//Antes que todo
	{
	}
	
	//--------------------------------------------------------------
	//---------  Manejo de MEMORIA -------------------------------
	//--------------------------------------------------------------
		
	/**
	 * Borra la memoria de todas las dependencias y la propia
	 */
	function disparar_limpieza_memoria()
	{
		$this->log->debug( $this->get_txt() . "[ disparar_limpieza_memoria ]", 'toba');
		foreach($this->get_dependencias_ci() as $dep){
			if( !isset($this->dependencias[$dep]) ){
				$this->inicializar_dependencias(array($dep));
			}
			$this->dependencias[$dep]->disparar_limpieza_memoria();
		}
		$this->evt__limpieza_memoria();
	}
	
	/**
	 * Borra la memoria de este CI y lo reinicializa
	 */
	function evt__limpieza_memoria($no_borrar=null)
	{
		$this->set_pantalla( $this->get_pantalla_inicial() );
		$this->borrar_memoria();
		$this->eliminar_estado_sesion($no_borrar);
		$this->evt__inicializar();
	}	
	
	//--------------------------------------------------------------
	//------  Interaccion con un CONTROLADOR de NEGOCIO ------------
	//--------------------------------------------------------------

	function asignar_controlador_negocio( $controlador )
	{
		$this->cn = $controlador;
	}

	//--  ENTRADA de DATOS ----

	function disparar_obtencion_datos_cn( $modo=null )
	{
		$this->log->debug( $this->get_txt() . "[ disparar_obtencion_datos_cn ]", 'toba');
		$this->evt__obtener_datos_cn( $modo );
		$deps = $this->get_dependencias_ci();
		foreach( $deps as $dep ){
			if( !isset($this->dependencias[$dep]) ){
				$this->inicializar_dependencias(array($dep));
			}
			$this->log->debug( $this->get_txt() . "[ disparar_obtencion_datos_cn ] ejecutar '$dep'", 'toba');
			$this->dependencias[$dep]->disparar_obtencion_datos_cn( $modo );
		}
	}

	function evt__obtener_datos_cn( $modo=null )
	{
		//Esta funcion hay que redefinirla en un hijo para OBTENER datos
		$this->log->warning($this->get_txt() . "[ evt__obtener_datos_cn ] No fue redefinido!");
	}

	//--  SALIDA de DATOS ----

	function disparar_entrega_datos_cn()
	{
		$this->log->debug( $this->get_txt() . "[ disparar_entrega_datos_cn ]", 'toba');
		//DUDA: Validar aca es redundante?
		$this->evt__validar_datos();
		$this->evt__entregar_datos_cn();
		$deps = $this->get_dependencias_ci();
		foreach( $deps as $dep ){
			if( !isset($this->dependencias[$dep]) ){
				$this->inicializar_dependencias(array($dep));
			}
			$this->log->debug( $this->get_txt() . "[ disparar_entrega_datos_cn ] ejecutar '$dep'", 'toba');
			$this->dependencias[$dep]->disparar_entrega_datos_cn();
		}
	}

	function evt__entregar_datos_cn()
	{
		//Esta funcion hay que redefinirla en un hijo para ENTREGAR datos
		$this->log->warning($this->get_txt() . "[ evt__entregar_datos_cn ] No fue redefinido!");
	}

	function get_dependencias_ci()
	// Avisa que dependencias son CI, si hay una regla ad-hoc que define que CIs cargar
	// (osea: si se utilizo el metodo 'get_lista_ei' para dicidir cual de dos dependencias de tipo CI cargar)
	// hay que redeclarar este metodo con la misma regla utilizada en 
	// por la operacion
	{
		return $this->get_dependencias_clase('objeto_ci');
	}
	
	//------------------------------------------------
	//--  ETAPA EVENTOS   ----------------------------
	//------------------------------------------------
	
	/**
	 * Se disparan los eventos propios y se les ordena a las dependencias que gatillen sus eventos
	 * Cualquier error de usuario que aparezca, sea donde sea, se atrapa en la solicitud
	 * @todo Esto esta bien? --> cuando aparece el primer error no se sigan procesando las cosas... solo se puede atrapar un error.
	 */
	function disparar_eventos()
	{
		$this->log->debug( $this->get_txt() . " disparar_eventos", 'toba');

		//PANTALLA
		$this->definir_pantalla_eventos();
		if (isset($this->pantalla_id_eventos)) {
			$this->controlar_eventos_propios();
			//Los eventos que no manejan dato tienen que controlarse antes
			if( isset($this->memoria['eventos'][$this->evento_actual]) && 
					$this->memoria['eventos'][$this->evento_actual] == false ) {
				$this->disparar_evento_propio();
			} else {
				//Disparo los eventos de las dependencias
				foreach( $this->get_dependencias_eventos() as $dep) {
					$this->dependencias[$dep]->disparar_eventos();
				}
				$this->disparar_evento_propio();
			}
		} else {
 			$this->log->debug( $this->get_txt() . "No hay se�ales de un servicio anterior, no se atrapan eventos", 'toba');
		}
		$this->definir_pantalla_servicio();
		$this->evt__post_recuperar_interaccion();		
	}

	/**
	 * Reconoce que evento del CI se ejecuto
	 */
	protected function controlar_eventos_propios()
	{
		$this->evento_actual = "";
		if(isset($_POST[$this->submit])){
			$evento = $_POST[$this->submit];
			//La opcion seleccionada estaba entre las ofrecidas?
			if(isset(  $this->memoria['eventos'][$evento] )){
				$this->evento_actual = $evento;
				$this->evento_actual_param = $_POST[$this->submit."__param"];
			}
		}
	}

	protected function disparar_evento_propio()
	{
		if($this->evento_actual != "")	{
			$metodo = apex_ei_evento . apex_ei_separador . $this->evento_actual;
			if(method_exists($this, $metodo)){
				//Ejecuto el metodo que implementa al evento
				$this->log->debug( $this->get_txt() . "[ disparar_evento_propio ] '{$this->evento_actual}' -> [ $metodo ]", 'toba');
				$this->$metodo($this->evento_actual_param);
				//Comunico el evento al contenedor
				$this->reportar_evento( $this->evento_actual );
			}else{
				$this->log->info($this->get_txt() . "[ disparar_evento_propio ]  El METODO [ $metodo ] no existe - '{$this->evento_actual}' no fue atrapado", 'toba');
			}
		}
		
		//--- El cambio de tab es un evento
		//--- Si se lanzo se determina cual es el candidato (aun falta la aprobacion)
		if (isset($_POST[$this->submit])) {
			$submit = $_POST[$this->submit];
			//Se pidio explicitamente un id de pantalla o navegar atras-adelante?
			$tab = (strpos($submit, 'cambiar_tab_') !== false) ? str_replace('cambiar_tab_', '', $submit) : false;
			if ($tab == '_siguiente' || $tab == '_anterior') {
				$this->pantalla_id_servicio = $this->ir_a_limitrofe($tab);
			} 
			if ($tab !== false && $this->puede_ir_a_pantalla($tab)) {
				if(isset($this->memoria['tabs']) && in_array($tab, $this->memoria['tabs'])){
					$this->pantalla_id_servicio = $tab;
				}else{
					toba::get_logger()->crit("No se pudo determinar los tabs anteriores, no se encuentra en la memoria sincronizada");
					//Error, voy a la pantalla inicial
					$this->pantalla_id_servicio =  $this->get_pantalla_inicial();
				}
			}
		}
	}
		
	
	/**
	 * Se disparan eventos dentro del nivel actual
	 * Puede recibir N parametros adicionales
	 * @param string $id Id. o rol que tiene la dependencia en este objeto
	 * @param string $evento Id. del evento
	 */
	function registrar_evento($id, $evento) 
	{
		$parametros	= func_get_args();
		array_splice($parametros, 0 , 2);
		$metodo = apex_ei_evento . apex_ei_separador . $id . apex_ei_separador . $evento;
		if (method_exists($this, $metodo)) {
			$this->log->debug( $this->get_txt() . "[ registrar_evento ] '$evento' -> [ $metodo ]\n" . var_export($parametros, true), 'toba');
			return call_user_func_array(array($this, $metodo), $parametros);
		} else {
			$this->log->info($this->get_txt() . "[ registrar_evento ]  El METODO [ $metodo ] no existe - '$evento' no fue atrapado", 'toba');
			return apex_ei_evt_sin_rpta;
		}
	}	


	//------------------------------------------------
	//--  Eventos Predefinidos------------------------
	//------------------------------------------------
	
	/**
	 * Despues de que los eventos son atendidos
	 */
	function evt__post_recuperar_interaccion() {}

	/**
	 * Validar el estado interno, dispara una excepcion si falla
	 */
	function evt__validar_datos() {}


	/**
	 * Evento predefinido de cancelar, limpia este objeto, y en caso de exisitr, cancela al cn asociado
	 */
	function evt__cancelar()
	{
		$this->log->debug($this->get_txt() . "[ evt__cancelar ]", 'toba');
		$this->disparar_limpieza_memoria();
		if(isset($this->cn)){
			$this->cn->cancelar();			
		}
	}

	/**
	 * Evento predefinido de procesar, en caso de existir el cn le entrega los datos y limpia la memoria
	 */
	function evt__procesar()
	{
		$this->log->debug($this->get_txt() . "[ evt__procesar ]", 'toba');
		if(isset($this->cn)){
			$this->disparar_entrega_datos_cn();
			$this->cn->procesar();
		}
		$this->disparar_limpieza_memoria();
	}	

	
	//----------------------------------------------------
	//------------   Manejo de Dependencias  -------------
	//----------------------------------------------------

	function inicializar_dependencias( $dependencias )
	//Carga las dependencias y las inicializar
	{
		asercion::es_array($dependencias,"No hay dependencias definidas");
		$this->log->debug( $this->get_txt() . "[ inicializar_dependencias ]\n" . var_export($dependencias, true), 'toba');
		//Parametros a generales
		$parametro["nombre_formulario"] = $this->nombre_formulario;
		foreach($dependencias as $dep)
		{
			if(isset($this->dependencias[$dep])){
				//La dependencia ya se encuentra cargada
				continue;
			}
			//-[0]- Creo la dependencia
			$this->cargar_dependencia($dep);		
			//-[1]- La inicializo
			$parametro['id'] = $dep;
			$this->inicializar_dependencia($dep, $parametro);
		}
	}

	function inicializar_dependencia($dep, $parametro)
	{
		if( in_array( $dep, $this->dependencias_inicializadas ) )  return;
		if ($this->dependencias[$dep] instanceof objeto_ci ){
			$this->dependencias_ci[$dep] = $this->dependencias[$dep]->get_clave_memoria_global();			
			if(isset($this->cn)){
				$this->dependencias[$dep]->asignar_controlador_negocio( $this->cn );
			}
		}
		$this->dependencias[$dep]->set_controlador($this, $dep); //Se hace antes para que puede acceder a su padre
		$this->dependencias[$dep]->inicializar($parametro);
		$this->dependencias_inicializadas[] = $dep;
	}

	/**
	 * Accede a una dependencia del objeto, opcionalmente si la dependencia no esta cargada, la carga
	 *	si la dependencia es un EI y no figura en la lista GI (generacion de interface) dispara el eventos de carga!
	 * @param string $id Identificador de la dependencia dentro del objeto actual
	 * @param boolean $cargar_en_demanda En caso de que el objeto no se encuentre cargado en memoria, lo carga
	 * @return Objeto
	 */
	function dependencia($id, $carga_en_demanda = true)
	{
		$dependencia = parent::dependencia( $id, $carga_en_demanda );
		if ( ! in_array( $id, $this->dependencias_inicializadas ) ) {
 			if (  $dependencia instanceof objeto_ei ) {
				$parametro['id'] = $id;
				$parametro['nombre_formulario'] = $this->nombre_formulario;
				$this->inicializar_dependencia( $id, $parametro );
			}
		}
		return $dependencia;
	}
	
	/**
	 * @see dependencia
	 */
	function dep($id, $carga_en_demanda = true)
	{
		return $this->dependencia($id, $carga_en_demanda);
	}
	
	/**
	 * Devuelve la lista de dependencias que se utlizaron para generar el servicio anterior (atender los eventos actuales)
	 */
	protected function get_dependencias_eventos()
	{
		//Memoria sobre dependencias que fueron a la interface
		if( isset($this->memoria['pantalla_dep']) ){
			$dependencias = $this->memoria['pantalla_dep'];
			//Necesito cargar los daos dinamicos?
			//Esto es posible si los EF chequean que su valor se encuentre entre los posibles
			$this->inicializar_dependencias( $dependencias );
			return $dependencias;
		}else{
			return array();
		}
	}
		
	
	//--------------------------------------------------------
	//--  MANEJO de PANTALLAS  -------------------------------
	//--------------------------------------------------------

	/**
	 * Define la pantalla de eventos (servicio del request anterior)
	 */
	protected function definir_pantalla_eventos()
	{
		//--- La pantalla anterior de servicio ahora se convierte en la potencial pantalla de eventos
		if (isset($this->memoria['pantalla_servicio'])) {
			$this->pantalla_id_eventos = $this->memoria['pantalla_servicio'];
			unset($this->memoria['pantalla_servicio']);
			$this->log->debug( $this->get_txt() . "Pantalla de eventos: '{$this->pantalla_id_eventos}'", 'toba');			
		}
	}

	/**
	 * Define la pantalla servicio
	 * ATENCION: esto se esta ejecutando despues de los eventos propios... 
	 * puede traer problemas de ejecucion de eventos antes de validar la salida de pantallas
	 */
	protected function definir_pantalla_servicio()
	{
		$pantalla_previa = (isset($this->pantalla_id_eventos)) ? $this->pantalla_id_eventos : null;
		
		//--- Es posible que nadie haya decidido aun la pantalla ,se decide aca
		if (! isset($this->pantalla_id_servicio)) {
			if(isset( $pantalla_previa )){
				$this->pantalla_id_servicio =  $this->pantalla_id_eventos;
			} else {
				$this->pantalla_id_servicio = $this->get_pantalla_inicial();
			}
		}
		//--- Se da la oportunidad de que alguien rechaze el seteo, y vuelva todo para atras
		if ($pantalla_previa !== $this->pantalla_id_servicio) { 
			// -[ 1 ]-  Controlo que se pueda salir de la pantalla anterior
			// Esto no lo tengo que subir al metodo anterior?
			if( isset($this->pantalla_id_eventos) ){
				// Habia una etapa anterior
				$evento_salida = apex_ei_evento . apex_ei_separador . $this->pantalla_id_eventos . apex_ei_separador . "salida";
				$this->invocar_callback($evento_salida);				
			}	
			// -[ 2 ]-  Controlo que se pueda ingresar a la etapa propuesta como ACTUAL
			$evento_entrada = apex_ei_evento . apex_ei_separador . $this->pantalla_id_servicio . apex_ei_separador . "entrada";
			$this->invocar_callback($evento_entrada);
		}
		$this->log->debug( $this->get_txt() . "Pantalla de servicio: '{$this->pantalla_id_servicio}'", 'toba');
	}

	function get_pantalla_inicial()
	{
		return $this->info_ci_me_pantalla[0]["identificador"];
	}
	
	function set_pantalla_inicial($id)
	{
		$this->info_ci_me_pantalla[0]["identificador"] = $id;
	}

	/**
	 * Busca alguna regla particular para determinar si la navegaci�n hacia una pantalla es v�lida
	 * El m�todo a definir para incidir en esta regla es evt__puede_mostrar_pantalla y recibe la pantalla como par�metro
	 * @return boolean
	 */
	protected function puede_ir_a_pantalla($tab)
	{
		$evento_mostrar = apex_ei_evento . apex_ei_separador . "puede_mostrar_pantalla";
		if(method_exists($this, $evento_mostrar)){
			return $this->$evento_mostrar($tab);
		}
		return true;
	}
	
	/**
	 * Recorre las pantallas en un sentido buscando una v�lida para mostrar
	 * @param string $sentido "_anterior" o "_siguiente"
	 */
	protected function ir_a_limitrofe($sentido)
	{
		if (!isset($this->pantalla_id_eventos)) {
			toba::get_logger()->crit("No se pudo determinar la pantalla anterior, no se encuentra en la memoria sincronizada");
			return $this->get_pantalla_inicial();
		}
		$indice = ($sentido == '_anterior') ? 0 : 1;	//Para generalizar la busquda de siguiente o anterior
		$candidato = $this->pantalla_id_eventos;
		while ($candidato !== false) {
			$limitrofes = $this->pantallas_limitrofes($candidato);
			$candidato = $limitrofes[$indice];
			if ($this->puede_ir_a_pantalla($candidato)) {
				return $candidato;
			}
		}
		//Si no se encuentra ninguno, no se cambia
		return $this->pantalla_id_eventos;
	}
	
	/**
	 * Wizard: Determina la pantalla anterior y siguiente a la dada 
	 */
	function pantallas_limitrofes($actual)
	{
		reset($this->lista_tabs);
		$pantalla = current($this->lista_tabs);
		$anterior = false;
		$siguiente = false;
		while ($pantalla !== false) {
			if (key($this->lista_tabs) == $actual) {  //Es la pantalla actual?
				if (next($this->lista_tabs) !== false)
					$siguiente = key($this->lista_tabs);
				else
					$siguiente = false;
				break;
			}
			$anterior = key($this->lista_tabs);
			$pantalla = next($this->lista_tabs);
		}
		return array($anterior, $siguiente);	
	}	

	//------------------------------------------------
	//--  ETAPA SERVICIO  ----------------------------
	//------------------------------------------------
	
	function pre_configurar()
	{
		//--- Configuracion propia
		$this->conf();
		
		//--- Configuracion pantalla actual
		$this->pantalla()->pre_configurar();		
		$conf_pantalla = 'conf__'.$this->pantalla_id_servicio;
		$this->invocar_callback($conf_pantalla, $this->pantalla());
		$this->pantalla()->post_configurar();		
		
		//--- Configuracion de las dependencias
		foreach ($this->pantalla()->get_lista_dependencias() as $dep) {
			//--- Config. por defecto
			$this->dependencias[$dep]->pre_configurar();
			
			//--- Config. personalizada
			$conf_pantalla = 'conf__'.$dep;
			$rpta = $this->invocar_callback($conf_pantalla, $this->dependencias[$dep]);
			//--- Por comodidad y compat.hacia atras, si se responde con algo se asume que es para cargarle datos
			if (isset($rpta) && $rpta !== apex_callback_sin_rpta) {
				$this->dependencias[$dep]->set_datos($rpta);
			}		
			
			//--- Config. por defecto
			$this->dependencias[$dep]->post_configurar();
		}
	}
	
	function post_configurar()
	{}

	/**
	 * Ventana para hacer una configuraci�n personalizada del ci
	 */
	protected function conf() {}
	
	protected function get_info_pantalla($id)
	{
		foreach($this->info_ci_me_pantalla as $info_pantalla) {
			if ($info_pantalla['identificador'] == $id) {
				return $info_pantalla;	
			}
		}
	}
	
	/**
	 * @return objeto_ei_pantalla
	 */
	function pantalla()
	{
		if (! isset($this->pantalla_servicio)) {
			require_once('objeto_ei_pantalla.php');
			$id_pantalla = $this->get_id_pantalla();			
			$info = array('info' => $this->info,
						 'info_ci' => $this->info_ci, 
						 'info_eventos' => $this->info_eventos,
						 'info_ci_me_pantalla' => $this->info_ci_me_pantalla);
			$info['info_pantalla'] = $this->get_info_pantalla($id_pantalla);
			
			//ei_arbol($info);
			$this->pantalla_servicio = new objeto_ei_pantalla($info, $this);	
			$this->pantalla_servicio->set_controlador($this, $id_pantalla);
		}
		return $this->pantalla_servicio;
	}
	
	protected function set_pantalla($id)
	{
		$this->pantalla_id_servicio	= $id;
	}

	protected function get_id_pantalla()
	{
		return $this->pantalla_id_servicio;	
	}

	function generar_html()
	{
		$this->pantalla()->generar_html();	
	}
	
	function get_consumo_javascript()
	{
		return $this->pantalla()->get_consumo_javascript();
	}
	
	function generar_js()
	{
		return $this->pantalla()->generar_js();
	}
	
}
?>