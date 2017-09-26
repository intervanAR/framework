<?php

class toba_mc_comp__1827
{
	static function get_metadatos()
	{
		return array (
  '_info' => 
  array (
    'proyecto' => 'toba_editor',
    'objeto' => 1827,
    'anterior' => NULL,
    'identificador' => NULL,
    'reflexivo' => NULL,
    'clase_proyecto' => 'toba',
    'clase' => 'toba_ci',
    'subclase' => 'ci_proyecto',
    'subclase_archivo' => 'configuracion/ci_proyecto.php',
    'objeto_categoria_proyecto' => NULL,
    'objeto_categoria' => NULL,
    'nombre' => 'Parametros Basicos',
    'titulo' => NULL,
    'colapsable' => 0,
    'descripcion' => NULL,
    'fuente_proyecto' => NULL,
    'fuente' => NULL,
    'solicitud_registrar' => NULL,
    'solicitud_obj_obs_tipo' => NULL,
    'solicitud_obj_observacion' => NULL,
    'parametro_a' => NULL,
    'parametro_b' => NULL,
    'parametro_c' => NULL,
    'parametro_d' => NULL,
    'parametro_e' => NULL,
    'parametro_f' => NULL,
    'usuario' => NULL,
    'creacion' => '2006-06-20 03:58:14',
    'punto_montaje' => 12,
    'clase_editor_proyecto' => 'toba_editor',
    'clase_editor_item' => '1000249',
    'clase_archivo' => 'nucleo/componentes/interface/toba_ci.php',
    'clase_vinculos' => NULL,
    'clase_editor' => '1000249',
    'clase_icono' => 'objetos/multi_etapa.gif',
    'clase_descripcion_corta' => 'ci',
    'clase_instanciador_proyecto' => 'toba_editor',
    'clase_instanciador_item' => '1642',
    'objeto_existe_ayuda' => NULL,
    'ap_clase' => NULL,
    'ap_archivo' => NULL,
    'ap_punto_montaje' => NULL,
    'cant_dependencias' => 5,
    'posicion_botonera' => 'ambos',
  ),
  '_info_eventos' => 
  array (
    0 => 
    array (
      'evento_id' => 465,
      'identificador' => 'modificacion',
      'etiqueta' => '&Guardar',
      'maneja_datos' => 1,
      'sobre_fila' => NULL,
      'confirmacion' => NULL,
      'estilo' => NULL,
      'imagen_recurso_origen' => 'apex',
      'imagen' => 'guardar.gif',
      'en_botonera' => 1,
      'ayuda' => NULL,
      'ci_predep' => NULL,
      'implicito' => 0,
      'defecto' => 1,
      'grupo' => NULL,
      'accion' => NULL,
      'accion_imphtml_debug' => 0,
      'accion_vinculo_carpeta' => NULL,
      'accion_vinculo_item' => NULL,
      'accion_vinculo_objeto' => NULL,
      'accion_vinculo_popup' => 0,
      'accion_vinculo_popup_param' => NULL,
      'accion_vinculo_celda' => NULL,
      'accion_vinculo_target' => NULL,
      'accion_vinculo_servicio' => NULL,
      'es_seleccion_multiple' => 0,
      'es_autovinculo' => 0,
    ),
  ),
  '_info_puntos_control' => 
  array (
  ),
  '_info_ci' => 
  array (
    'ev_procesar_etiq' => NULL,
    'ev_cancelar_etiq' => NULL,
    'objetos' => NULL,
    'ancho' => '600px',
    'alto' => NULL,
    'posicion_botonera' => 'ambos',
    'tipo_navegacion' => 'tab_h',
    'con_toc' => 0,
    'botonera_barra_item' => 0,
  ),
  '_info_ci_me_pantalla' => 
  array (
    0 => 
    array (
      'pantalla' => 986,
      'identificador' => 'pant_basica',
      'etiqueta' => 'Configuraci�n b�sica',
      'descripcion' => NULL,
      'tip' => NULL,
      'imagen_recurso_origen' => 'apex',
      'imagen' => NULL,
      'objetos' => NULL,
      'eventos' => NULL,
      'orden' => 1,
      'punto_montaje' => 12,
      'subclase' => NULL,
      'subclase_archivo' => NULL,
      'template' => NULL,
      'template_impresion' => NULL,
    ),
    1 => 
    array (
      'pantalla' => 993,
      'identificador' => 'pant_login',
      'etiqueta' => 'Login',
      'descripcion' => 'Los cambios a las preferencias de login solo ser�n visibles una vez renovada la sesi�n.',
      'tip' => NULL,
      'imagen_recurso_origen' => 'apex',
      'imagen' => NULL,
      'objetos' => NULL,
      'eventos' => NULL,
      'orden' => 2,
      'punto_montaje' => 12,
      'subclase' => NULL,
      'subclase_archivo' => NULL,
      'template' => NULL,
      'template_impresion' => NULL,
    ),
    2 => 
    array (
      'pantalla' => 994,
      'identificador' => 'pant_nucleo',
      'etiqueta' => 'Extensi�n del n�cleo',
      'descripcion' => NULL,
      'tip' => NULL,
      'imagen_recurso_origen' => 'apex',
      'imagen' => NULL,
      'objetos' => NULL,
      'eventos' => NULL,
      'orden' => 3,
      'punto_montaje' => 12,
      'subclase' => NULL,
      'subclase_archivo' => NULL,
      'template' => NULL,
      'template_impresion' => NULL,
    ),
    3 => 
    array (
      'pantalla' => 1022,
      'identificador' => 'pant_version',
      'etiqueta' => 'Versi�n',
      'descripcion' => NULL,
      'tip' => NULL,
      'imagen_recurso_origen' => 'proyecto',
      'imagen' => 'versiones.gif',
      'objetos' => NULL,
      'eventos' => NULL,
      'orden' => 4,
      'punto_montaje' => 12,
      'subclase' => NULL,
      'subclase_archivo' => NULL,
      'template' => NULL,
      'template_impresion' => NULL,
    ),
  ),
  '_info_obj_pantalla' => 
  array (
    0 => 
    array (
      'pantalla' => 986,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1827,
      'dep_id' => 787,
      'orden' => 1,
      'identificador_pantalla' => 'pant_basica',
      'identificador_dep' => 'basica',
    ),
    1 => 
    array (
      'pantalla' => 993,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1827,
      'dep_id' => 804,
      'orden' => 1,
      'identificador_pantalla' => 'pant_login',
      'identificador_dep' => 'login',
    ),
    2 => 
    array (
      'pantalla' => 994,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1827,
      'dep_id' => 805,
      'orden' => 1,
      'identificador_pantalla' => 'pant_nucleo',
      'identificador_dep' => 'nucleo',
    ),
    3 => 
    array (
      'pantalla' => 1022,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1827,
      'dep_id' => 850,
      'orden' => 1,
      'identificador_pantalla' => 'pant_version',
      'identificador_dep' => 'version',
    ),
  ),
  '_info_evt_pantalla' => 
  array (
    0 => 
    array (
      'pantalla' => 986,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1827,
      'evento_id' => 465,
      'identificador_pantalla' => 'pant_basica',
      'identificador_evento' => 'modificacion',
    ),
    1 => 
    array (
      'pantalla' => 993,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1827,
      'evento_id' => 465,
      'identificador_pantalla' => 'pant_login',
      'identificador_evento' => 'modificacion',
    ),
    2 => 
    array (
      'pantalla' => 994,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1827,
      'evento_id' => 465,
      'identificador_pantalla' => 'pant_nucleo',
      'identificador_evento' => 'modificacion',
    ),
    3 => 
    array (
      'pantalla' => 1022,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1827,
      'evento_id' => 465,
      'identificador_pantalla' => 'pant_version',
      'identificador_evento' => 'modificacion',
    ),
  ),
  '_info_dependencias' => 
  array (
    0 => 
    array (
      'identificador' => 'basica',
      'proyecto' => 'toba_editor',
      'objeto' => 1829,
      'clase' => 'toba_ei_formulario',
      'clase_archivo' => 'nucleo/componentes/interface/toba_ei_formulario.php',
      'subclase' => 'eiform_proyecto_confbasica',
      'subclase_archivo' => 'configuracion/eiform_proyecto_confbasica.php',
      'fuente' => 'instancia',
      'parametros_a' => NULL,
      'parametros_b' => NULL,
    ),
    1 => 
    array (
      'identificador' => 'datos',
      'proyecto' => 'toba_editor',
      'objeto' => 1828,
      'clase' => 'toba_datos_tabla',
      'clase_archivo' => 'nucleo/componentes/persistencia/toba_datos_tabla.php',
      'subclase' => NULL,
      'subclase_archivo' => NULL,
      'fuente' => 'instancia',
      'parametros_a' => NULL,
      'parametros_b' => NULL,
    ),
    2 => 
    array (
      'identificador' => 'login',
      'proyecto' => 'toba_editor',
      'objeto' => 1850,
      'clase' => 'toba_ei_formulario',
      'clase_archivo' => 'nucleo/componentes/interface/toba_ei_formulario.php',
      'subclase' => 'eiform_proyecto_conflogin',
      'subclase_archivo' => 'configuracion/eiform_proyecto_conflogin.php',
      'fuente' => 'instancia',
      'parametros_a' => NULL,
      'parametros_b' => NULL,
    ),
    3 => 
    array (
      'identificador' => 'nucleo',
      'proyecto' => 'toba_editor',
      'objeto' => 1851,
      'clase' => 'toba_ei_formulario',
      'clase_archivo' => 'nucleo/componentes/interface/toba_ei_formulario.php',
      'subclase' => 'eiform_proyecto_confnucleo',
      'subclase_archivo' => 'configuracion/eiform_proyecto_confnucleo.php',
      'fuente' => 'instancia',
      'parametros_a' => NULL,
      'parametros_b' => NULL,
    ),
    4 => 
    array (
      'identificador' => 'version',
      'proyecto' => 'toba_editor',
      'objeto' => 1905,
      'clase' => 'toba_ei_formulario',
      'clase_archivo' => 'nucleo/componentes/interface/toba_ei_formulario.php',
      'subclase' => NULL,
      'subclase_archivo' => NULL,
      'fuente' => 'instancia',
      'parametros_a' => NULL,
      'parametros_b' => NULL,
    ),
  ),
);
	}

}

?>