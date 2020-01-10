<?php

class toba_mc_comp__1404
{
	static function get_metadatos()
	{
		return array (
  '_info' => 
  array (
    'proyecto' => 'toba_editor',
    'objeto' => 1404,
    'anterior' => NULL,
    'identificador' => NULL,
    'reflexivo' => NULL,
    'clase_proyecto' => 'toba',
    'clase' => 'toba_ci',
    'subclase' => 'ci_principal',
    'subclase_archivo' => 'objetos_toba/db_tablas/ci_principal.php',
    'objeto_categoria_proyecto' => NULL,
    'objeto_categoria' => NULL,
    'nombre' => 'Editor OBJETO - datos_relacion',
    'titulo' => NULL,
    'colapsable' => NULL,
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
    'creacion' => NULL,
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
    'cant_dependencias' => 6,
    'posicion_botonera' => 'ambos',
  ),
  '_info_eventos' => 
  array (
    0 => 
    array (
      'evento_id' => 78,
      'identificador' => 'eliminar',
      'etiqueta' => '&Eliminar',
      'maneja_datos' => 0,
      'sobre_fila' => 0,
      'confirmacion' => 'Este comando ELIMINARA el COMPONENTE y sus asociaciones con otros elementos del sistema. �Desea continuar?',
      'estilo' => NULL,
      'imagen_recurso_origen' => 'apex',
      'imagen' => 'borrar.gif',
      'en_botonera' => 1,
      'ayuda' => NULL,
      'ci_predep' => NULL,
      'implicito' => NULL,
      'defecto' => NULL,
      'grupo' => NULL,
      'accion' => NULL,
      'accion_imphtml_debug' => NULL,
      'accion_vinculo_carpeta' => NULL,
      'accion_vinculo_item' => NULL,
      'accion_vinculo_objeto' => NULL,
      'accion_vinculo_popup' => NULL,
      'accion_vinculo_popup_param' => NULL,
      'accion_vinculo_celda' => NULL,
      'accion_vinculo_target' => NULL,
      'accion_vinculo_servicio' => NULL,
      'es_seleccion_multiple' => 0,
      'es_autovinculo' => 0,
    ),
    1 => 
    array (
      'evento_id' => 79,
      'identificador' => 'procesar',
      'etiqueta' => '&Guardar',
      'maneja_datos' => 1,
      'sobre_fila' => 0,
      'confirmacion' => NULL,
      'estilo' => NULL,
      'imagen_recurso_origen' => 'apex',
      'imagen' => 'guardar.gif',
      'en_botonera' => 1,
      'ayuda' => NULL,
      'ci_predep' => NULL,
      'implicito' => NULL,
      'defecto' => 1,
      'grupo' => NULL,
      'accion' => NULL,
      'accion_imphtml_debug' => NULL,
      'accion_vinculo_carpeta' => NULL,
      'accion_vinculo_item' => NULL,
      'accion_vinculo_objeto' => NULL,
      'accion_vinculo_popup' => NULL,
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
    'alto' => '400px',
    'posicion_botonera' => 'ambos',
    'tipo_navegacion' => 'tab_h',
    'con_toc' => NULL,
    'botonera_barra_item' => NULL,
  ),
  '_info_ci_me_pantalla' => 
  array (
    0 => 
    array (
      'pantalla' => 382,
      'identificador' => 'p_prop_basicas',
      'etiqueta' => 'Propiedades basicas',
      'descripcion' => NULL,
      'tip' => NULL,
      'imagen_recurso_origen' => 'apex',
      'imagen' => 'objetos/datos_relacion.gif',
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
      'pantalla' => 383,
      'identificador' => 'p_tablas',
      'etiqueta' => 'Tablas',
      'descripcion' => 'Adjuntar los [wiki:Referencia/Objetos/datos_tabla datos_tabla] que forman parte de la relaci�n.',
      'tip' => NULL,
      'imagen_recurso_origen' => 'apex',
      'imagen' => 'objetos/datos_tabla.gif',
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
      'pantalla' => 458,
      'identificador' => 'p_relaciones',
      'etiqueta' => 'Relaciones',
      'descripcion' => 'Describir las [wiki:Referencia/Objetos/datos_relacion#TiposdeRelaciones relaciones existentes] entre las distintas tablas.',
      'tip' => NULL,
      'imagen_recurso_origen' => 'apex',
      'imagen' => 'objetos/relaciones.gif',
      'objetos' => NULL,
      'eventos' => NULL,
      'orden' => 3,
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
      'pantalla' => 382,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1404,
      'dep_id' => 74,
      'orden' => 1,
      'identificador_pantalla' => 'p_prop_basicas',
      'identificador_dep' => 'base',
    ),
    1 => 
    array (
      'pantalla' => 383,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1404,
      'dep_id' => 76,
      'orden' => 1,
      'identificador_pantalla' => 'p_tablas',
      'identificador_dep' => 'dependencias',
    ),
    2 => 
    array (
      'pantalla' => 458,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1404,
      'dep_id' => 78,
      'orden' => 1,
      'identificador_pantalla' => 'p_relaciones',
      'identificador_dep' => 'relaciones',
    ),
    3 => 
    array (
      'pantalla' => 382,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1404,
      'dep_id' => 77,
      'orden' => 2,
      'identificador_pantalla' => 'p_prop_basicas',
      'identificador_dep' => 'prop_basicas',
    ),
    4 => 
    array (
      'pantalla' => 382,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1404,
      'dep_id' => 718,
      'orden' => 3,
      'identificador_pantalla' => 'p_prop_basicas',
      'identificador_dep' => 'opciones',
    ),
  ),
  '_info_evt_pantalla' => 
  array (
    0 => 
    array (
      'pantalla' => 382,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1404,
      'evento_id' => 78,
      'identificador_pantalla' => 'p_prop_basicas',
      'identificador_evento' => 'eliminar',
    ),
    1 => 
    array (
      'pantalla' => 382,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1404,
      'evento_id' => 79,
      'identificador_pantalla' => 'p_prop_basicas',
      'identificador_evento' => 'procesar',
    ),
    2 => 
    array (
      'pantalla' => 383,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1404,
      'evento_id' => 78,
      'identificador_pantalla' => 'p_tablas',
      'identificador_evento' => 'eliminar',
    ),
    3 => 
    array (
      'pantalla' => 383,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1404,
      'evento_id' => 79,
      'identificador_pantalla' => 'p_tablas',
      'identificador_evento' => 'procesar',
    ),
    4 => 
    array (
      'pantalla' => 458,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1404,
      'evento_id' => 78,
      'identificador_pantalla' => 'p_relaciones',
      'identificador_evento' => 'eliminar',
    ),
    5 => 
    array (
      'pantalla' => 458,
      'proyecto' => 'toba_editor',
      'objeto_ci' => 1404,
      'evento_id' => 79,
      'identificador_pantalla' => 'p_relaciones',
      'identificador_evento' => 'procesar',
    ),
  ),
  '_info_dependencias' => 
  array (
    0 => 
    array (
      'identificador' => 'datos',
      'proyecto' => 'toba_editor',
      'objeto' => 1532,
      'clase' => 'toba_datos_relacion',
      'clase_archivo' => 'nucleo/componentes/persistencia/toba_datos_relacion.php',
      'subclase' => NULL,
      'subclase_archivo' => NULL,
      'fuente' => 'instancia',
      'parametros_a' => NULL,
      'parametros_b' => NULL,
    ),
    1 => 
    array (
      'identificador' => 'relaciones',
      'proyecto' => 'toba_editor',
      'objeto' => 1550,
      'clase' => 'toba_ci',
      'clase_archivo' => 'nucleo/componentes/interface/toba_ci.php',
      'subclase' => 'ci_relaciones',
      'subclase_archivo' => 'objetos_toba/db_tablas/ci_relaciones.php',
      'fuente' => NULL,
      'parametros_a' => NULL,
      'parametros_b' => NULL,
    ),
    2 => 
    array (
      'identificador' => 'prop_basicas',
      'proyecto' => 'toba_editor',
      'objeto' => 1511,
      'clase' => 'toba_ei_formulario',
      'clase_archivo' => 'nucleo/componentes/interface/toba_ei_formulario.php',
      'subclase' => 'eiform_ap',
      'subclase_archivo' => 'objetos_toba/db_tablas/eiform_ap.php',
      'fuente' => 'instancia',
      'parametros_a' => NULL,
      'parametros_b' => NULL,
    ),
    3 => 
    array (
      'identificador' => 'base',
      'proyecto' => 'toba_editor',
      'objeto' => 1510,
      'clase' => 'toba_ei_formulario',
      'clase_archivo' => 'nucleo/componentes/interface/toba_ei_formulario.php',
      'subclase' => 'eiform_prop_base',
      'subclase_archivo' => 'objetos_toba/eiform_prop_base.php',
      'fuente' => 'instancia',
      'parametros_a' => NULL,
      'parametros_b' => NULL,
    ),
    4 => 
    array (
      'identificador' => 'opciones',
      'proyecto' => 'toba_editor',
      'objeto' => 1750,
      'clase' => 'toba_ei_formulario',
      'clase_archivo' => 'nucleo/componentes/interface/toba_ei_formulario.php',
      'subclase' => NULL,
      'subclase_archivo' => NULL,
      'fuente' => 'instancia',
      'parametros_a' => NULL,
      'parametros_b' => NULL,
    ),
    5 => 
    array (
      'identificador' => 'dependencias',
      'proyecto' => 'toba_editor',
      'objeto' => 1508,
      'clase' => 'toba_ei_formulario_ml',
      'clase_archivo' => 'nucleo/componentes/interface/toba_ei_formulario_ml.php',
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