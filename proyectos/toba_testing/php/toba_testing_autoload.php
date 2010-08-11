<?php
/**
 * Esta clase fue y ser� generada autom�ticamente. NO EDITAR A MANO.
 * @ignore
 */
class toba_testing_autoload 
{
	static function existe_clase($nombre)
	{
		return isset(self::$clases[$nombre]);
	}

	static function cargar($nombre)
	{
		if (self::existe_clase($nombre)) { require_once(dirname(__FILE__) .'/'. self::$clases[$nombre]); }
	}

	static $clases = array(
		'ci_relacion_ml_dt' => 'ci_relacion_ml_dt.php',
		'ci_vinculos_servicios' => 'ci_vinculos_servicios.php',
		'ci_ocultar' => 'componentes/ci_ocultar.php',
		'ci_datos_tabla_ap_mt' => 'componentes/datos_tabla/ci_datos_tabla_ap_mt.php',
		'ci_serializacion_propiedades' => 'componentes/serializacion/ci_serializacion_propiedades.php',
		'objeto_manual' => 'componentes/serializacion/ci_serializacion_propiedades.php',
		'objeto_automatico' => 'componentes/serializacion/ci_serializacion_propiedades.php',
		'dao_externo' => 'dao_externo.php',
		'ci_definicion' => 'definicion_runtime/ci_definicion.php',
		'ci_errores_db' => 'errores_db/ci_errores_db.php',
		'toba_testing_ci' => 'extension_toba/componentes/toba_testing_ci.php',
		'toba_testing_cn' => 'extension_toba/componentes/toba_testing_cn.php',
		'toba_testing_datos_relacion' => 'extension_toba/componentes/toba_testing_datos_relacion.php',
		'toba_testing_datos_tabla' => 'extension_toba/componentes/toba_testing_datos_tabla.php',
		'toba_testing_ei_arbol' => 'extension_toba/componentes/toba_testing_ei_arbol.php',
		'toba_testing_ei_archivos' => 'extension_toba/componentes/toba_testing_ei_archivos.php',
		'toba_testing_ei_calendario' => 'extension_toba/componentes/toba_testing_ei_calendario.php',
		'toba_testing_ei_cuadro' => 'extension_toba/componentes/toba_testing_ei_cuadro.php',
		'toba_testing_ei_esquema' => 'extension_toba/componentes/toba_testing_ei_esquema.php',
		'toba_testing_ei_filtro' => 'extension_toba/componentes/toba_testing_ei_filtro.php',
		'toba_testing_ei_formulario' => 'extension_toba/componentes/toba_testing_ei_formulario.php',
		'toba_testing_ei_formulario_ml' => 'extension_toba/componentes/toba_testing_ei_formulario_ml.php',
		'toba_testing_ei_grafico' => 'extension_toba/componentes/toba_testing_ei_grafico.php',
		'toba_testing_ei_mapa' => 'extension_toba/componentes/toba_testing_ei_mapa.php',
		'toba_testing_servicio_web' => 'extension_toba/componentes/toba_testing_servicio_web.php',
		'ci_impresion' => 'impresion/ci_impresion.php',
		'ci_login' => 'login/ci_login.php',
		'cuadro_autologin' => 'login/cuadro_autologin.php',
		'eiform_login' => 'login/eiform_login.php',
		'ci_con_dependencias' => 'p_acciones/administrador/test_elemento_toba.php',
		'subclase_cuadro' => 'p_acciones/clonador/sub_carpeta/subclase_cuadro.php',
		'subclase_ci' => 'p_acciones/clonador/subclase_ci.php',
		'subclase_form' => 'p_acciones/clonador/subclase_form.php',
		'ci_activacion' => 'p_acciones/efs/ci_activacion.php',
		'ci_cascadas' => 'p_acciones/efs/ci_cascadas.php',
		'ci_mecanismos_carga' => 'p_acciones/efs/ci_mecanismos_carga.php',
		'ci_validacion_js' => 'p_acciones/efs/ci_validacion_js.php',
		'ci_validacion_server' => 'p_acciones/efs/ci_validacion_server.php',
		'dao_estatico' => 'p_acciones/efs/dao_estatico.php',
		'form_activacion' => 'p_acciones/efs/form_activacion.php',
		'form_simple' => 'p_acciones/efs/form_simple.php',
		'form_validaciones_server' => 'p_acciones/efs/form_validaciones_server.php',
		'ml_instancias_server' => 'p_acciones/efs/ml_validaciones_server.php',
		'ci_principal' => 'p_acciones/efs/solo_lectura/ci_principal.php',
		'form_ml_solo_lectura' => 'p_acciones/efs/solo_lectura/form_ml_solo_lectura.php',
		'form_solo_lectura' => 'p_acciones/efs/solo_lectura/form_solo_lectura.php',
		'ci_principal' => 'p_acciones/item_popup/ci_principal.php',
		'cuadro' => 'p_acciones/item_popup/cuadro.php',
		'cuadro_popup' => 'p_acciones/item_popup/cuadro_popup.php',
		'ci' => 'p_acciones/prueba_ml/ci.php',
		'cn' => 'p_acciones/prueba_ml/cn.php',
		'formulario' => 'p_acciones/prueba_ml/formulario.php',
		'ml' => 'p_acciones/prueba_ml/ml.php',
		'ci_datos_usuario' => 'perfil_de_datos/ci_datos_usuario.php',
		'pantalla_api_alto_nivel' => 'perfil_de_datos/pantalla_api_alto_nivel.php',
		'pantalla_api_bajo_nivel' => 'perfil_de_datos/pantalla_api_bajo_nivel.php',
		'pantalla_perfil_datos' => 'perfil_de_datos/pantalla_perfil_datos.php',
		'la_subclase' => 'pruebas/la_subclase.php',
		'ci_principal' => 'reutilizacion_comp/ci_principal.php',
		'ci_xss' => 'seguridad/ci_xss.php',
		'ci_opciones_ef_seleccion' => 'seguridad/opciones_ef_seleccion/ci_opciones_ef_seleccion.php',
		'hilo_version_test' => 'testing/mocks/hilo_version_test.php',
		'test_exportador' => 'testing/test_administrador/_test_exportador.php',
		'padre_hijo_codigo_previo' => 'testing/test_administrador/archivo_padre_hijo_codigo_previo.php',
		'padre_hijo_include_previo' => 'testing/test_administrador/archivo_padre_hijo_include_previo.php',
		'padre_hijo_vacio' => 'testing/test_administrador/archivo_padre_hijo_vacio.php',
		'test_asignador_objetos' => 'testing/test_administrador/test_asignador_objetos.php',
		'test_clonador_items' => 'testing/test_administrador/test_clonador_items.php',
		'test_clonador_objetos' => 'testing/test_administrador/test_clonador_objetos.php',
		'test_elemento_toba' => 'testing/test_administrador/test_elemento_toba.php',
		'test_parser_ayuda' => 'testing/test_administrador/test_parser_ayuda.php',
		'test_reflexion' => 'testing/test_administrador/test_reflexion.php',
		'clase_previa' => 'testing/test_administrador/test_reflexion.php',
		'prueba_daos' => 'testing/test_ef/prueba_daos.php',
		'test_editable' => 'testing/test_ef/test_editable.php',
		'test_editable_numero' => 'testing/test_ef/test_editable_numero.php',
		'test_entrega_parametros' => 'testing/test_ef/test_entrega_parametros.php',
		'test_fijos' => 'testing/test_ef/test_fijos.php',
		'test_multi_seleccion' => 'testing/test_ef/test_multi_seleccion.php',
		'test_arbol_items' => 'testing/test_items/test_arbol_items.php',
		'test_item' => 'testing/test_items/test_item.php',
		'base_test_datos' => 'testing/test_objetos/base_test_datos.php',
		'test_dr_1n_simple' => 'testing/test_objetos/test_dr_1n_simple.php',
		'test_dr_nn_deptos' => 'testing/test_objetos/test_dr_nn_deptos.php',
		'test_dt_clave_simple' => 'testing/test_objetos/test_dt_clave_simple.php',
		'test_dt_tabla_minima' => 'testing/test_objetos/test_dt_tabla_minima.php',
		'test_ei_formulario_ml' => 'testing/test_objetos/test_ei_formulario_ml.php',
		'test_toba' => 'testing/test_toba.php',
		'EqualArrayExpectation' => 'testing/test_toba.php',
		'test_migracion' => 'testing/test_varios/test_migracion.php',
		'test_parseo_etiquetas' => 'testing/test_varios/test_parseo_etiquetas.php',
		'test_permisos' => 'testing/test_varios/test_permisos.php',
		'test_sql' => 'testing/test_varios/test_sql.php',
		'toba_testing_autoload' => 'toba_testing_autoload.php',
		'ci_carga_por_indice' => 'varios/ci_carga_por_indice.php',
		'ci_prueba_montaje' => 'varios/ci_prueba_montaje.php',
		'cn_carga_por_indice' => 'varios/cn_carga_por_indice.php',
		'ci_principal' => 'varios/extension_php/ci_principal.php',
		'archivo_linux' => 'varios/line_endings/archivo_linux.php',
		'archivo_windows' => 'varios/line_endings/archivo_windows.php',
		'pant_linux' => 'varios/line_endings/pant_linux.php',
		'pant_windows' => 'varios/line_endings/pant_windows.php',
		'ci_perfil_funcional' => 'varios/perfil_funcional/ci_perfil_funcional.php',
		'ci_perfil_funcional_interno' => 'varios/perfil_funcional/ci_perfil_funcional_interno.php',
		'form_perfil_funcional' => 'varios/perfil_funcional/form_perfil_funcional.php',
		'pant_seleccion' => 'varios/perfil_funcional/pant_seleccion.php',
	);
}
?>